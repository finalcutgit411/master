#!/usr/bin/env bash
# =============================================================================
#  Unit tests of seedtunnel: no root and no server needed (run by
#  « make check », and on GitHub before the real installations of
#  tests/integration.sh). They replay bugs found in the past, so that they
#  never come back, and check a few helpers.
# =============================================================================
set -Euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PASS=0
FAIL=0

check() {
    local description=$1
    shift
    if "$@" >"$WORK/out" 2>&1; then
        printf '  \033[32m✔\033[0m %s\n' "$description"
        PASS=$((PASS + 1))
    else
        printf '  \033[31m✘ %s\033[0m\n' "$description"
        sed 's/^/      /' "$WORK/out"
        FAIL=$((FAIL + 1))
    fi
}

# Loads the libraries with their state and log in $WORK (each test runs in a
# subshell: « die » only leaves the test)
load() {
    APP_DIR=$ROOT
    # shellcheck source=lib/common.sh
    . "$ROOT/lib/common.sh"
    APP_STATE_DIR="$WORK/state"
    APP_LOG="$WORK/log"
    APP_LANG_FILE="$WORK/state/language"
    mkdir -p "$APP_STATE_DIR"
    local library
    for library in i18n vpn seedbox firewall share diskguard backup update doctor; do
        # shellcheck source=/dev/null
        . "$ROOT/lib/$library.sh"
    done
    i18n_load en
}

ME="$(id -un):$(id -gn)"

# --- vpn_sync: a refused configuration must not show « ok » --------------------

vpn_sync_reports_wg_failure() (
    load
    wg-quick() { printf '[Interface]\n'; }
    wg() {
        echo "wg: invalid configuration" >&2
        return 1
    }
    nft() { return 0; }
    local out
    if out=$(run 'Applying the configuration' vpn_sync 2>&1); then return 1; fi
    [[ $out == *failed* && $out != *"… ok"* ]]
)

vpn_sync_reports_strip_failure() (
    load
    wg-quick() { return 1; }
    wg() { return 0; }
    nft() { return 0; }
    ! (run 'Applying the configuration' vpn_sync) &>/dev/null
)

vpn_sync_ok_when_all_steps_work() (
    load
    wg-quick() { printf '[Interface]\n'; }
    # the configuration arrives as a file (process substitution), never on stdin
    wg() { [[ $1 == syncconf && -r $3 ]]; }
    nft() { return 0; }
    local out
    out=$(run 'Applying the configuration' vpn_sync 2>&1 </dev/null)
    [[ $out == *ok* ]]
)

# --- write_if_changed: never a half-written file ---------------------------------

write_keeps_file_when_generator_fails() (
    load
    printf 'old\n' >"$WORK/conf1"
    half_written() {
        printf 'half'
        return 1
    }
    local out
    if out=$(write_if_changed "$WORK/conf1" 644 "$ME" half_written 2>&1); then return 1; fi
    [[ $(<"$WORK/conf1") == old && $out == *"Cannot generate"* ]] && ! ls "$WORK"/conf1.?* &>/dev/null
)

write_keeps_file_when_replace_fails() (
    load
    printf 'old\n' >"$WORK/conf2"
    mv() { return 1; }
    local out
    if out=$(write_if_changed "$WORK/conf2" 644 "$ME" printf 'new\n' 2>&1); then return 1; fi
    [[ $(<"$WORK/conf2") == old && $out == *"Cannot replace"* ]] && ! ls "$WORK"/conf2.?* &>/dev/null
)

write_reports_changed_and_unchanged() (
    load
    rm -f "$WORK/conf3"
    write_if_changed "$WORK/conf3" 640 "$ME" printf 'a\n' || return 1
    [[ $(<"$WORK/conf3") == a && $(stat -c %a "$WORK/conf3") == 640 ]] || return 1
    ! write_if_changed "$WORK/conf3" 640 "$ME" printf 'a\n'
)

# --- one-time links ---------------------------------------------------------------

share_link_deleted_at_first_opening() (
    load
    command -v inotifywait >/dev/null || {
        echo "inotifywait missing (package inotify-tools)"
        return 1
    }
    local dir="$WORK/share/token1" pid i
    mkdir -p "$dir"
    echo data >"$dir/file.conf"
    bash -c "$SHARE_WATCHER" watcher "$dir/file.conf" 20 "$dir" "$WORK/mark" &
    pid=$!
    # opened again until the watcher reacts (it may take a moment to start)
    for i in $(seq 1 50); do
        [[ -e $dir/file.conf ]] || break
        cat "$dir/file.conf" &>/dev/null || true
        sleep 0.2
    done
    wait "$pid"
    [[ ! -e $dir && -e $WORK/mark ]]
)

share_link_expires() (
    load
    command -v inotifywait >/dev/null || return 1
    local dir="$WORK/share/token2"
    mkdir -p "$dir"
    echo data >"$dir/file.conf"
    rm -f "$WORK/mark2"
    bash -c "$SHARE_WATCHER" watcher "$dir/file.conf" 1 "$dir" "$WORK/mark2"
    [[ ! -e $dir && ! -e $WORK/mark2 ]]
)

# --- translations -------------------------------------------------------------------

french_message() (
    load
    i18n_load fr
    [[ $(t 'Client "%s" revoked: its key can no longer connect.' pc) == 'Client « pc » révoqué : sa clé ne peut plus se connecter.' ]]
)

unknown_message_stays_english() (
    load
    i18n_load fr
    [[ $(t 'A message nobody translated: %s' x) == 'A message nobody translated: x' ]]
)

language_detection() (
    load
    rm -f "$APP_LANG_FILE"
    [[ $(LANG=fr_FR.UTF-8 LC_ALL='' SEEDTUNNEL_LANG='' i18n_detect) == fr ]] || return 1
    [[ $(LANG=en_US.UTF-8 LC_ALL='' SEEDTUNNEL_LANG='' i18n_detect) == en ]] || return 1
    [[ $(LANG=fr_FR.UTF-8 LC_ALL='' SEEDTUNNEL_LANG=en i18n_detect) == en ]] || return 1
    echo fr >"$APP_LANG_FILE"
    [[ $(LANG=C LC_ALL='' SEEDTUNNEL_LANG='' i18n_detect) == fr ]]
)

long_texts_exist_in_french() (
    load
    i18n_load fr
    [[ $(text usage) == *"Utilisation :"* ]]
)

# --- helpers --------------------------------------------------------------------------

firewall_ports_parsing() (
    load
    local rules='tcp dport { 22, 2222 } accept
tcp dport { 80, 443 } accept
meta l4proto { tcp, udp } th dport 60000 accept
udp dport 51820 accept'
    [[ $(firewall_open_tcp_ports <<<"$rules" | tr '\n' ' ') == "22 80 443 2222 " ]]
)

lock_message_names_the_holder() (
    load
    APP_LOCK="$WORK/lock"
    (
        exec 9<>"$APP_LOCK"
        flock 9
        printf '%s %s %s\n' "$BASHPID" "$(date +%s)" pts/9 >"$APP_LOCK"
        sleep 3
    ) &
    sleep 0.5
    local out
    if out=$(take_lock 2>&1); then return 1; fi
    wait
    [[ $out == *"process "* && $out == *"pts/9"* && $out == *"kill "* ]]
)

# --- seedbox: changing the domain can always be cancelled ------------------------
# A seedbox with a valid Let's Encrypt certificate for old.example.org; the
# answers typed in the menu come from ANSWERS, « confirm » answers no.

domain_menu_load() {
    load
    INTERACTIVE=1
    SEEDBOX_DOMAIN=old.example.org
    SEEDBOX_CERTIFICATE=letsencrypt
    SEEDBOX_LETSENCRYPT=auto
    SEEDBOX_LETSENCRYPT_SERVER=production
    APPLIED=0
    ANSWERS=()
    # a question asked once more than planned = a menu with no way out
    exec 3>&2
    ask() {
        if ((${#ANSWERS[@]} == 0)); then
            echo "the menu asks again: no way out of it" >&3
            exit 1
        fi
        printf -v "$1" '%s' "${ANSWERS[0]}"
        ANSWERS=("${ANSWERS[@]:1}")
    }
    confirm() { return 1; }
    clear() { :; }
    public_ipv4() { printf 203.0.113.10; }
    dns_ipv4_addresses() { if [[ $1 == *.example.org ]]; then printf 203.0.113.10; fi; }
    letsencrypt_usable() { [[ $SEEDBOX_DOMAIN == old.example.org && $1 == production ]]; }
    letsencrypt_expiry_date() { printf 2027-01-29; }
    seedbox_apply_https() { APPLIED=1; }
    seedbox_save() { APPLIED=1; }
}

# nothing applied, and the domain is still the old one
domain_untouched() {
    [[ $APPLIED == 0 && $SEEDBOX_DOMAIN == old.example.org && $SEEDBOX_LETSENCRYPT == auto ]] || {
        echo "applied: $APPLIED, domain: $SEEDBOX_DOMAIN, letsencrypt: $SEEDBOX_LETSENCRYPT"
        return 1
    }
}

domain_change_empty_answer_goes_back() (
    domain_menu_load
    ANSWERS=("")
    seedbox_change_domain >"$WORK/domain.out" 2>&1
    domain_untouched && grep -q 'Nothing changed' "$WORK/domain.out"
)

domain_change_same_name_keeps_certificate() (
    domain_menu_load
    ANSWERS=("old.example.org")
    seedbox_change_domain >"$WORK/domain.out" 2>&1
    domain_untouched && grep -q 'Nothing to change' "$WORK/domain.out"
)

domain_change_warns_before_replacing_certificate() (
    domain_menu_load
    ANSWERS=("new.example.org")
    seedbox_change_domain >"$WORK/domain.out" 2>&1
    domain_untouched && grep -q 'will be deleted' "$WORK/domain.out"
)

domain_change_back_when_name_points_elsewhere() (
    domain_menu_load
    ANSWERS=("elsewhere.test" "q")
    seedbox_change_domain >"$WORK/domain.out" 2>&1
    domain_untouched && grep -q 'Nothing changed' "$WORK/domain.out"
)

domain_change_applied_once_confirmed() (
    domain_menu_load
    confirm() { return 0; }
    ANSWERS=("new.example.org")
    seedbox_change_domain >"$WORK/domain.out" 2>&1
    [[ $APPLIED == 1 && $SEEDBOX_DOMAIN == new.example.org ]]
)

# --- firewall: refusing new rules puts the previous ones back --------------------
# The answer to « Does it work? » comes from standard input; the nft and
# systemd-run commands are recorded in $WORK/fw/calls.

firewall_trial_load() {
    load
    INTERACTIVE=1
    rm -rf "$WORK/fw"
    mkdir -p "$WORK/fw"
    : >"$WORK/fw/calls"
    FIREWALL_RULES="$WORK/fw/firewall.nft"
    FIREWALL_CANDIDATE="$WORK/fw/firewall.nft.new"
    FIREWALL_CONF_FILE="$WORK/fw/firewall.conf"
    FIREWALL_UNIT="$WORK/fw/seedtunnel-firewall.service"
    apt_install() { :; }
    firewall_generate_rules() { echo "new rules"; }
    firewall_summary() { echo SSH; }
    confirm() { return 0; }
    pause() { :; }
    clear() { :; }
    chown() { :; }
    systemctl() { :; }
    nft() { echo "nft $*" >>"$WORK/fw/calls"; }
    systemd-run() { echo "systemd-run $*" >>"$WORK/fw/calls"; }
}

firewall_was_on() {
    echo "old rules" >"$FIREWALL_RULES"
    FIREWALL_ENABLED=1
    state_write "$FIREWALL_CONF_FILE" FIREWALL_ENABLED
}

firewall_change_refused_restores_previous_rules() (
    firewall_trial_load
    firewall_was_on
    firewall_enable <<<"no" >"$WORK/fw/out" 2>&1
    cat "$WORK/fw/calls"
    [[ $(<"$FIREWALL_RULES") == "old rules" && ! -e $FIREWALL_CANDIDATE ]] || return 1
    # undo, now and in 2 minutes: the old rules again, never « no firewall »
    grep -qx "nft -f $FIREWALL_RULES" "$WORK/fw/calls" \
        && grep -q "systemd-run .* /usr/sbin/nft -f $FIREWALL_RULES" "$WORK/fw/calls" \
        && ! grep -q "delete table" "$WORK/fw/calls"
)

firewall_first_trial_refused_leaves_nothing() (
    firewall_trial_load
    firewall_enable <<<"no" >"$WORK/fw/out" 2>&1
    cat "$WORK/fw/calls"
    [[ ! -e $FIREWALL_RULES && ! -e $FIREWALL_CANDIDATE ]] && ! firewall_enabled \
        && grep -qx "nft delete table inet $FIREWALL_TABLE" "$WORK/fw/calls"
)

firewall_change_confirmed_becomes_permanent() (
    firewall_trial_load
    firewall_was_on
    firewall_enable <<<"yes" >"$WORK/fw/out" 2>&1
    [[ $(<"$FIREWALL_RULES") == "new rules" && ! -e $FIREWALL_CANDIDATE ]] && firewall_enabled
)

# --- VPN: a change that failed is applied at the next run ------------------------

vpn_change_failed_then_retried() (
    load
    VPN_PORT=51820
    : >"$WORK/syncconf"
    systemctl() { return 0; }
    wg-quick() { printf '[Interface]\n'; }
    nft() { return 0; }
    wg() {
        case $1 in
            show) echo 51820 ;;
            syncconf)
                echo call >>"$WORK/syncconf"
                # the first application fails, the next ones work
                (($(wc -l <"$WORK/syncconf") > 1))
                ;;
        esac
    }
    # first run: the files changed, WireGuard refuses them → failure reported
    if (vpn_reconcile 1) </dev/null &>/dev/null; then return 1; fi
    # next run: the files are already written (nothing changed), yet the
    # running VPN is put in line with them
    vpn_reconcile 0 </dev/null &>/dev/null || return 1
    (($(wc -l <"$WORK/syncconf") == 2))
)

# --- backups: a failed backup never becomes « the latest backup » ----------------

backup_load() {
    load
    BACKUP_DIR="$WORK/backups"
    rm -rf "$BACKUP_DIR"
    BACKUP_PASSPHRASE="a test passphrase"
    backup_paths() { echo etc/hostname; }
}

backup_failed_leaves_nothing() (
    backup_load
    # tar stops halfway (disk error, file gone…)
    tar() {
        if [[ $1 == -czf ]]; then
            printf 'half an archive'
            return 2
        fi
        command tar "$@"
    }
    if (backup_write "$BACKUP_DIR/test.tar.gz.enc") </dev/null &>/dev/null; then return 1; fi
    ls -A "$BACKUP_DIR"
    [[ -z $(ls -A "$BACKUP_DIR") && -z $(backup_latest) ]]
)

backup_complete_and_checked() (
    backup_load
    backup_write "$BACKUP_DIR/test.tar.gz.enc" </dev/null &>/dev/null || return 1
    [[ -s $BACKUP_DIR/test.tar.gz.enc && ! -e $BACKUP_DIR/test.tar.gz.enc.partial ]] || return 1
    [[ $(backup_latest) == "$BACKUP_DIR/test.tar.gz.enc" ]] || return 1
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass pass:"a test passphrase" \
        -in "$BACKUP_DIR/test.tar.gz.enc" | tar -tzf - | grep -qx etc/hostname
)

printf '\033[1m=== Unit tests\033[0m\n'
check "vpn_sync: WireGuard refusing the configuration shows « failed »" vpn_sync_reports_wg_failure
check "vpn_sync: a failure of « wg-quick strip » is seen" vpn_sync_reports_strip_failure
check "vpn_sync: « ok » when every step works" vpn_sync_ok_when_all_steps_work
check "write_if_changed: generator failing (disk full) → file kept" write_keeps_file_when_generator_fails
check "write_if_changed: replacement failing → file kept" write_keeps_file_when_replace_fails
check "write_if_changed: says whether the file changed, sets its mode" write_reports_changed_and_unchanged
check "one-time link: deleted when the file is first opened" share_link_deleted_at_first_opening
check "one-time link: deleted when it expires, not marked as downloaded" share_link_expires
check "translation: French message with its value" french_message
check "translation: missing message stays in English" unknown_message_stays_english
check "language: environment, saved choice, system language" language_detection
check "translation: long texts in French" long_texts_exist_in_french
check "firewall: open TCP ports read from the rules" firewall_ports_parsing
check "lock: the message names the process holding it" lock_message_names_the_holder
check "domain menu: an empty answer goes back, nothing changed" domain_change_empty_answer_goes_back
check "domain menu: same name, certificate kept without a new request" domain_change_same_name_keeps_certificate
check "domain menu: warning and confirmation before replacing the certificate" domain_change_warns_before_replacing_certificate
check "domain menu: Q goes back when the name points elsewhere" domain_change_back_when_name_points_elsewhere
check "domain menu: new name applied once confirmed" domain_change_applied_once_confirmed
check "firewall: change refused → previous rules back, boot file untouched" firewall_change_refused_restores_previous_rules
check "firewall: first activation refused → no rules left" firewall_first_trial_refused_leaves_nothing
check "firewall: change confirmed → becomes the rules loaded at boot" firewall_change_confirmed_becomes_permanent
check "VPN: a change refused by WireGuard is applied at the next run" vpn_change_failed_then_retried
check "backup: a failed backup leaves no file, never « the latest »" backup_failed_leaves_nothing
check "backup: complete archive, checked, then renamed" backup_complete_and_checked

printf '\n\033[1m%s passed, %s failed\033[0m\n' "$PASS" "$FAIL"
((FAIL == 0))
