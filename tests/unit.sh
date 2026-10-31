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

# --- firewall: a failed undo is never announced as done --------------------------

firewall_undo_failure_keeps_automatic_undo() (
    firewall_trial_load
    firewall_was_on
    systemctl() { echo "systemctl $*" >>"$WORK/fw/calls"; }
    nft() {
        echo "nft $*" >>"$WORK/fw/calls"
        # putting the previous rules back fails
        [[ "$*" != "-f $FIREWALL_RULES" ]]
    }
    if (firewall_enable <<<"no") >"$WORK/fw/out" 2>&1; then return 1; fi
    cat "$WORK/fw/calls"
    # once the automatic undo is scheduled, its timer is never stopped
    ! sed -n '/^systemd-run/,$p' "$WORK/fw/calls" | grep -q "systemctl stop"
)

# --- a configuration refused once is applied at the next run ----------------------
# The first application fails, the next ones work: the second run must apply
# again, although the file did not change since the first one.

retried() { echo call >>"$1" && (($(wc -l <"$1") > 1)); }
calls() { wc -l <"$1"; }

firewall_refresh_retried_after_failure() (
    load
    rm -rf "$APP_STATE_DIR/pending"
    : >"$WORK/nft-calls"
    FIREWALL_RULES="$WORK/pending.nft"
    rm -f "$FIREWALL_RULES"
    firewall_enabled() { return 0; }
    firewall_generate_rules() { echo "new rules"; }
    chown() { :; }
    nft() { retried "$WORK/nft-calls"; }
    if (firewall_refresh) &>/dev/null; then return 1; fi
    firewall_refresh &>/dev/null || return 1
    (($(calls "$WORK/nft-calls") == 2))
)

nginx_reload_retried_after_failure() (
    load
    rm -rf "$APP_STATE_DIR/pending"
    : >"$WORK/nginx-reloads"
    NGINX_SITE="$WORK/nginx-site"
    NGINX_SITE_LINK="$WORK/nginx-link"
    NGINX_DEFAULT_SITE="$WORK/nginx-default"
    rm -f "$NGINX_SITE"
    ln -sfn "$NGINX_SITE" "$NGINX_SITE_LINK"
    nginx_generate_site() { echo "server {}"; }
    chown() { :; }
    nginx() { return 0; }
    systemctl() {
        case $1 in
            reload-or-restart) retried "$WORK/nginx-reloads" ;;
            *) return 0 ;;
        esac
    }
    if (seedbox_apply_nginx) &>/dev/null; then return 1; fi
    seedbox_apply_nginx &>/dev/null || return 1
    (($(calls "$WORK/nginx-reloads") == 2))
)

ssh_reload_retried_after_failure() (
    load
    rm -rf "$APP_STATE_DIR/pending"
    : >"$WORK/ssh-reloads"
    SSHD_SEEDBOX_CONF="$WORK/sshd-seedbox.conf"
    SFTP_KEYS_DIR="$WORK/sftp-keys"
    rm -f "$SSHD_SEEDBOX_CONF"
    SEEDBOX_USER=lancelot
    SEEDBOX_DATA_DIR="$WORK/data"
    SEEDBOX_SFTP_PASSWORD=yes
    sshd_generate_seedbox_conf() { echo "Match User lancelot"; }
    chown() { :; }
    sshd() { return 0; }
    systemctl() { retried "$WORK/ssh-reloads"; }
    if (seedbox_apply_sftp) &>"$WORK/ssh.out"; then
        cat "$WORK/ssh.out"
        return 1
    fi
    seedbox_apply_sftp &>>"$WORK/ssh.out" || {
        cat "$WORK/ssh.out"
        return 1
    }
    (($(calls "$WORK/ssh-reloads") == 2))
)

# --- seedbox removal: the account goes before its SFTP restrictions ---------------

uninstall_stops_when_user_remains() (
    load
    OPT_YES=1
    local root="$WORK/uninstall" var
    rm -rf "$root"
    mkdir -p "$root"
    SEEDBOX_USER=lancelot
    SEEDBOX_DATA_DIR="$root/data"
    for var in SSHD_SEEDBOX_CONF NGINX_SITE NGINX_SITE_LINK NGINX_HTPASSWD FAIL2BAN_JAIL FAIL2BAN_MAIN_CONF \
        TRANSMISSION_DROPIN SFTP_KEYS_DIR SEEDBOX_SSL_DIR LETSENCRYPT_WEBROOT SHARE_DIR SEEDBOX_SECRETS_FILE; do
        printf -v "$var" '%s' "$root/$var"
    done
    echo "Match User lancelot" >"$SSHD_SEEDBOX_CONF"
    echo "SEEDBOX_USER=lancelot" >"$SEEDBOX_CONF_FILE"
    # the account exists and cannot be deleted (« user is currently used by process »)
    id() { [[ $1 == lancelot ]]; }
    userdel() { return 8; }
    pkill() { :; }
    sleep() { :; }
    systemctl() { :; }
    certbot() { :; }
    apt_purge() { :; }
    diskguard_remove() { :; }
    net_hardening_cleanup() { :; }
    firewall_refresh() { :; }
    backup_auto_stop_if_unused() { :; }
    if (seedbox_uninstall) &>"$WORK/uninstall.out"; then return 1; fi
    cat "$WORK/uninstall.out"
    # the SFTP restrictions and the state are still there
    [[ -e $SSHD_SEEDBOX_CONF && -e $SEEDBOX_CONF_FILE ]]
)

# --- backups: never written through a link prepared in advance -------------------

backup_does_not_follow_prepared_link() (
    backup_load
    install -d -m 700 "$BACKUP_DIR"
    echo "precious" >"$WORK/victim"
    # links at the names a backup could use
    ln -s "$WORK/victim" "$BACKUP_DIR/test.tar.gz.enc.partial"
    backup_write "$BACKUP_DIR/test.tar.gz.enc" </dev/null &>/dev/null || return 1
    [[ $(<"$WORK/victim") == precious && -f $BACKUP_DIR/test.tar.gz.enc && ! -L $BACKUP_DIR/test.tar.gz.enc ]]
)

backup_refuses_open_folder() (
    backup_load
    mkdir -p "$WORK/shared"
    chmod 777 "$WORK/shared"
    if (backup_write "$WORK/shared/test.tar.gz.enc") </dev/null &>"$WORK/open.out"; then return 1; fi
    cat "$WORK/open.out"
    [[ -z $(ls -A "$WORK/shared") ]]
)

# --- one-time links: no link without its watcher ---------------------------------

share_refused_without_watcher() (
    load
    SHARE_DIR="$WORK/share-nowatch"
    rm -rf "$SHARE_DIR"
    SEEDBOX_DOMAIN=seedbox.example.org
    echo secret >"$WORK/to-share"
    apt_install() { :; }
    seedbox_apply_nginx() { :; }
    install() {
        local -a args=()
        while (($#)); do
            case $1 in
                -o | -g) shift 2 ;;
                *)
                    args+=("$1")
                    shift
                    ;;
            esac
        done
        command install "${args[@]}"
    }
    chown() { :; }
    systemd-run() { :; }
    systemctl() { echo "systemctl $*" >>"$WORK/share-calls"; }
    # the watcher never shows up
    pgrep() { return 1; }
    sleep() { :; }
    if (share_create "$WORK/to-share" file.conf Title "" Note) &>"$WORK/share.out"; then
        cat "$WORK/share.out"
        return 1
    fi
    # no link shown, nothing left to download
    ! grep -q "https://" "$WORK/share.out" && [[ -z $(ls -A "$SHARE_DIR") ]]
)

# --- diagnostics: a weekly backup that never worked is reported -------------------

doctor_reports_first_backup_missing() (
    load
    BACKUP_DIR="$WORK/doctor-backups"
    mkdir -p "$BACKUP_DIR"
    BACKUP_PASSPHRASE_FILE="$WORK/doctor-passphrase"
    BACKUP_DOWNLOADED_MARK="$WORK/doctor-mark"
    # turned on 10 days ago, and no automatic backup since
    touch -d '10 days ago' "$BACKUP_PASSPHRASE_FILE"
    touch "$BACKUP_DOWNLOADED_MARK"
    backup_auto_enabled() { return 0; }
    systemctl() { return 1; }
    DOCTOR_ERRORS=0
    DOCTOR_WARNINGS=0
    doctor_backup >"$WORK/doctor.out" 2>&1
    cat "$WORK/doctor.out"
    ((DOCTOR_WARNINGS == 1)) && grep -q "since it was turned on 10 days ago" "$WORK/doctor.out"
)

# --- restore: no decrypted secrets left after a failure ---------------------------

restore_cleans_up_after_failure() (
    load
    local root="$WORK/restore-root"
    rm -rf "$root" "$WORK/restore-tmp"
    mkdir -p "$root/etc/seedtunnel" "$WORK/restore-tmp"
    echo "VPN_PORT=51820" >"$root/etc/seedtunnel/vpn.conf"
    tar -czf - -C "$root" etc/seedtunnel | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
        -pass pass:"a test passphrase" -out "$WORK/restore.enc"
    echo "a test passphrase" >"$WORK/restore-passphrase"
    OPT_PASSPHRASE_FILE="$WORK/restore-passphrase"
    OPT_YES=1
    export TMPDIR="$WORK/restore-tmp"
    # the extraction fails (disk full…)
    tar() {
        if [[ $1 == -xzf ]]; then return 2; fi
        command tar "$@"
    }
    if (restore_main "$WORK/restore.enc") &>"$WORK/restore.out"; then return 1; fi
    ls -AR "$WORK/restore-tmp"
    [[ -z $(ls -A "$WORK/restore-tmp") ]]
)

# --- full disk: Transmission does not start (at boot either) ----------------------

diskguard_refuses_start_on_full_disk() (
    load
    DISKGUARD_MARKER="$WORK/diskguard.stopped"
    rm -f "$DISKGUARD_MARKER"
    SEEDBOX_DATA_DIR=$WORK
    seedbox_installed() { return 0; }
    logger() { :; }
    disk_free_gb() { echo 1; }
    if diskguard_prestart &>/dev/null; then return 1; fi
    [[ -e $DISKGUARD_MARKER ]] || return 1
    # room again: it may start
    disk_free_gb() { echo 50; }
    diskguard_prestart &>/dev/null && [[ ! -e $DISKGUARD_MARKER ]]
)

# --- update: the installed version stays until the new one works ------------------

update_failed_keeps_previous_version() (
    load
    APP_DIR="$WORK/app/seedtunnel"
    rm -rf "$WORK/app"
    mkdir -p "$APP_DIR" "$WORK/app/new"
    printf '#!/bin/sh\necho old >>"%s"\n' "$WORK/app/applied" >"$APP_DIR/seedtunnel.sh"
    # the new version cannot apply the configuration
    printf '#!/bin/sh\nexit 7\n' >"$WORK/app/new/seedtunnel.sh"
    chmod +x "$APP_DIR/seedtunnel.sh" "$WORK/app/new/seedtunnel.sh"
    if (update_switch "$WORK/app/new" 9.9.9) &>"$WORK/update.out"; then
        cat "$WORK/update.out"
        return 1
    fi
    # the previous version is back, and it applied its configuration again
    grep -q "echo old" "$APP_DIR/seedtunnel.sh" && [[ $(<"$WORK/app/applied") == old ]]
)

# --- validation of addresses and ports ----------------------------------------------

validators_reject_out_of_range() (
    load
    is_ipv4 192.168.1.1 && is_ipv4 0.0.0.0 && ! is_ipv4 256.1.2.3 && ! is_ipv4 999.999.999.999 || return 1
    is_valid_port 1 && is_valid_port 65535 && ! is_valid_port 0 && ! is_valid_port 65536 \
        && ! is_valid_port 080 && ! is_valid_port 010 || return 1
    vpn_is_valid_dns "1.1.1.1, 1.0.0.1" && vpn_is_valid_dns "2620:fe::fe" \
        && ! vpn_is_valid_dns "a" && ! vpn_is_valid_dns "," && ! vpn_is_valid_dns "300.1.1.1"
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
check "firewall: a failed undo is reported and the automatic undo kept" firewall_undo_failure_keeps_automatic_undo
check "firewall: rules refused once are applied at the next run" firewall_refresh_retried_after_failure
check "nginx: a reload that failed is done at the next run" nginx_reload_retried_after_failure
check "SSH: a reload that failed is done at the next run" ssh_reload_retried_after_failure
check "seedbox removal: account not deleted → SFTP restrictions kept" uninstall_stops_when_user_remains
check "backup: a link prepared in advance is never written through" backup_does_not_follow_prepared_link
check "backup: refused in a folder others can write to" backup_refuses_open_folder
check "one-time link: watcher not started → no link" share_refused_without_watcher
check "diagnostics: no automatic backup since it was turned on → warning" doctor_reports_first_backup_missing
check "restore: decrypted files deleted after a failure" restore_cleans_up_after_failure
check "full disk: Transmission refused to start, allowed again with room" diskguard_refuses_start_on_full_disk
check "update: new version failing → previous version back" update_failed_keeps_previous_version
check "validation: addresses, ports and DNS out of range refused" validators_reject_out_of_range

printf '\n\033[1m%s passed, %s failed\033[0m\n' "$PASS" "$FAIL"
((FAIL == 0))
