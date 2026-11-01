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
    # a new SSH login went through the new rules
    journalctl() { echo "Accepted publickey for admin from 203.0.113.5 port 50000 ssh2: ED25519 SHA256:x"; }
    # this session comes from the Internet
    SSH_CONNECTION="203.0.113.5 49999 198.51.100.1 22"
    who() { :; }
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

# What « sshd -T » shows for the seedbox account when its SFTP rule applies
sshd_rule_in_force() {
    printf 'chrootdirectory %s\nforcecommand internal-sftp -u 0002\n' "$SEEDBOX_DATA_DIR"
    printf '%s no\n' permittty allowtcpforwarding allowagentforwarding allowstreamlocalforwarding x11forwarding permittunnel
}

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
    sshd() { if [[ $1 == -T ]]; then sshd_rule_in_force; fi; }
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

share_load() {
    load
    SHARE_DIR="$WORK/share-$1"
    rm -rf "$SHARE_DIR"
    SEEDBOX_DOMAIN=seedbox.example.org
    SEEDBOX_CERTIFICATE=letsencrypt
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
    sleep() { :; }
}

share_refused_without_watcher() (
    share_load nowatch
    # the watcher never shows up
    pgrep() { return 1; }
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
    chmod 600 "$WORK/restore-passphrase"
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

# --- SFTP: never an account without its restrictions ------------------------------

sftp_load() {
    load
    rm -rf "$APP_STATE_DIR/pending"
    SSHD_SEEDBOX_CONF="$WORK/sshd-seedbox.conf"
    SFTP_KEYS_DIR="$WORK/sftp-keys"
    rm -f "$SSHD_SEEDBOX_CONF"
    : >"$WORK/user-calls"
    SEEDBOX_USER=lancelot
    SEEDBOX_DATA_DIR="$WORK/data"
    SEEDBOX_SFTP_PASSWORD=yes
    sshd_generate_seedbox_conf() { echo "Match User lancelot"; }
    chown() { :; }
    systemctl() { :; }
    sleep() { :; }
    id() { [[ $1 == lancelot ]]; }
    # the expiry date of the account is kept in $WORK/expiry
    rm -f "$WORK/expiry"
    usermod() {
        echo "usermod $*" >>"$WORK/user-calls"
        if [[ $1 == --expiredate ]]; then printf '%s' "$2" >"$WORK/expiry"; fi
    }
    getent() {
        case $1 in
            shadow) printf '%s:!:20000:0:99999:7::%s:\n' "$2" "$(cat "$WORK/expiry" 2>/dev/null)" ;;
            group) [[ $2 == lancelot ]] ;;
            *) return 2 ;;
        esac
    }
    pkill() { echo "pkill $*" >>"$WORK/user-calls"; }
    pgrep() { return 1; }
}

sftp_rule_not_applied_suspends_account() (
    sftp_load
    # sshd accepts the file, but a Match block placed before ours wins: no
    # chroot, and tunnels allowed for the account
    sshd() { if [[ $1 == -T ]]; then printf 'chrootdirectory none\nforcecommand none\nallowtcpforwarding yes\n'; fi; }
    if (seedbox_apply_sftp) &>"$WORK/sftp.out"; then
        cat "$WORK/sftp.out"
        return 1
    fi
    cat "$WORK/user-calls"
    grep -qxF "usermod --expiredate 1 lancelot" "$WORK/user-calls" \
        && grep -qxF "pkill -KILL -u lancelot" "$WORK/user-calls" || return 1
    # once the rule applies, the account suspended by seedtunnel comes back
    sshd() { if [[ $1 == -T ]]; then sshd_rule_in_force; fi; }
    seedbox_apply_sftp &>>"$WORK/sftp.out" || return 1
    grep -qxF "usermod --expiredate  lancelot" "$WORK/user-calls"
)

rename_suspends_account_first() (
    sftp_load
    SFTP_KEYS_DIR="$WORK/rename-keys"
    groupmod() { :; }
    seedbox_save() { :; }
    seedbox_apply() { echo "apply" >>"$WORK/user-calls"; }
    seedbox_set_credentials galahad &>"$WORK/rename.out" || {
        cat "$WORK/rename.out"
        return 1
    }
    cat "$WORK/user-calls"
    # suspended, sessions closed, then renamed: never an account named
    # galahad that the rule written for lancelot does not cover
    [[ $(head -n 3 "$WORK/user-calls") == $'usermod --expiredate 1 lancelot\npkill -KILL -u lancelot\nusermod --login galahad lancelot' ]]
)

# --- self-signed certificate: its fingerprint comes with every link ----------------

share_shows_selfsigned_fingerprint() (
    share_load fingerprint
    SEEDBOX_CERTIFICATE=selfsigned
    SEEDBOX_DOMAIN=203.0.113.7
    SEEDBOX_SSL_DIR="$WORK/ssl"
    mkdir -p "$SEEDBOX_SSL_DIR"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj /CN=203.0.113.7 \
        -keyout "$SEEDBOX_SSL_DIR/selfsigned.key" -out "$SEEDBOX_SSL_DIR/selfsigned.crt" &>/dev/null || return 1
    pgrep() { return 0; }
    share_create "$WORK/to-share" file.conf Title "" Note &>"$WORK/share-fp.out" || {
        cat "$WORK/share-fp.out"
        return 1
    }
    cat "$WORK/share-fp.out"
    grep -qF "$(openssl x509 -in "$SEEDBOX_SSL_DIR/selfsigned.crt" -noout -fingerprint -sha256 | cut -d= -f2)" "$WORK/share-fp.out"
)

# --- files holding a secret: readable by their owner only ---------------------------

secret_files_must_be_private() (
    load
    printf 'VPN_PORT=51820\n' >"$WORK/open.conf"
    printf 'a test passphrase\n' >"$WORK/open-passphrase"
    chmod 644 "$WORK/open.conf"
    chmod 640 "$WORK/open-passphrase"
    OPT_PASSPHRASE_FILE="$WORK/open-passphrase"
    if (config_load "$WORK/open.conf") &>"$WORK/secret.out"; then return 1; fi
    if (backup_read_passphrase 0) &>>"$WORK/secret.out"; then return 1; fi
    cat "$WORK/secret.out"
    # readable by their owner only: accepted
    chmod 600 "$WORK/open.conf" "$WORK/open-passphrase"
    (config_load "$WORK/open.conf") && (backup_read_passphrase 0) </dev/null
)

# --- firewall: « yes » only counts once a new SSH login went through -------------

firewall_yes_needs_new_ssh_login() (
    firewall_trial_load
    firewall_was_on
    # « yes » typed, but no new SSH login since the rules were applied
    journalctl() { :; }
    firewall_enable <<<"yes" >"$WORK/fw/out" 2>&1
    cat "$WORK/fw/out"
    [[ $(<"$FIREWALL_RULES") == "old rules" && ! -e $FIREWALL_CANDIDATE ]] || return 1
    # a login of the SFTP account (it may come through the VPN) does not count
    SEEDBOX_USER=lancelot
    journalctl() { echo "Accepted password for lancelot from 10.8.0.2 port 50000 ssh2"; }
    firewall_enable <<<"yes" >"$WORK/fw/out" 2>&1
    [[ $(<"$FIREWALL_RULES") == "old rules" ]]
)

# --- packages: a removal only takes what seedtunnel installed ----------------------

packages_load() {
    load
    # a new server: nothing installed by seedtunnel yet
    rm -f "$APP_STATE_DIR/packages" "$APP_STATE_DIR/vpn.conf" "$APP_STATE_DIR/seedbox.conf" "$WORK/apt-calls"
    printf '%s\n' curl nginx unrelated >"$WORK/installed"
    package_installed() { grep -qxF -- "$1" "$WORK/installed"; }
    packages_installed_list() { LC_ALL=C sort "$WORK/installed"; }
    APP_APT_UPDATED=1
}

install_records_what_it_brought() (
    packages_load
    apt-get() {
        echo "apt-get $*" >>"$WORK/apt-calls"
        # transmission-daemon comes with transmission-common
        if [[ $* == *" install "* ]]; then printf '%s\n' transmission-daemon transmission-common >>"$WORK/installed"; fi
    }
    # nginx was there before
    apt_install curl nginx transmission-daemon &>/dev/null || return 1
    cat "$APP_STATE_DIR/packages"
    [[ $(<"$APP_STATE_DIR/packages") == $'transmission-common\ntransmission-daemon' ]]
)

purge_only_what_seedtunnel_installed() (
    packages_load
    printf '%s\n' certbot libdep >>"$WORK/installed"
    printf '%s\n' certbot libdep >"$APP_STATE_DIR/packages"
    apt-get() {
        echo "apt-get $*" >>"$WORK/apt-calls"
        # what nothing needs any more: a dependency of certbot, and a package
        # that has nothing to do with seedtunnel
        if [[ $1 == -s ]]; then printf 'Remv libdep [1.0]\nRemv unrelated [2.0]\n'; fi
    }
    apt_purge nginx certbot &>"$WORK/purge.out" || {
        cat "$WORK/purge.out"
        return 1
    }
    cat "$WORK/apt-calls"
    grep -q " purge -y certbot$" "$WORK/apt-calls" && grep -q " purge -y libdep$" "$WORK/apt-calls" \
        && ! grep -q "nginx\|unrelated\|autoremove -y" "$WORK/apt-calls"
)

packages_from_older_version_still_removed() (
    packages_load
    # set up by a version without the list: what it installed is still removed
    echo "SEEDBOX_USER=lancelot" >"$APP_STATE_DIR/seedbox.conf"
    apt-get() { echo "apt-get $*" >>"$WORK/apt-calls"; }
    apt_purge nginx certbot &>/dev/null || return 1
    cat "$WORK/apt-calls"
    grep -q " purge -y nginx$" "$WORK/apt-calls"
)

# --- Transmission: settings never half-written, Transmission not left stopped -----

transmission_settings_failure_keeps_them() (
    load
    TRANSMISSION_DROPIN="$WORK/dropin/seedtunnel.conf"
    SEEDBOX_DATA_DIR="$WORK/data"
    printf '{"old": true}\n' >"$WORK/settings.json"
    : >"$WORK/tr-calls"
    transmission_settings_file() { echo "$WORK/settings.json"; }
    transmission_desired_settings() { echo '{"new": true}'; }
    transmission_settings_uptodate() { return 1; }
    diskguard_stopped() { return 1; }
    chown() { :; }
    systemctl() { echo "systemctl $*" >>"$WORK/tr-calls"; }
    # the disk is full: the new settings stop halfway
    jq() {
        [[ $1 == empty ]] && return 1
        printf '{"old": true, "ne'
        return 1
    }
    if (seedbox_apply_transmission) &>"$WORK/tr.out"; then return 1; fi
    cat "$WORK/tr.out" "$WORK/tr-calls"
    # the previous settings are whole, nothing left behind, and Transmission runs again
    [[ $(<"$WORK/settings.json") == '{"old": true}' && ! -e $WORK/settings.json.tmp ]] \
        && grep -qx "systemctl start transmission-daemon" "$WORK/tr-calls" || return 1
    # it works: replaced in one go
    unset -f jq
    seedbox_apply_transmission &>"$WORK/tr.out" || return 1
    [[ $(jq -c . "$WORK/settings.json") == '{"old":true,"new":true}' && ! -e $WORK/settings.json.tmp ]]
)

transmission_waits_for_data_disk() (
    load
    SEEDBOX_DATA_DIR=/srv/seedbox
    transmission_generate_dropin | grep -qxF "RequiresMountsFor=/srv/seedbox"
)

# --- ports 80/443: every program listening is checked -----------------------------

web_ports_other_program_beside_nginx() (
    load
    # nginx on 80 (an earlier attempt), apache2 on 443
    ss() { printf '%s\n' 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=10,fd=6))' \
        'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("apache2",pid=20,fd=4))'; }
    if (seedbox_check_web_ports) &>"$WORK/ports.out"; then return 1; fi
    grep -q apache2 "$WORK/ports.out" || return 1
    # nginx alone (the seedbox itself): fine
    ss() { echo 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=10,fd=6))'; }
    seedbox_check_web_ports
)

# --- full disk protection: a disk that cannot be measured is reported -------------

diskguard_warns_when_unmeasurable() (
    load
    DISKGUARD_MARKER="$WORK/diskguard.stopped"
    rm -f "$DISKGUARD_MARKER" "$WORK/logger"
    SEEDBOX_DATA_DIR="$WORK/missing-disk"
    seedbox_installed() { return 0; }
    logger() { echo "logger $*" >>"$WORK/logger"; }
    disk_free_gb() { :; }
    # Transmission is not stopped for it, but it is said, in the journal too
    diskguard_check &>"$WORK/dg.out" || return 1
    diskguard_prestart &>>"$WORK/dg.out" || return 1
    cat "$WORK/dg.out"
    grep -q "Cannot measure the free space" "$WORK/dg.out" && grep -q "cannot be measured" "$WORK/logger"
)

# --- diagnostics: the certificate served is checked as a browser does -------------

doctor_reports_certificate_refused() (
    load
    SEEDBOX_CERTIFICATE=letsencrypt
    SEEDBOX_DOMAIN=seedbox.example.org
    DOCTOR_ERRORS=0
    DOCTOR_WARNINGS=0
    # valid on the disk, but the one served does not verify (curl: 60)
    curl() {
        [[ " $* " == *" -k "* || " $* " == *" -sk "* ]] && return 0
        return 60
    }
    doctor_certificate_served 203.0.113.7 &>"$WORK/cert.out"
    cat "$WORK/cert.out"
    ((DOCTOR_ERRORS == 1)) || return 1
    # served and trusted: fine
    curl() { return 0; }
    DOCTOR_ERRORS=0
    doctor_certificate_served 203.0.113.7 &>/dev/null
    ((DOCTOR_ERRORS == 0))
)

# --- VPN clients: what happens when the tunnel drops is explained ---------------

vpn_help_explains_kill_switch() (
    load
    i18n_load fr
    local name=laptop port=60002 VPN_PUBLIC_ADDRESS=203.0.113.7
    text_en_vpn_client_help | grep -q "kill switch" && text_fr_vpn_client_help | grep -q "kill switch" \
        && text_en_share_steps_vpn | grep -q "kill switch" && text_fr_share_steps_vpn | grep -q "kill switch"
)

# --- SFTP (1.2.2): suspension checked, rule checked from everywhere, rename undone -

sftp_suspension_failure_is_said() (
    sftp_load
    sshd() { if [[ $1 == -T ]]; then printf 'chrootdirectory none\n'; fi; }
    # the account database is locked: the expiry date cannot be written
    usermod() {
        echo "usermod $*" >>"$WORK/user-calls"
        return 1
    }
    if (seedbox_apply_sftp) &>"$WORK/sftp.out"; then return 1; fi
    cat "$WORK/sftp.out"
    grep -q "could not be suspended" "$WORK/sftp.out" || return 1
    # nor is an account renamed if it cannot be suspended first
    seedbox_apply() { :; }
    seedbox_save() { :; }
    if (seedbox_set_credentials galahad) &>"$WORK/rename.out"; then return 1; fi
    ! grep -q -- "--login" "$WORK/user-calls"
)

sftp_rule_checked_from_everywhere() (
    sftp_load
    # in force from the server itself only (a Match Address block for the
    # other addresses, placed before ours)
    sshd() {
        [[ $1 == -T ]] || return 0
        if [[ $3 == *addr=127.0.0.1* ]]; then sshd_rule_in_force; else printf 'chrootdirectory none\n'; fi
    }
    if (seedbox_apply_sftp) &>"$WORK/sftp.out"; then
        cat "$WORK/sftp.out"
        return 1
    fi
    # everywhere, but tunnels (PermitTunnel) still allowed
    sshd() { if [[ $1 == -T ]]; then sshd_rule_in_force | sed 's/^permittunnel no$/permittunnel yes/'; fi; }
    if (seedbox_apply_sftp) &>"$WORK/sftp.out"; then
        cat "$WORK/sftp.out"
        return 1
    fi
    grep -qxF "usermod --expiredate 1 lancelot" "$WORK/user-calls"
)

rename_undone_when_a_step_fails() (
    sftp_load
    SFTP_KEYS_DIR="$WORK/rename-keys"
    # the group cannot be renamed
    groupmod() {
        echo "groupmod $*" >>"$WORK/user-calls"
        return 1
    }
    seedbox_save() { echo "save" >>"$WORK/user-calls"; }
    seedbox_apply() { echo "apply" >>"$WORK/user-calls"; }
    if (seedbox_set_credentials galahad) &>"$WORK/rename.out"; then return 1; fi
    cat "$WORK/rename.out" "$WORK/user-calls"
    # the old name is back, the account is no longer suspended, nothing saved
    grep -qxF "usermod --login lancelot galahad" "$WORK/user-calls" \
        && [[ $(tail -n 1 "$WORK/user-calls") == "usermod --expiredate  lancelot" ]] \
        && ! grep -qx "save\|apply" "$WORK/user-calls"
)

# --- firewall: logins through the VPN or from the server itself do not count -----

firewall_vpn_login_does_not_count() (
    firewall_trial_load
    firewall_was_on
    # this session comes from the Internet: a login through the VPN proves
    # nothing for that way
    journalctl() {
        echo "Accepted publickey for admin from 10.8.0.2 port 50000 ssh2: ED25519 SHA256:x"
        echo "Accepted publickey for admin from 127.0.0.1 port 50001 ssh2: ED25519 SHA256:x"
    }
    firewall_enable <<<"yes" >"$WORK/fw/out" 2>&1
    cat "$WORK/fw/out"
    [[ $(<"$FIREWALL_RULES") == "old rules" && ! -e $FIREWALL_CANDIDATE ]]
)

firewall_vpn_session_confirms_through_vpn() (
    firewall_trial_load
    firewall_was_on
    # this session comes through the VPN (after sudo: found from the terminal)
    unset SSH_CONNECTION
    who() { echo "admin    pts/0        2026-11-01 03:00 (10.8.0.2)"; }
    journalctl() { echo "Accepted publickey for admin from 10.8.0.2 port 50000 ssh2: ED25519 SHA256:x"; }
    firewall_enable <<<"yes" >"$WORK/fw/out" 2>&1
    cat "$WORK/fw/out"
    [[ $(<"$FIREWALL_RULES") == "new rules" ]] || return 1
    # a login from the server itself never counts
    firewall_was_on
    journalctl() { echo "Accepted publickey for admin from 127.0.0.1 port 50000 ssh2: ED25519 SHA256:x"; }
    firewall_enable <<<"yes" >"$WORK/fw/out" 2>&1
    [[ $(<"$FIREWALL_RULES") == "old rules" ]]
)

# --- diagnostics: certificate not checked → said --------------------------------

doctor_says_certificate_not_checked() (
    load
    SEEDBOX_CERTIFICATE=letsencrypt
    SEEDBOX_DOMAIN=seedbox.example.org
    DOCTOR_ERRORS=0
    DOCTOR_WARNINGS=0
    # connection refused
    curl() { return 7; }
    doctor_certificate_served 203.0.113.7 &>"$WORK/cert.out"
    cat "$WORK/cert.out"
    ((DOCTOR_WARNINGS == 1 && DOCTOR_ERRORS == 0))
)

# --- IPv6 addresses (DNS of the VPN) ---------------------------------------------

ipv6_forms() (
    load
    local good bad
    for good in 2620:fe::fe 2001:db8::1 ::1 :: fe80:: 2001:db8:0:0:0:0:0:1 1:2:3:4:5:6:7::; do
        vpn_is_valid_dns "$good" || {
            echo "refused: $good"
            return 1
        }
    done
    for bad in 2001:::1 1:2 2001:db8::1::2 12345::1 1:2:3:4:5:6:7:8:9 1::2:3:4:5:6:7:8 :1:2:3:4:5:6:7:8 1:2:3:4:5:6:7:8: g::1; do
        if vpn_is_valid_dns "$bad"; then
            echo "accepted: $bad"
            return 1
        fi
    done
)

# --- restore stopped halfway: how to go back is said -------------------------------

restore_unfinished_says_how_to_go_back() (
    load
    local root="$WORK/restore2-root"
    rm -rf "$root" "$WORK/restore2-state"*
    mkdir -p "$root/etc/seedtunnel"
    echo "VPN_PORT=51820" >"$root/etc/seedtunnel/vpn.conf"
    tar -czf - -C "$root" etc/seedtunnel | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
        -pass pass:"a test passphrase" -out "$WORK/restore2.enc"
    echo "a test passphrase" >"$WORK/restore2-passphrase"
    chmod 600 "$WORK/restore2-passphrase"
    OPT_PASSPHRASE_FILE="$WORK/restore2-passphrase"
    OPT_YES=1
    # settings in place before the restore
    APP_STATE_DIR="$WORK/restore2-state"
    mkdir -p "$APP_STATE_DIR"
    echo "VPN_PORT=1194" >"$APP_STATE_DIR/vpn.conf"
    # the restore stops once the new settings are copied (disk full…)
    i18n_init() { die 'Disk full'; }
    if (restore_main "$WORK/restore2.enc") &>"$WORK/restore2.out"; then return 1; fi
    cat "$WORK/restore2.out"
    grep -q "did not finish" "$WORK/restore2.out" \
        && grep -q "mv $APP_STATE_DIR.before-restore-[0-9-]* $APP_STATE_DIR" "$WORK/restore2.out" \
        && [[ $(cat "$APP_STATE_DIR".before-restore-*/vpn.conf) == "VPN_PORT=1194" ]]
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
check "SFTP: restrictions not in force → account suspended, then back" sftp_rule_not_applied_suspends_account
check "SFTP: renamed account suspended before its new name" rename_suspends_account_first
check "one-time link: fingerprint of the self-signed certificate shown" share_shows_selfsigned_fingerprint
check "files holding a secret: refused if others can read them" secret_files_must_be_private
check "firewall: « yes » refused without a new SSH login" firewall_yes_needs_new_ssh_login
check "packages: installed ones listed, dependencies included" install_records_what_it_brought
check "packages: removal only takes what seedtunnel installed" purge_only_what_seedtunnel_installed
check "packages: server set up by an older version → its packages still removed" packages_from_older_version_still_removed
check "Transmission: settings write failing → previous ones whole, Transmission started" transmission_settings_failure_keeps_them
check "Transmission: waits for the disk of the data" transmission_waits_for_data_disk
check "ports 80/443: another program beside nginx is seen" web_ports_other_program_beside_nginx
check "full disk: free space not measurable → said, Transmission left alone" diskguard_warns_when_unmeasurable
check "diagnostics: certificate served refused by browsers → error" doctor_reports_certificate_refused
check "VPN help: the kill switch is explained" vpn_help_explains_kill_switch
check "SFTP: suspension that cannot be done is said, no rename" sftp_suspension_failure_is_said
check "SFTP: restrictions checked from everywhere, all of them" sftp_rule_checked_from_everywhere
check "SFTP: rename failing halfway → old name back" rename_undone_when_a_step_fails
check "firewall: session from the Internet → a login through the VPN does not count" firewall_vpn_login_does_not_count
check "firewall: session through the VPN → a login through the VPN counts" firewall_vpn_session_confirms_through_vpn
check "diagnostics: certificate served not checked → warning" doctor_says_certificate_not_checked
check "validation: IPv6 addresses, valid and invalid forms" ipv6_forms
check "restore stopped halfway: how to go back is said" restore_unfinished_says_how_to_go_back

printf '\n\033[1m%s passed, %s failed\033[0m\n' "$PASS" "$FAIL"
((FAIL == 0))
