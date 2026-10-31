#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — backup and restore
#
#  Backup: encrypted archive (AES-256, key derived from the passphrase) with
#  /etc/seedtunnel (keys and clients of the VPN, settings and password hashes
#  of the seedbox, firewall), the Let's Encrypt certificates, the SSH keys of
#  SFTP, and the state of Transmission (list of torrents, progress, settings).
#  Downloaded files are not included: copy them with rsync.
#  All backups go to /var/backups/seedtunnel.
#
#  Weekly backup (« seedtunnel backup auto on »): a systemd timer makes an
#  encrypted backup every week and keeps the last 4. Its passphrase is saved on
#  the server (root only): without it, a backup cannot be restored, so it must
#  also be written down somewhere else.
#
#  « seedtunnel backup share » gives a one-time link to download the latest
#  backup onto a computer: if the server disappears, the backup does not
#  disappear with it. « seedtunnel doctor » reminds you when it was not done
#  for a month.
#
#  Restore: on a new server, puts everything back and installs what is
#  needed. VPN clients keep working without any change if the address of the
#  server (ideally a domain name) points to it.
# =============================================================================

BACKUP_DIR="/var/backups/seedtunnel"
BACKUP_KEEP=4
BACKUP_PASSPHRASE_FILE="$APP_STATE_DIR/backup.passphrase"
# date of the last download of a backup (see backup_share)
BACKUP_DOWNLOADED_MARK="$APP_STATE_DIR/backup.downloaded"
BACKUP_SERVICE="/etc/systemd/system/seedtunnel-backup.service"
BACKUP_TIMER="/etc/systemd/system/seedtunnel-backup.timer"
BACKUP_PASSPHRASE=""
BACKUP_TMP_DIR=""

backup_cleanup() {
    if [[ -n $BACKUP_TMP_DIR && -d $BACKUP_TMP_DIR ]]; then rm -rf "$BACKUP_TMP_DIR"; fi
    BACKUP_TMP_DIR=""
    BACKUP_PASSPHRASE=""
}

# What goes into the archive (paths without the leading /)
backup_paths() {
    local path settings
    for path in etc/seedtunnel etc/letsencrypt etc/ssh/seedtunnel_authorized_keys \
        "${TRANSMISSION_STATE_DIR#/}/torrents" "${TRANSMISSION_STATE_DIR#/}/resume"; do
        if [[ -e /$path ]]; then printf '%s\n' "$path"; fi
    done
    settings=$(transmission_settings_file)
    if seedbox_installed && [[ -f $settings ]]; then printf '%s\n' "${settings#/}"; fi
}

# Only what seedtunnel saves can be restored
BACKUP_ALLOWED='^(etc/seedtunnel|etc/letsencrypt|etc/ssh/seedtunnel_authorized_keys|var/lib/transmission-daemon/\.config/transmission-daemon/(torrents|resume|settings\.json)|etc/transmission-daemon/settings\.json)(/|$)'

backup_require_something() {
    if ! vpn_installed && ! seedbox_installed && ! firewall_enabled; then
        die 'Nothing to back up: neither VPN, nor seedbox, nor firewall installed.'
    fi
}

# backup_read_passphrase 1|0 — 1: new passphrase (typed twice, 12 characters
# at least). Read from --passphrase-file, from the terminal, or (backups only)
# from the passphrase saved for the weekly backups.
backup_read_passphrase() {
    local again
    if [[ -n $OPT_PASSPHRASE_FILE ]]; then
        [[ -r $OPT_PASSPHRASE_FILE ]] || die 'Passphrase file not found: %s' "$OPT_PASSPHRASE_FILE"
        IFS= read -r BACKUP_PASSPHRASE <"$OPT_PASSPHRASE_FILE" || true
    elif [[ -t 0 ]]; then
        IFS= read -r -s -p "$(t 'Passphrase of the backup:') " BACKUP_PASSPHRASE || exit 130
        echo
        if (($1)); then
            IFS= read -r -s -p "$(t 'Type it again:') " again || exit 130
            echo
            [[ $BACKUP_PASSPHRASE == "$again" ]] || die 'The two entries differ.'
        fi
    elif (($1)) && [[ -r $BACKUP_PASSPHRASE_FILE ]]; then
        IFS= read -r BACKUP_PASSPHRASE <"$BACKUP_PASSPHRASE_FILE" || true
    else
        die 'Without a terminal, give the passphrase with --passphrase-file FILE.'
    fi
    if (($1)) && ((${#BACKUP_PASSPHRASE} < 12)); then die 'Passphrase: at least 12 characters.'; fi
    [[ -n $BACKUP_PASSPHRASE ]] || die 'Empty passphrase.'
}

# Compressed tar archive, then encrypted; the passphrase goes through a file
# descriptor, never as an argument (invisible in « ps »). The archive is
# written next to its final name, checked by decrypting it, and only renamed
# once complete: a backup that fails never becomes « the latest backup ».
backup_create_archive() {
    local out=$1 partial="$1.partial"
    shift
    if tar -czf - --numeric-owner -C / "$@" \
        | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass fd:3 -out "$partial" 3<<<"$BACKUP_PASSPHRASE" \
        && openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass fd:3 -in "$partial" 3<<<"$BACKUP_PASSPHRASE" \
        | tar -tzf - >/dev/null; then
        mv -f "$partial" "$out"
    else
        rm -f "$partial"
        return 1
    fi
}

# backup_write FILE — encrypted archive with BACKUP_PASSPHRASE
backup_write() {
    local out=$1 old_umask
    local -a paths=()
    mapfile -t paths < <(backup_paths)
    install -d -m 700 "$BACKUP_DIR"
    # left by a backup interrupted the hard way (power cut)
    find "$BACKUP_DIR" -maxdepth 1 -name '*.partial' -mmin +1440 -delete 2>/dev/null || true
    old_umask=$(umask)
    umask 077
    run 'Creating the encrypted archive' backup_create_archive "$out" "${paths[@]}"
    umask "$old_umask"
    BACKUP_PASSPHRASE=""
}

backup_file_name() {
    printf '%s/seedtunnel-%s-%s%s.tar.gz.enc' "$BACKUP_DIR" "$(hostname -s)" "$(date +%Y%m%d-%H%M%S)" "${1-}"
}

# Most recent backup (manual or weekly)
backup_latest() {
    local file
    file=$(ls -1t "$BACKUP_DIR"/*.tar.gz.enc 2>/dev/null | head -n 1 || true)
    [[ -n $file ]] && printf '%s' "$file"
}

# Age in days of a file (empty if it does not exist)
file_age_days() {
    local modified
    [[ -e $1 ]] || return 0
    modified=$(stat -c %Y "$1")
    printf '%s' "$((($(date +%s) - modified) / 86400))"
}

backup_main() {
    local out
    banner
    section 'BACKUP'
    backup_require_something
    out=${OPT_OUTPUT_FILE:-$(backup_file_name)}
    text backup_contents
    echo
    backup_read_passphrase 1
    backup_write "$out"
    echo
    ok 'Backup: %s' "$out"
    text backup_after
    pause
}

backup_list() {
    local file
    local -a files=()
    mapfile -t files < <(ls -1t "$BACKUP_DIR"/*.tar.gz.enc 2>/dev/null || true)
    if ((${#files[@]} == 0)); then
        say 'No backup yet in %s.' "$BACKUP_DIR"
        return 0
    fi
    for file in "${files[@]}"; do
        printf '  %s  %s  %s\n' "$(date -r "$file" '+%F %R')" "$(human_size "$(stat -c %s "$file")")" "$file"
    done
}

# One-time link to the latest backup; the download is recorded for the
# reminder of « seedtunnel doctor »
backup_share() {
    local file
    file=$(backup_latest) || die 'No backup yet:  seedtunnel backup'
    share_require "$(t 'Without a seedbox, copy it with WinSCP or scp: %s' "$file")"
    banner
    section 'DOWNLOAD THE LATEST BACKUP'
    say 'Backup of %s.' "$(date -r "$file" '+%F %R')"
    share_create "$file" "${file##*/}" "$(t 'seedtunnel backup')" "$(text share_steps_backup)" \
        "$(t 'The backup is encrypted: it cannot be read without its passphrase.')" "$BACKUP_DOWNLOADED_MARK"
}

# --- Weekly backup ---------------------------------------------------------------------

backup_auto_enabled() { systemctl is-enabled --quiet seedtunnel-backup.timer 2>/dev/null; }

backup_generate_service() {
    cat <<EOF
# Written by seedtunnel — encrypted backup, the last $BACKUP_KEEP are kept
[Unit]
Description=seedtunnel: weekly encrypted backup

[Service]
Type=oneshot
Nice=10
IOSchedulingClass=idle
ExecStart=$APP_DIR/seedtunnel.sh backup auto run
EOF
}

backup_generate_timer() {
    cat <<'EOF'
# Written by seedtunnel
[Unit]
Description=seedtunnel: weekly encrypted backup

[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

# Units of the weekly backup (also called after an update or a restore)
backup_auto_install_units() {
    local changed=0
    if write_if_changed "$BACKUP_SERVICE" 644 root:root backup_generate_service; then changed=1; fi
    if write_if_changed "$BACKUP_TIMER" 644 root:root backup_generate_timer; then changed=1; fi
    if ((changed)); then run 'Reloading systemd' systemctl daemon-reload; fi
    if ! systemctl is-enabled --quiet seedtunnel-backup.timer 2>/dev/null; then
        run 'Enabling the weekly backup' systemctl enable --now seedtunnel-backup.timer
    fi
}

backup_auto_enable() {
    banner
    section 'WEEKLY BACKUP'
    backup_require_something
    text backup_auto_help
    echo
    backup_read_passphrase 1
    (umask 077 && printf '%s\n' "$BACKUP_PASSPHRASE" >"$BACKUP_PASSPHRASE_FILE")
    BACKUP_PASSPHRASE=""
    backup_auto_install_units
    ok 'Weekly backup on: the last %s are kept in %s.' "$BACKUP_KEEP" "$BACKUP_DIR"
    warn 'Write the passphrase down somewhere else: without it, no backup can be restored.'
}

backup_auto_disable() {
    systemctl disable --now seedtunnel-backup.timer >>"$APP_LOG" 2>&1 || true
    rm -f "$BACKUP_SERVICE" "$BACKUP_TIMER" "$BACKUP_PASSPHRASE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    ok 'Weekly backup off (the existing backups are kept in %s).' "$BACKUP_DIR"
}

# After removing the VPN or the seedbox: with nothing left to back up, the
# weekly backup is turned off
backup_auto_stop_if_unused() {
    if ! vpn_installed && ! seedbox_installed && backup_auto_enabled; then backup_auto_disable; fi
}

# Run by the timer: new backup, then only the last BACKUP_KEEP are kept
backup_auto_run() {
    local file
    [[ -r $BACKUP_PASSPHRASE_FILE ]] || die 'No saved passphrase:  seedtunnel backup auto on'
    backup_require_something
    IFS= read -r BACKUP_PASSPHRASE <"$BACKUP_PASSPHRASE_FILE" || true
    [[ -n $BACKUP_PASSPHRASE ]] || die 'Empty passphrase.'
    file=$(backup_file_name -auto)
    backup_write "$file"
    ls -1t "$BACKUP_DIR"/*-auto.tar.gz.enc 2>/dev/null | tail -n +$((BACKUP_KEEP + 1)) | while IFS= read -r file; do
        rm -f -- "$file"
    done
    ok 'Automatic backup done.'
}

backup_auto_status() {
    local latest age
    if backup_auto_enabled; then
        say 'Weekly backup: on (the last %s are kept in %s)' "$BACKUP_KEEP" "$BACKUP_DIR"
        latest=$(ls -1t "$BACKUP_DIR"/*-auto.tar.gz.enc 2>/dev/null | head -n 1 || true)
        if [[ -n $latest ]]; then say '  Last one: %s' "$(date -r "$latest" '+%F %R')"; fi
    else
        say 'Weekly backup: off   (seedtunnel backup auto on)'
    fi
    age=$(file_age_days "$BACKUP_DOWNLOADED_MARK")
    if [[ -n $age ]]; then
        say 'Last download of a backup: %s day(s) ago' "$age"
    else
        say 'No backup downloaded yet   (seedtunnel backup share)'
    fi
}

# seedtunnel backup …
backup_cli() {
    case ${1-} in
        "") backup_main ;;
        list) backup_list ;;
        share) backup_share ;;
        auto)
            case ${2-} in
                on) backup_auto_enable ;;
                off) backup_auto_disable ;;
                run) backup_auto_run ;;
                "" | status) backup_auto_status ;;
                *) die 'Usage: seedtunnel backup auto on|off|status' ;;
            esac
            ;;
        *) die 'Usage: seedtunnel backup [list|share|auto on|off|status]' ;;
    esac
}

backup_menu() {
    local choice file
    while true; do
        banner
        section 'BACKUP / RESTORE'
        backup_auto_status
        echo
        say '1) Create an encrypted backup now'
        say '2) Download the latest backup (one-time link)'
        say '3) Turn the weekly backup on / off'
        say '4) Restore a backup'
        echo
        say 'Q) Back'
        echo
        ask choice 'Your choice' ""
        case ${choice,,} in
            1) backup_main ;;
            2)
                backup_share
                pause
                ;;
            3)
                if backup_auto_enabled; then backup_auto_disable; else backup_auto_enable; fi
                pause
                ;;
            4)
                backup_list
                echo
                ask file 'Path of the backup file' "$(backup_latest || true)"
                if [[ -n $file ]]; then
                    restore_main "$file"
                    pause
                fi
                ;;
            q) return 0 ;;
        esac
    done
}

# --- Restore ---------------------------------------------------------------------------

# Puts back the torrents, their progress and the settings of Transmission
restore_transmission_state() {
    local extracted=$1 source="$1$TRANSMISSION_STATE_DIR" settings folder count
    [[ -d $source/torrents || -d $source/resume ]] || return 0
    run 'Stopping Transmission' systemctl stop transmission-daemon
    install -d -m 755 -o "$TRANSMISSION_USER" -g "$TRANSMISSION_USER" "$TRANSMISSION_STATE_DIR"
    for folder in torrents resume; do
        if [[ -d $source/$folder ]]; then
            rm -rf "${TRANSMISSION_STATE_DIR:?}/$folder"
            cp -a "$source/$folder" "$TRANSMISSION_STATE_DIR/"
            chown -R "$TRANSMISSION_USER:$TRANSMISSION_USER" "$TRANSMISSION_STATE_DIR/$folder"
        fi
    done
    for settings in "$extracted/etc/transmission-daemon/settings.json" "$source/settings.json"; do
        if [[ -f $settings && ! -L $settings ]]; then
            # « cat > » keeps the file itself (Debian links to it)
            cat "$settings" >"$(transmission_settings_file)"
            break
        fi
    done
    # our settings imposed again, then Transmission started
    seedbox_apply_transmission
    count=$(find "$TRANSMISSION_STATE_DIR/torrents" -name '*.torrent' 2>/dev/null | wc -l)
    ok 'List of torrents restored (%s torrent(s)).' "$count"
}

restore_main() {
    local file=${1-} list bad stamp was=$INTERACTIVE
    [[ -n $file ]] || die 'Usage: seedtunnel restore FILE'
    [[ -r $file ]] || die 'File not found: %s' "$file"
    banner
    section 'RESTORE'
    backup_read_passphrase 0
    BACKUP_TMP_DIR=$(mktemp -d)
    if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$file" -out "$BACKUP_TMP_DIR/backup.tar.gz" \
        -pass fd:3 3<<<"$BACKUP_PASSPHRASE" 2>>"$APP_LOG"; then
        backup_cleanup
        die 'Cannot decrypt: wrong passphrase or damaged file.'
    fi
    BACKUP_PASSPHRASE=""
    if ! list=$(tar -tzf "$BACKUP_TMP_DIR/backup.tar.gz" 2>>"$APP_LOG"); then
        backup_cleanup
        die 'Unreadable archive.'
    fi
    # Nothing else than what seedtunnel saves is extracted
    bad=$(grep -vE "$BACKUP_ALLOWED" <<<"$list" || true)
    if [[ -n $bad ]]; then
        backup_cleanup
        die 'Archive refused: unexpected path "%s"' "${bad%%$'\n'*}"
    fi
    say 'The backup contains:'
    if grep -qx 'etc/seedtunnel/vpn.conf' <<<"$list"; then say '  - the VPN and its clients'; fi
    if grep -qx 'etc/seedtunnel/seedbox.conf' <<<"$list"; then say '  - the seedbox (settings, passwords, certificates)'; fi
    if grep -q '/transmission-daemon/torrents' <<<"$list"; then say '  - the list of torrents'; fi
    if grep -qx 'etc/seedtunnel/firewall.conf' <<<"$list"; then say '  - the firewall'; fi
    echo
    if ! confirm 'Restore? The current settings of seedtunnel will be replaced' n; then
        backup_cleanup
        return 0
    fi
    echo
    mkdir "$BACKUP_TMP_DIR/x"
    run 'Extracting the archive' tar -xzf "$BACKUP_TMP_DIR/backup.tar.gz" --numeric-owner -C "$BACKUP_TMP_DIR/x"
    stamp=$(date +%Y%m%d-%H%M%S)
    if [[ -n $(ls -A "$APP_STATE_DIR" 2>/dev/null) ]]; then
        mv "$APP_STATE_DIR" "$APP_STATE_DIR.before-restore-$stamp"
        warn 'Previous settings moved to %s' "$APP_STATE_DIR.before-restore-$stamp"
    else
        rm -rf "$APP_STATE_DIR"
    fi
    cp -a "$BACKUP_TMP_DIR/x/etc/seedtunnel" /etc/
    if [[ -d $BACKUP_TMP_DIR/x/etc/letsencrypt ]]; then cp -a "$BACKUP_TMP_DIR/x/etc/letsencrypt" /etc/; fi
    if [[ -d $BACKUP_TMP_DIR/x/etc/ssh/seedtunnel_authorized_keys ]]; then
        cp -a "$BACKUP_TMP_DIR/x/etc/ssh/seedtunnel_authorized_keys" /etc/ssh/
    fi

    # Everything is installed again from the restored settings, without questions
    i18n_init
    vpn_load
    seedbox_load
    INTERACTIVE=0
    if vpn_installed; then
        vpn_check_kernel
        base_setup
        vpn_apply
    fi
    if seedbox_installed; then
        base_setup
        seedbox_apply
        restore_transmission_state "$BACKUP_TMP_DIR/x"
    fi
    if firewall_enabled; then firewall_enable; fi
    if [[ -r $BACKUP_PASSPHRASE_FILE ]]; then backup_auto_install_units; fi
    backup_cleanup
    INTERACTIVE=$was
    echo
    ok 'Restore finished.'
    if seedbox_installed; then text restore_after; fi
}
