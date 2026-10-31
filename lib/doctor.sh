#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — diagnostics (« seedtunnel doctor »)
#
#  Checks in one go what causes most breakdowns: stopped services, DNS not
#  pointing to the server, certificate about to expire, closed port, full
#  disk, wrong clock, missing backups… Each line says what to do.
#  Exit status: 0 if there is no problem, 1 otherwise (usable in a script).
#  It changes nothing, so it also runs while a menu is open elsewhere.
# =============================================================================

DOCTOR_ERRORS=0
DOCTOR_WARNINGS=0

doctor_ok() { ok "$@"; }
doctor_warn() {
    DOCTOR_WARNINGS=$((DOCTOR_WARNINGS + 1))
    printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$(t "$@")"
}
doctor_error() {
    DOCTOR_ERRORS=$((DOCTOR_ERRORS + 1))
    printf '%s✘%s %s\n' "$C_RED" "$C_RESET" "$(t "$@")"
}
doctor_title() { printf '\n%s%s%s\n' "$C_BOLD" "$(t "$@")" "$C_RESET"; }

# doctor_service SERVICE "Name shown"
doctor_service() {
    if systemctl is-active --quiet "$1"; then
        doctor_ok '%s: running' "$2"
    else
        doctor_error '%s: stopped   → journalctl -u %s -n 30' "$2" "$1"
    fi
}

# Days left before a certificate expires (empty if unreadable)
certificate_days_left() {
    local end expires now
    end=$(openssl x509 -in "$1" -noout -enddate 2>/dev/null | cut -d= -f2 || true)
    [[ -n $end ]] || return 0
    expires=$(date -d "$end" +%s 2>/dev/null) || return 0
    now=$(date +%s)
    printf '%s' "$(((expires - now) / 86400))"
}

doctor_system() {
    local free synced redirects
    doctor_title 'System'
    doctor_ok '%s, seedtunnel %s' "$APP_OS_DESCRIPTION" "$APP_VERSION"
    free=$(disk_free_gb /)
    if [[ -z $free ]]; then
        doctor_warn 'Free space of / unreadable'
    elif ((free < 2)); then
        doctor_error 'Disk almost full: %s GB free on /' "$free"
    else
        doctor_ok 'Free space on /: %s GB' "$free"
    fi
    if grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
        doctor_ok 'Automatic security updates on'
    else
        doctor_warn 'Automatic security updates off'
    fi
    if [[ -f $NET_HARDENING_FILE ]]; then
        redirects=$(sysctl -n net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects 2>/dev/null | tr -d '\n' || true)
        if [[ $redirects == 00 ]]; then
            doctor_ok 'Kernel network settings hardened'
        else
            doctor_warn 'Kernel network settings not applied   → seedtunnel apply'
        fi
    fi
    if [[ -e /run/reboot-required ]]; then
        doctor_warn 'Restart advised (update of the kernel or of a library)'
    fi
    synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
    if [[ $synced == yes ]]; then
        doctor_ok 'Clock synchronized'
    else
        doctor_warn 'Clock not synchronized: certificates and WireGuard depend on it (timedatectl)'
    fi
}

doctor_vpn() {
    local ip=$1 ips
    doctor_title 'WireGuard VPN'
    doctor_service "wg-quick@$VPN_INTERFACE" 'WireGuard service'
    if [[ $(wg show "$VPN_INTERFACE" listen-port 2>/dev/null || true) == "$VPN_PORT" ]]; then
        doctor_ok 'Listening on port %s/udp' "$VPN_PORT"
    else
        doctor_error 'WireGuard is not listening on port %s/udp   → seedtunnel vpn restart' "$VPN_PORT"
    fi
    if [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == 1 ]]; then
        doctor_ok 'IPv4 routing on'
    else
        doctor_error 'IPv4 routing off: the clients will have no Internet   → seedtunnel apply'
    fi
    if nft list table ip seedtunnel &>/dev/null; then
        doctor_ok 'NAT rules in place'
    else
        doctor_error 'NAT rules missing   → seedtunnel vpn restart'
    fi
    if is_ipv4 "$VPN_PUBLIC_ADDRESS"; then
        if [[ $VPN_PUBLIC_ADDRESS == "$ip" ]]; then
            doctor_ok 'Address of the clients (%s) = public IP of the server' "$VPN_PUBLIC_ADDRESS"
        else
            doctor_warn 'The clients connect to %s, but the public IP is %s' "$VPN_PUBLIC_ADDRESS" "${ip:-$(t 'unknown')}"
        fi
    else
        ips=$(dns_ipv4_addresses "$VPN_PUBLIC_ADDRESS")
        if [[ -n $ip ]] && grep -qxF "$ip" <<<"$ips"; then
            doctor_ok '"%s" points to this server' "$VPN_PUBLIC_ADDRESS"
        else
            doctor_warn '"%s" points to %s and not to %s' "$VPN_PUBLIC_ADDRESS" "${ips:-$(t 'nothing')}" "${ip:-$(t 'this server')}"
        fi
    fi
    doctor_ok 'Clients: %s, %s connected right now' "$(vpn_count_clients)" "$(vpn_connected_count)"
    say "  (the UDP port cannot be tested from outside by the server itself: if in"
    say "   doubt, check the firewall in the control panel of the provider)"
}

doctor_seedbox() {
    local ip=$1 crt days code free settings
    doctor_title 'Seedbox'
    if diskguard_stopped; then
        doctor_error 'Transmission stopped: disk almost full (%s GB free). Free some space: it restarts by itself above %s GB.' \
            "$(disk_free_gb "$SEEDBOX_DATA_DIR")" "$DISKGUARD_START_ABOVE_GB"
    else
        doctor_service transmission-daemon 'Transmission'
    fi
    doctor_service nginx 'nginx'
    doctor_service fail2ban 'fail2ban'
    doctor_service ssh.service 'SSH / SFTP'
    if systemctl is-active --quiet seedtunnel-diskguard.timer; then
        doctor_ok 'Full disk protection on (Transmission stopped under %s GB free)' "$DISKGUARD_STOP_BELOW_GB"
    else
        doctor_warn 'Full disk protection off   → seedtunnel apply'
    fi

    if is_ipv4 "$SEEDBOX_DOMAIN"; then
        doctor_warn 'No domain name (access by IP, self-signed certificate)'
    elif dns_points_here "$SEEDBOX_DOMAIN" "$ip"; then
        doctor_ok '"%s" points to this server (%s)' "$SEEDBOX_DOMAIN" "$ip"
    else
        doctor_error '"%s" does not point to this server (%s): check the DNS' "$SEEDBOX_DOMAIN" "${ip:-$(t 'IP unknown')}"
    fi

    if [[ $SEEDBOX_CERTIFICATE == selfsigned ]]; then crt="$SEEDBOX_SSL_DIR/selfsigned.crt"; else crt="$LETSENCRYPT_DIR/cert.pem"; fi
    days=$(certificate_days_left "$crt")
    if [[ -z $days ]]; then
        doctor_error 'Certificate unreadable: %s   → seedtunnel seedbox domain %s' "$crt" "$SEEDBOX_DOMAIN"
    elif [[ $SEEDBOX_CERTIFICATE == selfsigned ]]; then
        doctor_warn 'Self-signed certificate (browser warning)   → seedtunnel seedbox domain %s' "$SEEDBOX_DOMAIN"
    elif ((days < 7)); then
        doctor_error "Let's Encrypt certificate: expires in %s day(s), the renewal fails   → certbot renew" "$days"
    elif ((days < 21)); then
        doctor_warn "Let's Encrypt certificate: expires in %s days (it should have been renewed)" "$days"
    else
        doctor_ok 'Certificate %s: %s days left' "$(seedbox_certificate_label)" "$days"
    fi
    if [[ $SEEDBOX_CERTIFICATE != selfsigned ]]; then
        if systemctl is-active --quiet certbot.timer; then
            doctor_ok 'Automatic renewal scheduled (certbot.timer)'
        else
            doctor_error 'certbot.timer inactive: the certificate will not be renewed   → systemctl enable --now certbot.timer'
        fi
    fi

    code=$(seedbox_http_code /transmission/web/)
    if [[ $code == 401 ]]; then
        doctor_ok 'Web interface online and protected by a password'
    else
        doctor_error 'Web interface: unexpected answer (code %s) on %s' "${code:-$(t 'none')}" "https://$SEEDBOX_DOMAIN/"
    fi
    if [[ -n $ip ]]; then
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 \
            --resolve "$SEEDBOX_DOMAIN:443:$ip" "https://$SEEDBOX_DOMAIN/transmission/web/" 2>/dev/null || true)
        if [[ $code == 401 ]]; then
            doctor_ok 'HTTPS reachable through the public IP (tested from the server itself)'
        else
            doctor_warn 'HTTPS unreachable through the public IP %s (code %s): firewall?' "$ip" "${code:-$(t 'none')}"
        fi
    fi

    settings=$(sshd -T -C "user=$SEEDBOX_USER,host=localhost,addr=127.0.0.1" 2>/dev/null || true)
    if [[ $settings == *"chrootdirectory $SEEDBOX_DATA_DIR"* ]]; then
        doctor_ok 'SFTP locked in %s' "$SEEDBOX_DATA_DIR"
    else
        doctor_error 'SFTP rule inactive for %s   → seedtunnel apply' "$SEEDBOX_USER"
    fi
    if seedbox_check_data_dir "$SEEDBOX_DATA_DIR" 2>/dev/null; then
        doctor_ok 'Permissions of the data folder correct'
    else
        doctor_error 'Permissions of the folder %s incompatible with the locked SFTP' "$SEEDBOX_DATA_DIR"
    fi
    free=$(disk_free_gb "$SEEDBOX_DATA_DIR")
    if [[ -n $free ]] && ((free < 5)); then
        doctor_warn 'Little space left for downloads: %s GB free' "$free"
    elif [[ -n $free ]]; then
        doctor_ok 'Free space for downloads: %s GB' "$free"
    fi
    settings=$(fail2ban-client status 2>/dev/null || true)
    if [[ $settings == *sshd* && $settings == *nginx-http-auth* && $settings == *recidive* ]]; then
        doctor_ok 'fail2ban watches SSH, the web interface and repeat offenders'
    else
        doctor_warn 'fail2ban rules incomplete   → seedtunnel seedbox restart'
    fi
}

doctor_firewall() {
    local rules port open
    doctor_title 'Firewall'
    if firewall_enabled; then
        rules=$(nft list table inet "$FIREWALL_TABLE" 2>/dev/null || true)
        if [[ -z $rules ]]; then
            doctor_error 'Firewall enabled but rules missing   → seedtunnel firewall enable --yes'
        else
            doctor_ok 'On — open: %s' "$(firewall_summary)"
            # SSH port changed without updating the firewall: one would be
            # locked out at the next connection (or the next restart of SSH)
            open=" $(firewall_open_tcp_ports <<<"$rules" | tr '\n' ' ') "
            for port in $(firewall_sshd_ports); do
                if [[ $open == *" $port "* ]]; then
                    doctor_ok 'SSH port %s open in the firewall' "$port"
                else
                    doctor_error 'SSH uses port %s, closed by the firewall: risk of being locked out   → seedtunnel firewall enable' "$port"
                fi
            done
        fi
    else
        doctor_warn 'seedtunnel firewall off   → seedtunnel firewall enable'
    fi
    if systemctl is-enabled --quiet nftables.service 2>/dev/null \
        && grep -qs 'flush ruleset' /etc/nftables.conf; then
        doctor_warn 'nftables.service is enabled and empties all the rules at boot (/etc/nftables.conf)'
    fi
}

doctor_backup() {
    local latest age since
    doctor_title 'Backups'
    if backup_auto_enabled; then
        latest=$(ls -1t "$BACKUP_DIR"/*-auto.tar.gz.enc 2>/dev/null | head -n 1 || true)
        age=$(file_age_days "$latest")
        if systemctl is-failed --quiet seedtunnel-backup.service 2>/dev/null; then
            doctor_warn 'The last automatic backup failed   → journalctl -u seedtunnel-backup'
        elif [[ -z $age ]]; then
            # turned on when its passphrase was saved
            since=$(file_age_days "$BACKUP_PASSPHRASE_FILE")
            if [[ -n $since ]] && ((since > 8)); then
                doctor_warn 'No automatic backup since it was turned on %s days ago   → journalctl -u seedtunnel-backup' "$since"
            else
                doctor_ok 'Weekly backup on (the first one comes within a week)'
            fi
        elif ((age > 8)); then
            doctor_warn 'Last automatic backup %s days ago: the weekly backup seems to fail   → journalctl -u seedtunnel-backup' "$age"
        else
            doctor_ok 'Weekly backup on, last one %s day(s) ago' "$age"
        fi
    else
        doctor_warn 'Weekly backup off   → seedtunnel backup auto on'
    fi
    age=$(file_age_days "$BACKUP_DOWNLOADED_MARK")
    if [[ -z $age ]]; then
        doctor_warn 'No backup downloaded to your computer yet   → seedtunnel backup share'
    elif ((age > 30)); then
        doctor_warn 'Last download of a backup started %s days ago   → seedtunnel backup share' "$age"
    else
        # only the start of the download is known, not that it went to the end
        doctor_ok 'Download of a backup started %s day(s) ago (check its size on your computer)' "$age"
    fi
}

doctor_main() {
    local ip
    DOCTOR_ERRORS=0
    DOCTOR_WARNINGS=0
    banner
    section 'DIAGNOSTICS'
    printf '%s ' "$(t 'Looking for the public IP address…')"
    ip=$(public_ipv4)
    echo "${ip:-$(t 'not found')}"
    doctor_system
    if vpn_installed; then doctor_vpn "$ip"; fi
    if seedbox_installed; then doctor_seedbox "$ip"; fi
    doctor_firewall
    if vpn_installed || seedbox_installed; then doctor_backup; fi
    echo
    if ((DOCTOR_ERRORS)); then
        err '%s problem(s), %s warning(s).' "$DOCTOR_ERRORS" "$DOCTOR_WARNINGS"
    elif ((DOCTOR_WARNINGS)); then
        warn 'No blocking problem, %s warning(s).' "$DOCTOR_WARNINGS"
    else
        ok 'Everything is fine.'
    fi
    pause
}
