#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — seedbox module
#
#  Transmission  : only listens on 127.0.0.1, protected by its own password,
#                  and locked down by systemd (ProtectSystem=strict…)
#  nginx         : the only way in, HTTPS + password (same login)
#  Let's Encrypt : « webroot » validation through nginx, so the automatic
#                  renewal works (certbot.timer); self-signed as a fallback
#  SFTP          : replaces FTP; the user is locked in the data folder, with
#                  no shell and no tunnel; password and/or SSH keys
#  fail2ban      : SSH/SFTP, web password, repeat offenders (nftables)
#
#  Passwords are never stored in clear: only their hashes (system, nginx,
#  Transmission) are kept in /etc/seedtunnel/seedbox.secrets, so everything
#  can be applied again or restored without asking for the password.
#
#  Folders: <data>/complete    finished downloads (and shared)
#           <data>/incomplete  downloads in progress
#           <data>/watch       drop a .torrent here, it starts by itself
#           <data>/documents   personal space (Transmission has no access)
# =============================================================================

SEEDBOX_CONF_FILE="$APP_STATE_DIR/seedbox.conf"
SEEDBOX_SECRETS_FILE="$APP_STATE_DIR/seedbox.secrets"
SEEDBOX_SSL_DIR="$APP_STATE_DIR/ssl"
NGINX_SITE="/etc/nginx/sites-available/seedtunnel"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/seedtunnel"
NGINX_HTPASSWD="/etc/nginx/seedtunnel.htpasswd"
# site installed by the nginx package, replaced by the seedbox
NGINX_DEFAULT_SITE="/etc/nginx/sites-enabled/default"
SSHD_SEEDBOX_CONF="/etc/ssh/sshd_config.d/seedtunnel-seedbox.conf"
SFTP_KEYS_DIR="/etc/ssh/seedtunnel_authorized_keys"
FAIL2BAN_JAIL="/etc/fail2ban/jail.d/seedtunnel.local"
FAIL2BAN_MAIN_CONF="/etc/fail2ban/fail2ban.d/seedtunnel.local"
TRANSMISSION_DROPIN="/etc/systemd/system/transmission-daemon.service.d/seedtunnel.conf"
TRANSMISSION_USER="debian-transmission"
# torrents, progress (« resume ») and settings of Transmission (Debian)
TRANSMISSION_STATE_DIR="/var/lib/transmission-daemon/.config/transmission-daemon"
TRANSMISSION_RPC_PORT=9091
LETSENCRYPT_WEBROOT="/var/www/letsencrypt"
LETSENCRYPT_CERT_NAME="seedtunnel"
LETSENCRYPT_DIR="/etc/letsencrypt/live/$LETSENCRYPT_CERT_NAME"
# the VPN clients use 60001 and above
TORRENT_PORT=60000
# password being changed (never written to disk)
SEEDBOX_NEW_PASSWORD=""

# Settings imposed on Transmission. DHT, PEX, LPD and uTP are off: suited to
# private trackers (can be changed in the web interface, Preferences).
read -r -d '' TRANSMISSION_SETTINGS_FILTER <<'JQ' || true
{
  "download-dir": $dl,
  "incomplete-dir": $inc,
  "incomplete-dir-enabled": true,
  "watch-dir": $watch,
  "watch-dir-enabled": true,
  "rpc-enabled": true,
  "rpc-bind-address": "127.0.0.1",
  "rpc-port": $rpcport,
  "rpc-authentication-required": true,
  "rpc-username": $user,
  "rpc-password": $hash,
  "rpc-whitelist-enabled": true,
  "rpc-whitelist": "127.0.0.1,::1",
  "rpc-host-whitelist-enabled": false,
  "peer-port": $peerport,
  "peer-port-random-on-start": false,
  "port-forwarding-enabled": false,
  "dht-enabled": false,
  "pex-enabled": false,
  "lpd-enabled": false,
  "utp-enabled": false,
  "umask": 2
}
JQ

seedbox_load() {
    SEEDBOX_USER=""
    SEEDBOX_DOMAIN=""
    SEEDBOX_DATA_DIR=""
    # selfsigned | letsencrypt | staging: certificate served right now
    SEEDBOX_CERTIFICATE="selfsigned"
    # auto | yes | no: should a Let's Encrypt certificate be requested?
    SEEDBOX_LETSENCRYPT="auto"
    # production | staging: Let's Encrypt servers used
    SEEDBOX_LETSENCRYPT_SERVER="production"
    # yes | no: does SFTP accept the password (otherwise SSH keys only)
    SEEDBOX_SFTP_PASSWORD="yes"
    SEEDBOX_HASH_SYSTEM=""
    SEEDBOX_HASH_WEB=""
    SEEDBOX_HASH_TRANSMISSION=""
    state_read "$SEEDBOX_CONF_FILE"
    state_read "$SEEDBOX_SECRETS_FILE"
}

seedbox_save() {
    state_write "$SEEDBOX_CONF_FILE" SEEDBOX_USER SEEDBOX_DOMAIN SEEDBOX_DATA_DIR SEEDBOX_CERTIFICATE \
        SEEDBOX_LETSENCRYPT SEEDBOX_LETSENCRYPT_SERVER SEEDBOX_SFTP_PASSWORD
}

seedbox_installed() { [[ -f $SEEDBOX_CONF_FILE ]]; }

seedbox_require_installed() {
    seedbox_installed || die 'The seedbox is not installed:  seedtunnel seedbox install'
}

# Real settings file of Transmission (Debian puts it in /etc)
transmission_settings_file() {
    local link="$TRANSMISSION_STATE_DIR/settings.json"
    if [[ -e $link ]]; then readlink -f "$link"; else printf '%s' /etc/transmission-daemon/settings.json; fi
}

seedbox_certificate_label() {
    case $SEEDBOX_CERTIFICATE in
        letsencrypt) printf "Let's Encrypt" ;;
        staging) t "Let's Encrypt (test server, not trusted by browsers)" ;;
        *) t 'self-signed' ;;
    esac
}

# --- Checks ---------------------------------------------------------------------------

seedbox_is_valid_user() { [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }

seedbox_is_valid_domain() {
    [[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || is_ipv4 "$1"
}

# IPv4 addresses of a name, asked to a public DNS server (not the local cache)
dns_ipv4_addresses() {
    dig +short +time=3 +tries=2 A "$1" @9.9.9.9 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' || true
}

dns_points_here() {
    [[ -n $2 ]] && grep -qxF "$2" <<<"$(dns_ipv4_addresses "$1")"
}

# Suggests a name that already points to this server: name of the machine, or
# reverse name given by the provider (e.g. vps-1234abcd.vps.ovh.net). Else the IP.
seedbox_guess_domain() {
    local ip=$1 candidate reverse
    reverse=$(dig +short -x "$ip" @9.9.9.9 2>/dev/null | sed -n '1s/\.$//p' || true)
    for candidate in "$(hostname --fqdn 2>/dev/null || true)" "$reverse"; do
        candidate=${candidate,,}
        if [[ -n $candidate ]] && ! is_ipv4 "$candidate" && seedbox_is_valid_domain "$candidate" \
            && dns_points_here "$candidate" "$ip"; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    printf '%s' "$ip"
}

# Biggest local partition; if it is « / », /srv/seedbox is used
seedbox_default_data_dir() {
    local mount
    mount=$(df -lP -x tmpfs -x devtmpfs -x overlay -x squashfs -x vfat 2>/dev/null \
        | awk 'NR > 1 { print $4, $6 }' | sort -nr | awk 'NR == 1 { print $2 }' || true)
    case $mount in
        "" | / | /boot*) printf '/srv/seedbox' ;;
        *) printf '%s/seedbox' "${mount%/}" ;;
    esac
}

# sshd requires every folder in the path of the SFTP chroot to belong to root
# and to be writable by nobody else.
seedbox_check_data_dir() {
    local path=$1 current="" part owner mode
    local -a parts
    if [[ ! $path =~ ^(/[A-Za-z0-9._-]+)+$ || $path == *..* ]]; then
        warn 'Invalid path: /folder/subfolder (letters, digits, . _ -).'
        return 1
    fi
    case $path in
        /bin | /boot | /dev | /etc | /home | /lib | /lib64 | /media | /mnt | /opt | /proc | /root | /run | /sbin | /srv | /sys | /tmp | /usr | /var)
            warn 'Choose a subfolder, not a system folder (e.g. %s/seedbox).' "$path"
            return 1
            ;;
    esac
    IFS=/ read -r -a parts <<<"${path#/}"
    for part in "${parts[@]}"; do
        current+="/$part"
        # the rest will be created by the script (root, 755)
        [[ -e $current ]] || break
        if [[ ! -d $current ]]; then
            warn '%s exists but is not a folder.' "$current"
            return 1
        fi
        read -r owner mode < <(stat -L -c '%u %a' "$current")
        if ((owner != 0 || (8#$mode & 8#022))); then
            warn '%s must belong to root and be writable only by root (needed by the locked SFTP).' "$current"
            return 1
        fi
    done
    return 0
}

seedbox_check_web_ports() {
    local out
    out=$(ss -Hltnp '( sport = :80 or sport = :443 )' 2>/dev/null || true)
    # each listening line: nginx on one port does not cover another program on the other
    out=$(grep -v nginx <<<"$out" || true)
    if [[ -n $out ]]; then
        die 'Ports 80/443 are already used by another program:\n%s\n  Stop it (apache2 for example) before installing the seedbox.' "$out"
    fi
}

# --- Passwords (hashes only) -------------------------------------------------------

# Transmission stores « { » + sha1(password + salt) in hexadecimal + a salt of
# 8 characters. It is computed here: the password is never written in clear.
transmission_password_hash() {
    local salt="" random sum
    while ((${#salt} < 8)); do
        random=$(openssl rand -base64 12)
        salt+=${random//[^A-Za-z0-9]/}
    done
    salt=${salt:0:8}
    sum=$(printf '%s%s' "$1" "$salt" | sha1sum)
    printf '{%s%s' "${sum%% *}" "$salt"
}

# Computes and saves the three hashes of SEEDBOX_NEW_PASSWORD (the user must exist)
seedbox_hash_password() {
    # printf is built into bash: the password does not show in « ps »
    printf '%s:%s\n' "$SEEDBOX_USER" "$SEEDBOX_NEW_PASSWORD" | chpasswd
    SEEDBOX_HASH_SYSTEM=$(getent shadow "$SEEDBOX_USER" | cut -d: -f2)
    SEEDBOX_HASH_WEB=$(printf '%s\n' "$SEEDBOX_NEW_PASSWORD" | openssl passwd -6 -stdin)
    SEEDBOX_HASH_TRANSMISSION=$(transmission_password_hash "$SEEDBOX_NEW_PASSWORD")
    state_write "$SEEDBOX_SECRETS_FILE" SEEDBOX_HASH_SYSTEM SEEDBOX_HASH_WEB SEEDBOX_HASH_TRANSMISSION
}

# Is this password already the saved one? (running again changes nothing)
seedbox_password_matches() {
    local salt computed
    [[ $SEEDBOX_HASH_WEB == '$6$'* ]] || return 1
    salt=${SEEDBOX_HASH_WEB#\$6\$}
    salt=${salt%%\$*}
    computed=$(printf '%s\n' "$1" | openssl passwd -6 -salt "$salt" -stdin)
    [[ $computed == "$SEEDBOX_HASH_WEB" ]]
}

# --- Questions (interactive mode) ---------------------------------------------------

seedbox_ask_user() {
    local current=${1-} name
    while true; do
        ask name 'User name (web and SFTP)' "${SEEDBOX_USER:-lancelot}"
        if ! seedbox_is_valid_user "$name"; then
            warn 'Lowercase letters, digits, - and _ only (32 characters at most).'
        elif [[ $name != "$current" ]] && id "$name" &>/dev/null; then
            warn '"%s" already exists on this system: choose another name.' "$name"
        else
            break
        fi
    done
    OPT_NEW_USER=$name
    ask_password SEEDBOX_NEW_PASSWORD
}

# Asks for the domain name and checks that it points to this server.
# Sets SEEDBOX_DOMAIN, and SEEDBOX_LETSENCRYPT: auto if Let's Encrypt has a
# chance, otherwise no. With « change » (seedbox already installed): an empty
# answer or Q goes back, with status 1, and nothing is changed.
seedbox_ask_domain() {
    local ip=$1 mode=${2-} ips choice answer default=$SEEDBOX_DOMAIN
    if [[ $mode == change ]]; then default=""; fi
    text seedbox_domain_help
    echo
    while true; do
        if [[ $mode == change ]]; then
            ask answer 'New domain name or IP (empty to go back)' "$default"
        else
            ask answer 'Domain name or IP' "$default"
        fi
        answer=${answer,,}
        answer=${answer#http://}
        answer=${answer#https://}
        answer=${answer%/}
        if [[ -z $answer && $mode == change ]]; then return 1; fi
        if ! seedbox_is_valid_domain "$answer"; then
            warn 'Invalid domain name.'
            continue
        fi
        default=$answer
        if is_ipv4 "$answer"; then
            SEEDBOX_DOMAIN=$answer
            SEEDBOX_LETSENCRYPT=no
            return 0
        fi
        ips=$(dns_ipv4_addresses "$answer")
        if [[ -z $ips ]]; then
            warn '"%s" does not point to any IPv4 address.' "$answer"
        elif ! grep -qxF "$ip" <<<"$ips"; then
            warn '"%s" points to %s, not to this server (%s).' "$answer" "${ips//$'\n'/, }" "$ip"
        else
            ok '"%s" points to this server (%s).' "$answer" "$ip"
            SEEDBOX_DOMAIN=$answer
            SEEDBOX_LETSENCRYPT=auto
            return 0
        fi
        say "  Let's Encrypt will not be able to issue a certificate for this name."
        say '  (after a DNS change, allow a few minutes to a few hours)'
        say '  R) Try again    C) Continue with a self-signed certificate'
        if [[ $mode == change ]]; then say '  Q) Back, nothing is changed'; fi
        ask choice 'Your choice' "R"
        case ${choice,,} in
            c)
                SEEDBOX_DOMAIN=$answer
                SEEDBOX_LETSENCRYPT=no
                return 0
                ;;
            q) if [[ $mode == change ]]; then return 1; fi ;;
        esac
    done
}

# --- Applying (idempotent) -----------------------------------------------------------

seedbox_apply_user() {
    local current
    if ! id "$SEEDBOX_USER" &>/dev/null; then
        run "$(t 'Creating the user %s' "$SEEDBOX_USER")" useradd --no-create-home --home-dir / \
            --shell /usr/sbin/nologin --user-group --groups "$TRANSMISSION_USER" \
            --comment "seedtunnel seedbox" "$SEEDBOX_USER"
    fi
    if [[ " $(id -nG "$SEEDBOX_USER") " != *" $TRANSMISSION_USER "* ]]; then
        usermod -aG "$TRANSMISSION_USER" "$SEEDBOX_USER"
    fi
    if [[ -n $SEEDBOX_NEW_PASSWORD ]]; then
        seedbox_hash_password
    elif [[ -z $SEEDBOX_HASH_SYSTEM || -z $SEEDBOX_HASH_WEB || -z $SEEDBOX_HASH_TRANSMISSION ]]; then
        die 'No known password for %s: set one with  seedtunnel seedbox password' "$SEEDBOX_USER"
    else
        current=$(getent shadow "$SEEDBOX_USER" | cut -d: -f2)
        if [[ $current != "$SEEDBOX_HASH_SYSTEM" ]]; then
            printf '%s:%s\n' "$SEEDBOX_USER" "$SEEDBOX_HASH_SYSTEM" | chpasswd -e
        fi
    fi
}

seedbox_apply_dirs() {
    install -d -m 755 -o root -g root "$SEEDBOX_DATA_DIR"
    # setgid (the 2 of 2775): everything created inside belongs to the group of
    # Transmission, so the SFTP user can read and delete the files.
    install -d -m 2775 -o "$TRANSMISSION_USER" -g "$TRANSMISSION_USER" \
        "$SEEDBOX_DATA_DIR/complete" "$SEEDBOX_DATA_DIR/incomplete" "$SEEDBOX_DATA_DIR/watch"
    install -d -m 700 -o "$SEEDBOX_USER" -g "$SEEDBOX_USER" "$SEEDBOX_DATA_DIR/documents"
}

transmission_desired_settings() {
    jq -n --arg dl "$SEEDBOX_DATA_DIR/complete" --arg inc "$SEEDBOX_DATA_DIR/incomplete" \
        --arg watch "$SEEDBOX_DATA_DIR/watch" --arg user "$SEEDBOX_USER" --arg hash "$SEEDBOX_HASH_TRANSMISSION" \
        --argjson rpcport "$TRANSMISSION_RPC_PORT" --argjson peerport "$TORRENT_PORT" "$TRANSMISSION_SETTINGS_FILTER"
}

# Are the wanted settings already in place? (« umask » is ignored: Transmission
# writes it back in its own way depending on the version)
transmission_settings_uptodate() {
    [[ -s $1 ]] || return 1
    jq -e --argjson d "$2" '. as $c | $d | del(.umask) | to_entries | all(.value == $c[.key])' "$1" &>/dev/null
}

# systemd hardening: if Transmission were compromised, it could only write to
# its own folders and to the download folder.
transmission_generate_dropin() {
    local home=yes
    case $SEEDBOX_DATA_DIR in
        /home/* | /root/* | /run/user/*) home=no ;;
    esac
    cat <<EOF
# Written by seedtunnel — Transmission locked down by systemd
[Unit]
# downloads on a disk of their own: never on the system disk if it is missing
RequiresMountsFor=$SEEDBOX_DATA_DIR

[Service]
# not started on an almost full disk (« + »: this check runs as root)
ExecStartPre=+$APP_DIR/seedtunnel.sh diskguard-prestart
UMask=0002
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=-/var/lib/transmission-daemon -/etc/transmission-daemon -$SEEDBOX_DATA_DIR
ProtectHome=$home
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
EOF
}

seedbox_apply_transmission() {
    local settings desired restart=0
    settings=$(transmission_settings_file)
    desired=$(transmission_desired_settings)
    install -d -m 755 "${TRANSMISSION_DROPIN%/*}"
    if write_if_changed "$TRANSMISSION_DROPIN" 644 root:root transmission_generate_dropin; then
        run 'Reloading systemd' systemctl daemon-reload
        restart=1
    fi
    if ! transmission_settings_uptodate "$settings" "$desired"; then
        # Transmission writes its settings back when it stops: change them while stopped
        run 'Stopping Transmission' systemctl stop transmission-daemon
        [[ -s $settings ]] || printf '{}\n' >"$settings"
        if ! jq --argjson d "$desired" '. + $d' "$settings" >"$settings.tmp" || ! jq empty "$settings.tmp" 2>/dev/null; then
            rm -f "$settings.tmp"
            systemctl start transmission-daemon >>"$APP_LOG" 2>&1 || true
            die 'Cannot write the settings of Transmission %s (invalid JSON or disk full?). The previous ones were kept.' "$settings"
        fi
        # replaced by renaming, never half-written ($settings is the real file:
        # the link of Debian points to it, and still does)
        if ! { chown "$TRANSMISSION_USER:$TRANSMISSION_USER" "$settings.tmp" && chmod 600 "$settings.tmp" \
            && mv -f "$settings.tmp" "$settings"; }; then
            rm -f "$settings.tmp"
            systemctl start transmission-daemon >>"$APP_LOG" 2>&1 || true
            die 'Cannot write the settings of Transmission %s (invalid JSON or disk full?). The previous ones were kept.' "$settings"
        fi
        restart=1
    fi
    systemctl enable --quiet transmission-daemon 2>/dev/null || true
    # stopped on purpose because the disk is almost full: left alone
    if diskguard_stopped; then return 0; fi
    if ((restart)) || ! systemctl is-active --quiet transmission-daemon; then
        run 'Starting Transmission' systemctl restart transmission-daemon
    fi
}

seedbox_apply_htpasswd() {
    write_if_changed "$NGINX_HTPASSWD" 640 root:www-data \
        printf '%s:%s\n' "$SEEDBOX_USER" "$SEEDBOX_HASH_WEB" || true
}

# Self-signed fallback certificate, created again only if it no longer matches
seedbox_selfsigned_ensure() {
    local san="DNS:$SEEDBOX_DOMAIN" check=""
    if is_ipv4 "$SEEDBOX_DOMAIN"; then san="IP:$SEEDBOX_DOMAIN"; fi
    install -d -m 700 "$SEEDBOX_SSL_DIR"
    if [[ -s $SEEDBOX_SSL_DIR/selfsigned.crt && -s $SEEDBOX_SSL_DIR/selfsigned.key ]]; then
        if is_ipv4 "$SEEDBOX_DOMAIN"; then
            check=$(openssl x509 -in "$SEEDBOX_SSL_DIR/selfsigned.crt" -noout -checkip "$SEEDBOX_DOMAIN" 2>/dev/null || true)
        else
            check=$(openssl x509 -in "$SEEDBOX_SSL_DIR/selfsigned.crt" -noout -checkhost "$SEEDBOX_DOMAIN" 2>/dev/null || true)
        fi
        [[ $check == *"does match"* ]] && return 0
    fi
    run 'Creating a self-signed certificate (fallback)' \
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
        -subj "/CN=$SEEDBOX_DOMAIN" -addext "subjectAltName=$san" \
        -keyout "$SEEDBOX_SSL_DIR/selfsigned.key" -out "$SEEDBOX_SSL_DIR/selfsigned.crt"
}

# SHA-256 fingerprint of the self-signed certificate, as browsers show it
seedbox_selfsigned_fingerprint() {
    openssl x509 -in "$SEEDBOX_SSL_DIR/selfsigned.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true
}

# Is the existing Let's Encrypt certificate for this name?
letsencrypt_matches_domain() {
    local check
    [[ -e $LETSENCRYPT_DIR/cert.pem ]] || return 1
    check=$(openssl x509 -in "$LETSENCRYPT_DIR/cert.pem" -noout -checkhost "$SEEDBOX_DOMAIN" 2>/dev/null || true)
    [[ $check == *"does match"* ]]
}

# … and usable for the requested kind (production | staging), valid for 1 more day?
letsencrypt_usable() {
    local issuer
    letsencrypt_matches_domain || return 1
    openssl x509 -in "$LETSENCRYPT_DIR/cert.pem" -noout -checkend 86400 &>/dev/null || return 1
    issuer=$(openssl x509 -in "$LETSENCRYPT_DIR/cert.pem" -noout -issuer 2>/dev/null || true)
    if [[ $issuer == *STAGING* ]]; then [[ $1 == staging ]]; else [[ $1 == production ]]; fi
}

# Expiry date of the Let's Encrypt certificate (YYYY-MM-DD), empty if none
letsencrypt_expiry_date() {
    local end
    end=$(openssl x509 -in "$LETSENCRYPT_DIR/cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2 || true)
    [[ -n $end ]] || return 0
    date -d "$end" +%F 2>/dev/null || true
}

seedbox_certificate_mode() {
    if [[ $SEEDBOX_LETSENCRYPT_SERVER == staging ]]; then printf staging; else printf letsencrypt; fi
}

# Requests the Let's Encrypt certificate. Status 1 if it fails.
letsencrypt_request() {
    local label=""
    local -a extra=()
    install -d -m 755 "$LETSENCRYPT_WEBROOT"
    # Existing certificate for another name or another server: start over
    if [[ -e $LETSENCRYPT_DIR/cert.pem ]] && ! letsencrypt_usable "$SEEDBOX_LETSENCRYPT_SERVER"; then
        certbot delete --cert-name "$LETSENCRYPT_CERT_NAME" --non-interactive >>"$APP_LOG" 2>&1 || true
    fi
    if [[ $SEEDBOX_LETSENCRYPT_SERVER == staging ]]; then
        extra=(--test-cert)
        label=" $(t '(test server)')"
    fi
    printf '  %s… ' "$(t "Requesting the Let's Encrypt certificate%s for %s" "$label" "$SEEDBOX_DOMAIN")"
    printf '\n=== %(%F %T)T · certbot for %s\n' -1 "$SEEDBOX_DOMAIN" >>"$APP_LOG"
    if certbot certonly --webroot -w "$LETSENCRYPT_WEBROOT" --cert-name "$LETSENCRYPT_CERT_NAME" -d "$SEEDBOX_DOMAIN" \
        --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring \
        --deploy-hook "systemctl reload nginx" "${extra[@]}" >>"$APP_LOG" 2>&1; then
        printf '%s%s%s\n' "$C_GREEN" "$(t 'ok')" "$C_RESET"
        return 0
    fi
    printf '%s%s%s\n' "$C_RED" "$(t 'failed')" "$C_RESET"
    return 1
}

nginx_generate_site() {
    local crt key hsts="" ipv6_80="" ipv6_443=""
    if [[ $SEEDBOX_CERTIFICATE == selfsigned ]]; then
        crt="$SEEDBOX_SSL_DIR/selfsigned.crt"
        key="$SEEDBOX_SSL_DIR/selfsigned.key"
    else
        crt="$LETSENCRYPT_DIR/fullchain.pem"
        key="$LETSENCRYPT_DIR/privkey.pem"
    fi
    # HSTS only with a real certificate: otherwise the browser would then refuse
    # to let the user accept the security warning.
    if [[ $SEEDBOX_CERTIFICATE == letsencrypt ]]; then
        hsts=$'\n    add_header Strict-Transport-Security "max-age=31536000" always;'
    fi
    if [[ -e /proc/net/if_inet6 ]]; then
        ipv6_80=$'\n    listen [::]:80;'
        ipv6_443=$'\n    listen [::]:443 ssl;'
    fi
    cat <<EOF
# Written by seedtunnel — use the menu rather than editing this file.

$(share_generate_nginx_http)

server {
    listen 80;$ipv6_80
    server_name $SEEDBOX_DOMAIN;

    # Let's Encrypt validation and renewal
    location ^~ /.well-known/acme-challenge/ {
        root $LETSENCRYPT_WEBROOT;
        default_type text/plain;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;$ipv6_443
    server_name $SEEDBOX_DOMAIN;

    ssl_certificate     $crt;
    ssl_certificate_key $key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:seedtunnel:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    server_tokens off;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;$hsts

    auth_basic "Seedbox";
    auth_basic_user_file $NGINX_HTPASSWD;

    # Adding .torrent files from the web interface
    client_max_body_size 32m;
$(share_generate_nginx "${hsts//$'\n    '/$'\n        '}")

    location = / {
        return 302 /transmission/web/;
    }
    location /transmission/ {
        proxy_pass http://127.0.0.1:$TRANSMISSION_RPC_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
EOF
}

seedbox_apply_nginx() {
    if write_if_changed "$NGINX_SITE" 644 root:root nginx_generate_site; then pending_set nginx; fi
    if [[ ! -L $NGINX_SITE_LINK ]]; then
        ln -sf "$NGINX_SITE" "$NGINX_SITE_LINK"
        pending_set nginx
    fi
    if [[ -e $NGINX_DEFAULT_SITE || -L $NGINX_DEFAULT_SITE ]]; then
        rm -f "$NGINX_DEFAULT_SITE"
        pending_set nginx
    fi
    if pending nginx || ! systemctl is-active --quiet nginx; then
        run 'Checking the nginx configuration' nginx -t
        run 'Reloading nginx' systemctl reload-or-restart nginx
        pending_clear nginx
    fi
}

# Chooses the certificate served: Let's Encrypt if available or obtained,
# otherwise the self-signed one.
seedbox_apply_https() {
    local want=0 ip
    seedbox_selfsigned_ensure
    if is_ipv4 "$SEEDBOX_DOMAIN" || [[ $SEEDBOX_LETSENCRYPT == no ]]; then
        SEEDBOX_CERTIFICATE=selfsigned
    elif letsencrypt_usable "$SEEDBOX_LETSENCRYPT_SERVER"; then
        # certificate already in place (run again, restore): nothing to request
        SEEDBOX_CERTIFICATE=$(seedbox_certificate_mode)
    else
        if [[ $SEEDBOX_LETSENCRYPT == yes ]]; then
            want=1
        else
            ip=$(public_ipv4)
            if dns_points_here "$SEEDBOX_DOMAIN" "$ip"; then
                want=1
            else
                warn '"%s" does not point to this server (%s): self-signed certificate.' "$SEEDBOX_DOMAIN" "$ip"
            fi
        fi
        if ((want)); then
            # nginx must already answer on port 80 for the validation
            if [[ $SEEDBOX_CERTIFICATE != selfsigned ]] && ! letsencrypt_matches_domain; then SEEDBOX_CERTIFICATE=selfsigned; fi
            seedbox_apply_nginx
            if letsencrypt_request; then
                SEEDBOX_CERTIFICATE=$(seedbox_certificate_mode)
                ok "Let's Encrypt certificate installed, renewed automatically."
            elif letsencrypt_usable "$SEEDBOX_LETSENCRYPT_SERVER"; then
                SEEDBOX_CERTIFICATE=$(seedbox_certificate_mode)
                warn "Let's Encrypt did not answer, the existing certificate (still valid) is kept."
            else
                SEEDBOX_CERTIFICATE=selfsigned
                warn "Let's Encrypt did not issue a certificate: the self-signed one stays in place."
                text letsencrypt_failed_help
            fi
        else
            SEEDBOX_CERTIFICATE=selfsigned
        fi
    fi
    seedbox_apply_nginx
    # automatic renewal (installed with the certbot package)
    if [[ $SEEDBOX_CERTIFICATE != selfsigned ]] && ! systemctl is-active --quiet certbot.timer; then
        run 'Enabling automatic renewal' systemctl enable --now certbot.timer
    fi
}

sftp_has_keys() { [[ -s $SFTP_KEYS_DIR/$SEEDBOX_USER ]] && grep -q '^ssh-\|^ecdsa-\|^sk-' "$SFTP_KEYS_DIR/$SEEDBOX_USER"; }

# Effective SSH settings of the seedbox account connecting from the address
# $1, as sshd applies them
seedbox_sshd_settings() { sshd -T -C "user=$SEEDBOX_USER,host=$1,addr=$1" 2>/dev/null || true; }

# Are all the restrictions written for the account (sshd_generate_seedbox_conf)
# in force, wherever it connects from? From the server itself, through the
# VPN, from the Internet: a Match Address block could treat them differently.
seedbox_sftp_rule_applies() {
    local address settings line
    for address in 127.0.0.1 "$VPN_SUBNET.2" 203.0.113.1; do
        settings=$(seedbox_sshd_settings "$address")
        grep -qxF "chrootdirectory $SEEDBOX_DATA_DIR" <<<"$settings" || return 1
        grep -q '^forcecommand internal-sftp' <<<"$settings" || return 1
        for line in 'permittty no' 'allowtcpforwarding no' 'allowagentforwarding no' \
            'allowstreamlocalforwarding no' 'x11forwarding no' 'permittunnel no'; do
            grep -qxF "$line" <<<"$settings" || return 1
        done
    done
}

# A suspended account cannot log in at all, by password or by key (expired
# account), and its sessions are closed: used while its SFTP restrictions are
# not in force. Expiry « 1 » (2 January 1970) marks a suspension by seedtunnel.
# Checked, not assumed: fails if the account is not expired afterwards, or
# still has processes.
seedbox_user_suspend() {
    local user=${1:-$SEEDBOX_USER} i
    id "$user" &>/dev/null || return 0
    usermod --expiredate 1 "$user" >>"$APP_LOG" 2>&1 || true
    [[ $(getent shadow "$user" 2>/dev/null | cut -d: -f8 || true) == 1 ]] || return 1
    for i in {1..20}; do
        pkill -KILL -u "$user" >>"$APP_LOG" 2>&1 || true
        if ! pgrep -u "$user" >/dev/null 2>&1; then return 0; fi
        sleep 0.2
    done
    return 1
}

# Back to normal, if it was suspended by seedtunnel
seedbox_user_resume() {
    local user=${1:-$SEEDBOX_USER}
    if [[ $(getent shadow "$user" 2>/dev/null | cut -d: -f8 || true) == 1 ]]; then
        usermod --expiredate '' "$user" >>"$APP_LOG" 2>&1 || true
    fi
}

# Renames the account, its group and its SSH keys, suspended meanwhile (its
# SFTP rule is written for the old name). If a step fails, the steps already
# done are undone: the account keeps its old name, never half renamed.
seedbox_rename_account() {
    local old=$1 new=$2 group=0
    if ! seedbox_user_suspend "$old"; then
        seedbox_user_resume "$old"
        die 'Cannot suspend %s before renaming it (details in %s): nothing was changed.' "$old" "$APP_LOG"
    fi
    usermod --login "$new" "$old" >>"$APP_LOG" 2>&1 || seedbox_rename_undo "$old" "$new" 0 0
    if getent group "$old" >/dev/null; then
        groupmod --new-name "$new" "$old" >>"$APP_LOG" 2>&1 || seedbox_rename_undo "$old" "$new" 1 0
        group=1
    fi
    if [[ -e $SFTP_KEYS_DIR/$old ]]; then
        mv -f "$SFTP_KEYS_DIR/$old" "$SFTP_KEYS_DIR/$new" || seedbox_rename_undo "$old" "$new" 1 "$group"
    fi
    ok 'Account %s renamed to %s' "$old" "$new"
}

# seedbox_rename_undo OLD NEW USER_RENAMED GROUP_RENAMED — a step of the
# rename failed: the old names come back, then stop
seedbox_rename_undo() {
    local old=$1 new=$2
    if (($4)); then groupmod --new-name "$old" "$new" >>"$APP_LOG" 2>&1 || true; fi
    if (($3)) && ! usermod --login "$old" "$new" >>"$APP_LOG" 2>&1; then
        die 'Renaming %s to %s failed, and so did putting the old name back (details in %s). By hand:  usermod --login %s %s' "$old" "$new" "$APP_LOG" "$old" "$new"
    fi
    seedbox_user_resume "$old"
    die 'Renaming %s to %s failed (details in %s): the account keeps its name %s.' "$old" "$new" "$APP_LOG" "$old"
}

sshd_generate_seedbox_conf() {
    cat <<EOF
# Written by seedtunnel — SFTP access to the seedbox, locked in $SEEDBOX_DATA_DIR
Match User $SEEDBOX_USER
    ChrootDirectory $SEEDBOX_DATA_DIR
    ForceCommand internal-sftp -u 0002
    AuthorizedKeysFile $SFTP_KEYS_DIR/%u
    PasswordAuthentication $SEEDBOX_SFTP_PASSWORD
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTunnel no
EOF
}

seedbox_apply_sftp() {
    local settings
    install -d -m 755 "$SFTP_KEYS_DIR"
    if [[ ! -e $SFTP_KEYS_DIR/$SEEDBOX_USER ]]; then install -m 644 /dev/null "$SFTP_KEYS_DIR/$SEEDBOX_USER"; fi
    if [[ $SEEDBOX_SFTP_PASSWORD == no ]] && ! sftp_has_keys; then
        warn 'No SSH key saved: the SFTP password stays allowed.'
        SEEDBOX_SFTP_PASSWORD=yes
    fi
    if [[ -e $SSHD_SEEDBOX_CONF ]]; then cp -p "$SSHD_SEEDBOX_CONF" "$SSHD_SEEDBOX_CONF.previous"; fi
    if write_if_changed "$SSHD_SEEDBOX_CONF" 644 root:root sshd_generate_seedbox_conf; then pending_set ssh; fi
    if pending ssh; then
        # SSH is only reloaded if the configuration is valid: no risk of being
        # locked out. Otherwise, back to the previous version.
        if ! sshd -t >>"$APP_LOG" 2>&1; then
            if [[ -e $SSHD_SEEDBOX_CONF.previous ]]; then
                mv -f "$SSHD_SEEDBOX_CONF.previous" "$SSHD_SEEDBOX_CONF"
            else
                rm -f "$SSHD_SEEDBOX_CONF"
            fi
            pending_clear ssh
            die 'sshd refuses the generated configuration (details in %s). SSH was not changed.' "$APP_LOG"
        fi
        run 'Reloading SSH' systemctl try-reload-or-restart ssh.service
        pending_clear ssh
    fi
    rm -f "$SSHD_SEEDBOX_CONF.previous"

    # Do the restrictions really apply to the account (Include present, no
    # Match block before ours…)? If not, the account is suspended: no access
    # at all rather than an account without its restrictions.
    if seedbox_sftp_rule_applies; then
        seedbox_user_resume
    elif seedbox_user_suspend; then
        die 'The SFTP restrictions (chroot, SFTP only, no tunnel) do not apply to %s: the account is suspended. /etc/ssh/sshd_config must contain "Include /etc/ssh/sshd_config.d/*.conf" before any Match block; then run:  seedtunnel apply' "$SEEDBOX_USER"
    else
        die 'The SFTP restrictions (chroot, SFTP only, no tunnel) do not apply to %s, and the account could not be suspended (details in %s). Suspend it by hand:  usermod --expiredate 1 %s && pkill -KILL -u %s' "$SEEDBOX_USER" "$APP_LOG" "$SEEDBOX_USER" "$SEEDBOX_USER"
    fi
    settings=$(seedbox_sshd_settings 127.0.0.1)
    if [[ $settings == *$'\nallowusers '* || $settings == *$'\nallowgroups '* ]]; then
        warn 'Your SSH uses AllowUsers/AllowGroups: add %s to it so that it can connect.' "$SEEDBOX_USER"
    fi
}

fail2ban_generate_main() {
    # explicit log file: the « recidive » jail reads it
    cat <<'EOF'
# Written by seedtunnel
[DEFAULT]
logtarget = /var/log/fail2ban.log

[Definition]
logtarget = /var/log/fail2ban.log
EOF
}

fail2ban_generate_jail() {
    cat <<'EOF'
# Written by seedtunnel — protection against password guessing
[DEFAULT]
# The machine itself and the VPN clients are never banned
ignoreip  = 127.0.0.1/8 ::1 10.8.0.0/24
bantime   = 1h
findtime  = 10m
maxretry  = 5
banaction = nftables-multiport
banaction_allports = nftables[type=allports]

# SSH and SFTP: 5 failures in 10 min → banned 1 h from every port, which stays
# effective even when SSH does not listen on port 22
# (Debian 12+ has no /var/log/auth.log any more: the systemd journal is read)
[sshd]
enabled   = true
backend   = systemd
mode      = aggressive
banaction = %(banaction_allports)s

# Password of the web interface
[nginx-http-auth]
enabled = true
backend = auto
port    = http,https
logpath = /var/log/nginx/error.log

# Repeat offenders: banned 3 times in 24 h → banned 1 week from every port
[recidive]
enabled   = true
backend   = auto
logpath   = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime   = 1w
findtime  = 1d
maxretry  = 3
EOF
}

seedbox_apply_fail2ban() {
    local changed=0
    if write_if_changed "$FAIL2BAN_MAIN_CONF" 644 root:root fail2ban_generate_main; then changed=1; fi
    touch /var/log/fail2ban.log
    if write_if_changed "$FAIL2BAN_JAIL" 644 root:root fail2ban_generate_jail; then changed=1; fi
    if ((changed)) || ! systemctl is-active --quiet fail2ban; then
        systemctl enable --quiet fail2ban 2>/dev/null || true
        run 'Restarting fail2ban' systemctl restart fail2ban
    fi
}

# Puts the seedbox in the state described in /etc/seedtunnel (idempotent)
seedbox_apply() {
    apt_install transmission-daemon nginx certbot fail2ban python3-systemd bind9-dnsutils inotify-tools
    net_hardening_apply
    seedbox_apply_user
    seedbox_save
    # ports 80/443 open before the Let's Encrypt request
    firewall_refresh
    seedbox_apply_dirs
    seedbox_apply_transmission
    seedbox_apply_htpasswd
    seedbox_apply_https
    seedbox_apply_sftp
    seedbox_apply_fail2ban
    diskguard_install
    seedbox_save
}

# --- Check and summary -------------------------------------------------------------

# Authenticated request without a session token: Transmission answers 409 if
# HTTPS, nginx and both passwords work. Without a known password, we only
# check that access is refused (401).
seedbox_curl_auth() {
    local credentials="$SEEDBOX_USER:$SEEDBOX_NEW_PASSWORD"
    credentials=${credentials//\\/\\\\}
    credentials=${credentials//\"/\\\"}
    printf 'user = "%s"\n' "$credentials"
}

seedbox_http_code() {
    local -a target
    if is_ipv4 "$SEEDBOX_DOMAIN"; then
        target=(-H "Host: $SEEDBOX_DOMAIN" "https://127.0.0.1$1")
    else
        target=(--resolve "$SEEDBOX_DOMAIN:443:127.0.0.1" "https://$SEEDBOX_DOMAIN$1")
    fi
    if [[ ${2-} == auth ]]; then
        seedbox_curl_auth | curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -K - "${target[@]}" 2>/dev/null || true
    else
        curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "${target[@]}" 2>/dev/null || true
    fi
}

seedbox_selftest() {
    local code="" attempt
    for attempt in 1 2 3 4 5; do
        if [[ -n $SEEDBOX_NEW_PASSWORD ]]; then
            code=$(seedbox_http_code /transmission/rpc auth)
        else
            code=$(seedbox_http_code /transmission/web/)
        fi
        # 502: Transmission still starting
        [[ $code == 502 ]] || break
        sleep 2
    done
    case $code in
        409) ok 'Login test on the web interface: passed' ;;
        401)
            if [[ -n $SEEDBOX_NEW_PASSWORD ]]; then
                warn 'Login test: credentials refused (details in %s).' "$APP_LOG"
            else
                ok 'Web interface online and protected by a password'
            fi
            ;;
        502) warn 'Login test: nginx cannot reach Transmission (journalctl -u transmission-daemon).' ;;
        *) warn 'Login test: unexpected answer (code %s).' "${code:-$(t 'none')}" ;;
    esac
}

# First port on which SSH listens
ssh_first_port() {
    local settings
    settings=$(sshd -T 2>/dev/null || true)
    awk '$1 == "port" && !found { print $2; found = 1 }' <<<"$settings"
}

seedbox_summary() {
    local port
    port=$(ssh_first_port)
    port=${port:-22}
    echo
    text seedbox_summary
}

# --- SFTP connection settings (WinSCP, FileZilla) -------------------------------------

# Fingerprint of the key of the server, shown by SFTP programs at the first
# connection (e.g. « SHA256:szUj…NT8 ED25519 »): empty if not found
host_key_fingerprint() {
    local file=/etc/ssh/ssh_host_ed25519_key.pub
    [[ -r $file ]] || return 0
    ssh-keygen -l -E sha256 -f "$file" 2>/dev/null | awk '{ gsub(/[()]/, "", $NF); print $2, $NF }' || true
}

# Fingerprint in the format of WinSCP addresses: « ssh-ed25519-<SHA-256> »,
# base64 padded with « = », with « - » instead of « + » and « _ » instead of
# « / » (https://winscp.net/eng/docs/session_url)
host_key_fingerprint_url() {
    local file=/etc/ssh/ssh_host_ed25519_key.pub fingerprint
    [[ -r $file ]] || return 0
    fingerprint=$(ssh-keygen -l -E sha256 -f "$file" 2>/dev/null | awk '{ print $2 }' || true)
    fingerprint=${fingerprint#SHA256:}
    [[ -n $fingerprint ]] || return 0
    while ((${#fingerprint} % 4)); do fingerprint+="="; done
    fingerprint=${fingerprint//+/-}
    fingerprint=${fingerprint//\//_}
    printf 'ssh-ed25519-%s' "$fingerprint"
}

# Address to paste into WinSCP, with the fingerprint of the server when known:
# WinSCP then checks the key of the server by itself, without a question
winscp_url() {
    local port=$1 fingerprint
    fingerprint=$(host_key_fingerprint_url)
    if [[ -n $fingerprint ]]; then
        printf 'sftp://%s;fingerprint=%s@%s:%s/' "$SEEDBOX_USER" "$fingerprint" "$SEEDBOX_DOMAIN" "$port"
    else
        printf 'sftp://%s@%s:%s/' "$SEEDBOX_USER" "$SEEDBOX_DOMAIN" "$port"
    fi
}

# Site to import into FileZilla (File → Import…). Logontype 2: the password is
# asked at connection time, it is not in the file.
filezilla_generate_site() {
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3>
    <Servers>
        <Server>
            <Host>$SEEDBOX_DOMAIN</Host>
            <Port>$1</Port>
            <Protocol>1</Protocol>
            <Type>0</Type>
            <User>$SEEDBOX_USER</User>
            <Logontype>2</Logontype>
            <TimezoneOffset>0</TimezoneOffset>
            <PasvMode>MODE_DEFAULT</PasvMode>
            <MaximumMultipleConnections>0</MaximumMultipleConnections>
            <EncodingType>Auto</EncodingType>
            <BypassProxy>0</BypassProxy>
            <Name>Seedbox $SEEDBOX_DOMAIN</Name>
            <Comments />
            <Colour>0</Colour>
            <LocalDir />
            <RemoteDir />
            <SyncBrowsing>0</SyncBrowsing>
            <DirectoryComparison>0</DirectoryComparison>
        </Server>
    </Servers>
</FileZilla3>
EOF
}

# Link to the site to import into FileZilla
filezilla_share() {
    local port=$1 tmp fingerprint
    systemctl is-active --quiet nginx || die 'nginx is stopped:  seedtunnel seedbox restart'
    fingerprint=$(host_key_fingerprint)
    tmp=$(mktemp)
    filezilla_generate_site "$port" >"$tmp"
    share_create "$tmp" "seedbox-filezilla.xml" "$(t 'SFTP connection to the seedbox (FileZilla)')" \
        "$(text share_steps_filezilla)" "$(t 'The file holds no password.')"
    rm -f "$tmp"
}

# SFTP connection settings: address for WinSCP and, on request (« filezilla »),
# a link to the file to import into FileZilla
seedbox_sftp_config() {
    local port fingerprint keys_only="" url
    port=$(ssh_first_port)
    port=${port:-22}
    fingerprint=$(host_key_fingerprint)
    url=$(winscp_url "$port")
    if [[ $SEEDBOX_SFTP_PASSWORD == no ]]; then keys_only=" $(t '(SSH key only)')"; fi
    banner
    section 'SFTP CONNECTION TO THE SEEDBOX'
    say '  Protocol    : SFTP'
    say '  Host        : %s' "$SEEDBOX_DOMAIN"
    say '  Port        : %s' "$port"
    say '  User        : %s' "$SEEDBOX_USER$keys_only"
    if [[ -n $fingerprint ]]; then say '  Fingerprint : %s' "$fingerprint"; fi
    echo
    text sftp_config_help
    echo
    if [[ ${1-} == filezilla ]]; then
        filezilla_share "$port"
    elif ((INTERACTIVE)); then
        if confirm 'Also create a link to a file to import into FileZilla?' n; then
            filezilla_share "$port"
        fi
        if confirm 'Create an SSH key for WinSCP / FileZilla (connection without a password)?' n; then
            sftp_key_generate
        fi
    else
        say 'FileZilla: file to import with  seedtunnel seedbox sftp-config filezilla'
        say 'Connection without a password: key for WinSCP / FileZilla with  seedtunnel seedbox sftp-key new'
    fi
}

# --- SSH keys for SFTP ---------------------------------------------------------------

# Adds the valid public keys of a file (- = standard input), without duplicates
sftp_keys_import() {
    local source=$1 line tmp count=0 file="$SFTP_KEYS_DIR/$SEEDBOX_USER"
    install -d -m 755 "$SFTP_KEYS_DIR"
    if [[ ! -e $file ]]; then install -m 644 /dev/null "$file"; fi
    tmp=$(mktemp)
    if [[ $source == - ]]; then cat >"$tmp"; else cat -- "$source" >"$tmp"; fi
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        [[ -z $line || $line == \#* ]] && continue
        if ! ssh-keygen -l -f - <<<"$line" &>/dev/null; then
            rm -f "$tmp"
            die 'Invalid SSH key: %s…' "${line:0:40}"
        fi
        if ! grep -qxF -- "$line" "$file"; then
            printf '%s\n' "$line" >>"$file"
            count=$((count + 1))
        fi
    done <"$tmp"
    rm -f "$tmp"
    if ((count)); then
        ok '%s SSH key(s) added for %s.' "$count" "$SEEDBOX_USER"
    else
        ok 'Key(s) already saved for %s.' "$SEEDBOX_USER"
    fi
}

sftp_keys_list() {
    local index=0 line
    if ! sftp_has_keys; then
        say 'No SSH key saved for %s.' "$SEEDBOX_USER"
        return 0
    fi
    while IFS= read -r line; do
        [[ -z $line || $line == \#* ]] && continue
        index=$((index + 1))
        printf '  %2d) %s\n' "$index" "$(ssh-keygen -l -f - <<<"$line" 2>/dev/null || printf '%s' "${line:0:50}")"
    done <"$SFTP_KEYS_DIR/$SEEDBOX_USER"
}

sftp_keys_remove() {
    local number=$1 file="$SFTP_KEYS_DIR/$SEEDBOX_USER" index=0 line tmp found=0
    [[ $number =~ ^[0-9]+$ ]] || die 'Give the number of the key (seedtunnel seedbox sftp-key list).'
    tmp=$(mktemp)
    while IFS= read -r line; do
        if [[ -n $line && $line != \#* ]]; then
            index=$((index + 1))
            if ((index == number)); then
                found=1
                continue
            fi
        fi
        printf '%s\n' "$line" >>"$tmp"
    done <"$file"
    if ((!found)); then
        rm -f "$tmp"
        die 'Key number %s not found.' "$number"
    fi
    cat "$tmp" >"$file"
    rm -f "$tmp"
    if [[ $SEEDBOX_SFTP_PASSWORD == no ]] && ! sftp_has_keys; then
        SEEDBOX_SFTP_PASSWORD=yes
        seedbox_save
        warn 'No key left: the SFTP password is allowed again.'
    fi
    seedbox_apply_sftp
    ok 'Key number %s removed.' "$number"
}

# New SSH key for WinSCP / FileZilla: created here, its public part added to
# the allowed keys, its private part sent once as a .ppk file (PuTTY format,
# read by WinSCP and FileZilla) through a one-time link. No copy stays on the
# server. The key has no passphrase: it opens SFTP without a password.
sftp_key_generate() {
    local comment name="seedbox-$SEEDBOX_USER.ppk"
    systemctl is-active --quiet nginx || die 'nginx is stopped:  seedtunnel seedbox restart'
    apt_install putty-tools
    comment="seedtunnel-$SEEDBOX_USER-$(date +%Y%m%d-%H%M%S)"
    # in a subshell: the temporary folder with the private key is deleted
    # whatever happens, even if a step stops the script
    (
        tmp=$(mktemp -d)
        trap 'rm -rf "$tmp"' EXIT
        if ! (umask 077 && ssh-keygen -q -t ed25519 -N '' -C "$comment" -f "$tmp/key" \
            && puttygen "$tmp/key" -O private -o "$tmp/key.ppk" --ppk-param version=2) </dev/null >>"$APP_LOG" 2>&1; then
            die 'Cannot create the SSH key (details in %s).' "$APP_LOG"
        fi
        sftp_keys_import "$tmp/key.pub"
        seedbox_apply_sftp
        share_create "$tmp/key.ppk" "$name" "$(t 'SSH key of %s for WinSCP and FileZilla' "$SEEDBOX_USER")" \
            "$(text share_steps_sftp_key)" "$(t 'This key opens the seedbox without a password: keep it to yourself.')"
    ) || exit 1
    say 'Link unused? Remove the key "%s" (seedtunnel seedbox sftp-key list) and create another one.' "$comment"
}

seedbox_set_sftp_password() {
    case $1 in
        on | yes) SEEDBOX_SFTP_PASSWORD=yes ;;
        off | no)
            sftp_has_keys || die 'Add an SSH key first (seedtunnel seedbox sftp-key add FILE).'
            SEEDBOX_SFTP_PASSWORD=no
            ;;
        *) die 'Usage: seedtunnel seedbox sftp-password on|off' ;;
    esac
    seedbox_save
    seedbox_apply_sftp
    if [[ $SEEDBOX_SFTP_PASSWORD == yes ]]; then
        ok 'SFTP: password allowed.'
    else
        ok 'SFTP: SSH keys only (the password still works for the web interface).'
    fi
}

sftp_keys_menu() {
    local choice answer state
    while true; do
        seedbox_load
        banner
        section 'SSH KEYS FOR SFTP'
        say 'An SSH key is a good replacement for the password in SFTP.'
        say 'Paste the PUBLIC key (.pub file, starts with ssh-ed25519 or ssh-rsa).'
        say 'No key yet? Choice 2 creates one, ready for WinSCP and FileZilla.'
        echo
        sftp_keys_list
        echo
        if [[ $SEEDBOX_SFTP_PASSWORD == yes ]]; then state=$(t 'allowed'); else state=$(t 'refused (keys only)'); fi
        say '  SFTP password: %s' "$state"
        echo
        say '1) Add a key'
        say '2) Create a key for WinSCP / FileZilla (one-time download link)'
        say '3) Remove a key'
        say '4) Allow / refuse the password in SFTP'
        echo
        say 'Q) Back'
        echo
        ask choice 'Your choice' ""
        case ${choice,,} in
            1)
                ask answer 'Public key' ""
                if [[ -n $answer ]]; then
                    sftp_keys_import - <<<"$answer"
                    seedbox_apply_sftp
                fi
                pause
                ;;
            2)
                sftp_key_generate
                pause
                ;;
            3)
                ask answer 'Number of the key to remove' ""
                if [[ -n $answer ]]; then sftp_keys_remove "$answer"; fi
                pause
                ;;
            4)
                if [[ $SEEDBOX_SFTP_PASSWORD == yes ]]; then seedbox_set_sftp_password off; else seedbox_set_sftp_password on; fi
                pause
                ;;
            q) return 0 ;;
        esac
    done
}

# --- Actions ---------------------------------------------------------------------------

seedbox_install_interactive() {
    local ip certificate
    banner
    section 'SEEDBOX INSTALLATION'
    seedbox_check_web_ports
    base_setup
    apt_install bind9-dnsutils
    echo
    printf '%s ' "$(t 'Looking for the public IP address…')"
    ip=$(public_ipv4)
    echo "${ip:-$(t 'not found')}"
    SEEDBOX_DOMAIN=$(seedbox_guess_domain "$ip")
    SEEDBOX_DATA_DIR=$(seedbox_default_data_dir)
    if ((OPT_STAGING)); then SEEDBOX_LETSENCRYPT_SERVER=staging; fi
    echo
    while true; do
        seedbox_ask_user ""
        SEEDBOX_USER=$OPT_NEW_USER
        echo
        seedbox_ask_domain "$ip"
        echo
        while true; do
            ask SEEDBOX_DATA_DIR 'Data folder' "$SEEDBOX_DATA_DIR"
            if seedbox_check_data_dir "$SEEDBOX_DATA_DIR"; then break; fi
        done
        certificate="Let's Encrypt"
        if [[ $SEEDBOX_LETSENCRYPT_SERVER == staging ]]; then certificate=$(t "Let's Encrypt (test server)"); fi
        if [[ $SEEDBOX_LETSENCRYPT == no ]]; then certificate=$(t 'self-signed'); fi
        echo
        say 'Summary:'
        say '  User        : %s' "$SEEDBOX_USER"
        say '  Address     : %s' "https://$SEEDBOX_DOMAIN/"
        say '  Certificate : %s' "$certificate"
        say '  Data        : %s' "$SEEDBOX_DATA_DIR"
        echo
        if confirm 'Start the installation?' y; then break; fi
        echo
    done
    echo
    seedbox_apply
    echo
    seedbox_selftest
    banner
    section 'SEEDBOX INSTALLED — no restart needed'
    seedbox_summary
    SEEDBOX_NEW_PASSWORD=""
    echo
    pause
}

# Installation (or putting back in order) from a --config file
seedbox_install_from_config() {
    local password password_file ip generated=0 first=1 keys current_user=$SEEDBOX_USER
    if seedbox_installed; then first=0; fi
    base_setup
    apt_install bind9-dnsutils

    SEEDBOX_USER=$(config_get SEEDBOX_USER "${SEEDBOX_USER:-lancelot}")
    seedbox_is_valid_user "$SEEDBOX_USER" || die 'Invalid SEEDBOX_USER: "%s"' "$SEEDBOX_USER"
    if ((first)) && id "$SEEDBOX_USER" &>/dev/null; then
        die 'SEEDBOX_USER: the user "%s" already exists on this system.' "$SEEDBOX_USER"
    fi
    if ((!first)) && [[ $current_user != "$SEEDBOX_USER" ]]; then
        die 'Renaming the user goes through:  seedtunnel seedbox password --user %s' "$SEEDBOX_USER"
    fi

    SEEDBOX_DATA_DIR=$(config_get SEEDBOX_DATA_DIR "${SEEDBOX_DATA_DIR:-$(seedbox_default_data_dir)}")
    seedbox_check_data_dir "$SEEDBOX_DATA_DIR" || die 'SEEDBOX_DATA_DIR refused: "%s"' "$SEEDBOX_DATA_DIR"

    SEEDBOX_DOMAIN=$(config_get SEEDBOX_DOMAIN "$SEEDBOX_DOMAIN")
    SEEDBOX_DOMAIN=${SEEDBOX_DOMAIN,,}
    if [[ -z $SEEDBOX_DOMAIN ]]; then
        ip=$(public_ipv4)
        SEEDBOX_DOMAIN=$(seedbox_guess_domain "$ip")
    fi
    seedbox_is_valid_domain "$SEEDBOX_DOMAIN" || die 'Invalid SEEDBOX_DOMAIN: "%s"' "$SEEDBOX_DOMAIN"

    SEEDBOX_LETSENCRYPT=$(config_get SEEDBOX_LETSENCRYPT "$SEEDBOX_LETSENCRYPT")
    [[ $SEEDBOX_LETSENCRYPT =~ ^(auto|yes|no)$ ]] || die 'SEEDBOX_LETSENCRYPT: auto, yes or no'
    SEEDBOX_LETSENCRYPT_SERVER=$(config_get SEEDBOX_LETSENCRYPT_SERVER "$SEEDBOX_LETSENCRYPT_SERVER")
    if ((OPT_STAGING)); then SEEDBOX_LETSENCRYPT_SERVER=staging; fi
    [[ $SEEDBOX_LETSENCRYPT_SERVER =~ ^(production|staging)$ ]] || die 'SEEDBOX_LETSENCRYPT_SERVER: production or staging'
    SEEDBOX_SFTP_PASSWORD=$(config_get SEEDBOX_SFTP_PASSWORD "$SEEDBOX_SFTP_PASSWORD")
    [[ $SEEDBOX_SFTP_PASSWORD =~ ^(yes|no)$ ]] || die 'SEEDBOX_SFTP_PASSWORD: yes or no'

    # Password: file, value, or generated at the first installation.
    # If it is the one already in place, nothing is changed.
    password=$(config_get SEEDBOX_PASSWORD)
    password_file=$(config_get SEEDBOX_PASSWORD_FILE)
    if [[ -n $password_file ]]; then
        [[ -r $password_file ]] || die 'SEEDBOX_PASSWORD_FILE not found: %s' "$password_file"
        secret_file_check "$password_file"
        IFS= read -r password <"$password_file" || true
    fi
    if [[ -n $password ]]; then
        ((${#password} >= 10)) || die 'Seedbox password: at least 10 characters.'
        if seedbox_password_matches "$password"; then SEEDBOX_NEW_PASSWORD=""; else SEEDBOX_NEW_PASSWORD=$password; fi
    elif [[ -z $SEEDBOX_HASH_WEB ]]; then
        SEEDBOX_NEW_PASSWORD=$(generate_password)
        generated=1
    fi

    keys=$(config_get SEEDBOX_SSH_KEYS_FILE)
    if ((first)); then seedbox_check_web_ports; fi
    if [[ -n $keys ]]; then
        [[ -r $keys ]] || die 'SEEDBOX_SSH_KEYS_FILE not found: %s' "$keys"
        sftp_keys_import "$keys"
    fi

    seedbox_apply
    seedbox_selftest
    seedbox_summary
    if ((generated)); then warn 'Password generated automatically: write it down, it will not be shown again.'; fi
    SEEDBOX_NEW_PASSWORD=""
}

# Changes the password (and possibly the name) of the seedbox user
seedbox_set_credentials() {
    local new=$1 old=$SEEDBOX_USER
    if [[ $new != "$old" ]]; then
        seedbox_is_valid_user "$new" || die 'Invalid user name: "%s"' "$new"
        if id "$new" &>/dev/null; then die '"%s" already exists on this system.' "$new"; fi
        # seedbox_apply resumes it once the rule applies to the new name
        seedbox_rename_account "$old" "$new"
        SEEDBOX_USER=$new
        seedbox_save
    fi
    seedbox_apply
}

seedbox_change_credentials() {
    banner
    section 'USER AND PASSWORD'
    seedbox_ask_user "$SEEDBOX_USER"
    echo
    seedbox_set_credentials "$OPT_NEW_USER"
    echo
    seedbox_selftest
    seedbox_summary
    SEEDBOX_NEW_PASSWORD=""
}

# seedtunnel seedbox password [--user NAME]: typed, or read from standard input
seedbox_cli_password() {
    local new=${OPT_NEW_USER:-$SEEDBOX_USER}
    if [[ -t 0 ]]; then
        INTERACTIVE=1
        ask_password SEEDBOX_NEW_PASSWORD
    else
        IFS= read -r SEEDBOX_NEW_PASSWORD || true
        ((${#SEEDBOX_NEW_PASSWORD} >= 10)) || die 'Password: at least 10 characters (read from standard input).'
    fi
    seedbox_set_credentials "$new"
    seedbox_selftest
    SEEDBOX_NEW_PASSWORD=""
    ok 'Credentials updated for %s.' "$SEEDBOX_USER"
}

seedbox_set_domain() {
    local name=${1,,}
    seedbox_is_valid_domain "$name" || die 'Invalid domain name: "%s"' "$name"
    SEEDBOX_DOMAIN=$name
    SEEDBOX_LETSENCRYPT=auto
    if ((OPT_STAGING)); then SEEDBOX_LETSENCRYPT_SERVER=staging; else SEEDBOX_LETSENCRYPT_SERVER=production; fi
    seedbox_apply_https
    seedbox_save
    ok 'Seedbox available at %s (certificate %s)' "https://$SEEDBOX_DOMAIN/" "$(seedbox_certificate_label)"
}

# Menu: change the domain. Nothing is touched before the end: an empty answer
# goes back, and replacing a valid Let's Encrypt certificate is confirmed first
# (Let's Encrypt limits how many certificates a name can get each week).
seedbox_change_domain() {
    local ip server had_letsencrypt=0
    local old_domain=$SEEDBOX_DOMAIN old_letsencrypt=$SEEDBOX_LETSENCRYPT old_server=$SEEDBOX_LETSENCRYPT_SERVER
    banner
    section 'DOMAIN NAME AND HTTPS CERTIFICATE'
    say 'Right now: %s (certificate %s)' "https://$SEEDBOX_DOMAIN/" "$(seedbox_certificate_label)"
    if [[ $SEEDBOX_CERTIFICATE != selfsigned ]] && letsencrypt_usable "$SEEDBOX_LETSENCRYPT_SERVER"; then
        had_letsencrypt=1
        say '  valid until %s, renewed automatically' "$(letsencrypt_expiry_date)"
    fi
    echo
    printf '%s ' "$(t 'Looking for the public IP address…')"
    ip=$(public_ipv4)
    echo "${ip:-$(t 'not found')}"
    echo
    if ! seedbox_ask_domain "$ip" change; then
        say 'Nothing changed.'
        return 0
    fi
    if ((OPT_STAGING)); then server=staging; else server=production; fi
    echo
    if ((had_letsencrypt)); then
        if [[ $SEEDBOX_LETSENCRYPT != no ]] && letsencrypt_usable "$server"; then
            # same name, certificate still valid: nothing to request
            SEEDBOX_LETSENCRYPT=$old_letsencrypt
            ok 'Nothing to change: %s keeps its certificate.' "https://$SEEDBOX_DOMAIN/"
            return 0
        fi
        if [[ $SEEDBOX_LETSENCRYPT == no ]]; then
            warn "The Let's Encrypt certificate will no longer be used: browsers will show a warning."
        else
            warn 'The certificate of %s will be deleted and a new one requested for %s.' "$old_domain" "$SEEDBOX_DOMAIN"
            say "  Let's Encrypt issues at most 5 certificates a week for the same name: avoid going back and forth."
        fi
        if ! confirm 'Continue?' n; then
            SEEDBOX_DOMAIN=$old_domain
            SEEDBOX_LETSENCRYPT=$old_letsencrypt
            SEEDBOX_LETSENCRYPT_SERVER=$old_server
            say 'Nothing changed.'
            return 0
        fi
        echo
    fi
    SEEDBOX_LETSENCRYPT_SERVER=$server
    seedbox_apply_https
    seedbox_save
    echo
    ok 'Seedbox available at %s (certificate %s)' "https://$SEEDBOX_DOMAIN/" "$(seedbox_certificate_label)"
}

fail2ban_bans_print() {
    local jail out current total ips
    for jail in sshd nginx-http-auth recidive; do
        out=$(fail2ban-client status "$jail" 2>/dev/null || true)
        current=$(sed -n 's/.*Currently banned:[[:space:]]*//p' <<<"$out")
        total=$(sed -n 's/.*Total banned:[[:space:]]*//p' <<<"$out")
        ips=$(sed -n 's/.*Banned IP list:[[:space:]]*//p' <<<"$out")
        say '%s%-16s%s banned: %-4s since start: %s' "$C_BOLD" "$jail" "$C_RESET" "${current:-?}" "${total:-?}"
        if [[ -n ${ips// /} ]]; then printf '    %s\n' "$ips"; fi
    done
    echo
    say '  sshd = SSH/SFTP · nginx-http-auth = web interface · recidive = banned 1 week'
}

fail2ban_unban() {
    [[ $1 =~ ^[0-9A-Fa-f.:]+$ ]] || die 'Invalid IP address: "%s"' "$1"
    run "$(t 'Unbanning %s' "$1")" fail2ban-client unban "$1"
}

fail2ban_bans_menu() {
    local ip
    banner
    section 'BANNED IP ADDRESSES (fail2ban)'
    fail2ban_bans_print
    echo
    ask ip 'IP to unban (empty to go back)' ""
    if [[ -n $ip ]]; then
        fail2ban_unban "$ip"
        pause
    fi
}

seedbox_restart() {
    local service
    echo
    for service in nginx fail2ban; do
        run "$(t 'Restarting %s' "$service")" systemctl restart "$service"
    done
    if diskguard_stopped; then
        warn 'Transmission stays stopped: the disk is almost full (%s GB free). It restarts by itself above %s GB.' \
            "$(disk_free_gb "$SEEDBOX_DATA_DIR")" "$DISKGUARD_START_ABOVE_GB"
    else
        run "$(t 'Restarting %s' transmission-daemon)" systemctl restart transmission-daemon
    fi
}

# Deletes the seedbox account, after closing its open SFTP sessions (they
# prevent the deletion). Stops the script if the account is still there.
seedbox_delete_user() {
    local attempt
    [[ -n $SEEDBOX_USER ]] && id "$SEEDBOX_USER" &>/dev/null || return 0
    # the documents stay readable by root once the user is deleted
    if [[ -d $SEEDBOX_DATA_DIR/documents ]]; then chown -R root:root "$SEEDBOX_DATA_DIR/documents"; fi
    for attempt in 1 2 3; do
        pkill -KILL -u "$SEEDBOX_USER" >>"$APP_LOG" 2>&1 || true
        if userdel "$SEEDBOX_USER" >>"$APP_LOG" 2>&1 || ! id "$SEEDBOX_USER" &>/dev/null; then return 0; fi
        sleep 1
    done
    die 'Cannot delete the user %s (details in %s). The seedbox was not removed and its SFTP restrictions stay in place: run the removal again.' \
        "$SEEDBOX_USER" "$APP_LOG"
}

seedbox_uninstall() {
    local delete_data=0
    banner
    section 'REMOVING THE SEEDBOX'
    text seedbox_uninstall_help
    echo
    if ! confirm 'Remove the seedbox?' n; then return 0; fi
    if ((INTERACTIVE)); then
        if confirm "$(t 'ALSO delete all the data in %s?' "$SEEDBOX_DATA_DIR")" n; then delete_data=1; fi
    elif ((OPT_PURGE_DATA)); then
        delete_data=1
    fi
    echo
    # The account goes first: its SFTP restrictions (chroot, no tunnel) stay in
    # force until it is really gone. If it cannot be deleted, nothing else is
    # removed, so that running the removal again finishes the job.
    seedbox_delete_user
    diskguard_remove
    systemctl disable --now transmission-daemon >>"$APP_LOG" 2>&1 || true
    if [[ -f $SSHD_SEEDBOX_CONF ]]; then
        rm -f "$SSHD_SEEDBOX_CONF"
        run 'Reloading SSH' systemctl try-reload-or-restart ssh.service
    fi
    pending_clear ssh
    pending_clear nginx
    if command -v certbot >/dev/null; then
        certbot delete --cert-name "$LETSENCRYPT_CERT_NAME" --non-interactive >>"$APP_LOG" 2>&1 || true
    fi
    # download links in progress
    systemctl stop 'seedtunnel-share-*' >>"$APP_LOG" 2>&1 || true
    rm -rf "$SHARE_DIR"
    rm -f "$NGINX_SITE_LINK" "$NGINX_SITE" "$NGINX_HTPASSWD" "$FAIL2BAN_JAIL" "$FAIL2BAN_MAIN_CONF" "$TRANSMISSION_DROPIN"
    rm -f "$SFTP_KEYS_DIR/$SEEDBOX_USER"
    rmdir "$SFTP_KEYS_DIR" "${TRANSMISSION_DROPIN%/*}" 2>/dev/null || true
    rm -rf "$SEEDBOX_SSL_DIR" "$LETSENCRYPT_WEBROOT"
    systemctl daemon-reload 2>/dev/null || true
    apt_purge transmission-daemon transmission-common nginx nginx-common certbot fail2ban inotify-tools putty-tools
    if ((delete_data)) && [[ -n $SEEDBOX_DATA_DIR && $SEEDBOX_DATA_DIR != / ]]; then
        run 'Deleting the data' rm -rf "${SEEDBOX_DATA_DIR:?}"
    fi
    rm -f "$SEEDBOX_CONF_FILE" "$SEEDBOX_SECRETS_FILE"
    net_hardening_cleanup
    firewall_refresh
    backup_auto_stop_if_unused
    echo
    if ((delete_data)); then
        ok 'Seedbox and data deleted.'
    else
        ok 'Seedbox removed. Your data stays in %s.' "$SEEDBOX_DATA_DIR"
    fi
    pause
}

seedbox_menu() {
    local choice certificate transmission
    while true; do
        seedbox_load
        seedbox_installed || return 0
        if [[ $SEEDBOX_CERTIFICATE == selfsigned ]]; then
            certificate="$C_YELLOW$(t 'self-signed')$C_RESET $(t "(option 2 to try Let's Encrypt again)")"
        else
            certificate=$(seedbox_certificate_label)
        fi
        transmission=$(service_state transmission-daemon)
        if diskguard_stopped; then transmission="$C_RED$(t 'stopped: disk almost full')$C_RESET"; fi
        banner
        section 'SEEDBOX MANAGEMENT'
        say '  Web interface : %s' "https://$SEEDBOX_DOMAIN/"
        say '  Certificate   : %s' "$certificate"
        say '  SFTP          : %s — %s' "$SEEDBOX_USER@$SEEDBOX_DOMAIN" "$(disk_free_text "$SEEDBOX_DATA_DIR")"
        say '  Services      : transmission %s · nginx %s · fail2ban %s' \
            "$transmission" "$(service_state nginx)" "$(service_state fail2ban)"
        echo
        say '1) Change the user or the password'
        say '2) Domain name and HTTPS certificate'
        say '3) SSH keys for SFTP'
        say '4) SFTP connection: settings for WinSCP and FileZilla'
        say '5) Banned IP addresses (fail2ban)'
        echo
        say '6) Restart the services'
        say '7) Remove the seedbox'
        echo
        say 'Q) Back'
        echo
        ask choice 'Your choice' ""
        case ${choice,,} in
            1)
                seedbox_change_credentials
                echo
                pause
                ;;
            2)
                seedbox_change_domain
                echo
                pause
                ;;
            3) sftp_keys_menu ;;
            4)
                seedbox_sftp_config
                pause
                ;;
            5) fail2ban_bans_menu ;;
            6)
                seedbox_restart
                echo
                pause
                ;;
            7) seedbox_uninstall ;;
            q) return 0 ;;
        esac
    done
}

seedbox_main() {
    seedbox_load
    if seedbox_installed; then seedbox_menu; else seedbox_install_interactive; fi
}

# seedtunnel seedbox <command> …
seedbox_cli() {
    local command=${1-}
    if (($#)); then shift; fi
    case $command in
        "")
            require_terminal
            seedbox_main
            ;;
        install)
            if [[ -n $OPT_CONFIG_FILE ]]; then
                config_load "$OPT_CONFIG_FILE"
                seedbox_install_from_config
                if [[ $(config_get FIREWALL) == yes ]]; then firewall_enable; fi
            else
                require_terminal
                if seedbox_installed; then die 'The seedbox is already installed (seedtunnel seedbox to manage it).'; fi
                seedbox_install_interactive
            fi
            ;;
        password)
            seedbox_require_installed
            seedbox_cli_password
            ;;
        domain)
            seedbox_require_installed
            [[ -n ${1-} ]] || die 'Usage: seedtunnel seedbox domain NAME [--staging]'
            seedbox_set_domain "$1"
            ;;
        sftp-config)
            seedbox_require_installed
            case ${1-} in
                "" | filezilla) seedbox_sftp_config "${1-}" ;;
                *) die 'Usage: seedtunnel seedbox sftp-config [filezilla]' ;;
            esac
            ;;
        sftp-key)
            seedbox_require_installed
            case ${1-} in
                add)
                    [[ -n ${2-} ]] || die 'Usage: seedtunnel seedbox sftp-key add FILE.pub   (- for standard input)'
                    sftp_keys_import "$2"
                    seedbox_apply_sftp
                    ;;
                new) sftp_key_generate ;;
                list) sftp_keys_list ;;
                remove) sftp_keys_remove "${2-}" ;;
                *) die 'Usage: seedtunnel seedbox sftp-key add|new|list|remove' ;;
            esac
            ;;
        sftp-password)
            seedbox_require_installed
            seedbox_set_sftp_password "${1-}"
            ;;
        bans)
            seedbox_require_installed
            fail2ban_bans_print
            ;;
        unban)
            seedbox_require_installed
            fail2ban_unban "${1-}"
            ;;
        restart)
            seedbox_require_installed
            seedbox_restart
            ;;
        uninstall)
            seedbox_require_installed
            seedbox_uninstall
            ;;
        *) die 'Unknown command: seedbox %s   (help: seedtunnel help)' "$command" ;;
    esac
}
