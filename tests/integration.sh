#!/usr/bin/env bash
# =============================================================================
#  Integration tests of seedtunnel
#
#  Run by GitHub Actions in a fresh Debian container with systemd (see
#  .github/workflows/ci.yml and tests/Dockerfile). They really install
#  everything, check that every service answers, then remove it all.
#
#  NEVER RUN THIS ON A REAL SERVER: everything would be installed then removed.
#
#  Usage: integration.sh phase1   installation, VPN, seedbox, SFTP, firewall
#         integration.sh phase2   diagnostics, backups, restore, removal
# =============================================================================
set -Euo pipefail

APP=/opt/seedtunnel/seedtunnel.sh
W=/root/seedtunnel-tests
SBU=lancelot
PW1="password-ci-123"
PW2="new-password-ci-456"
DATA=/srv/seedbox
PASS=0
FAIL=0

[[ -f /.dockerenv || ${CI-} == true ]] || {
    echo "Refused: these tests must only run in the test container." >&2
    exit 1
}

step() { printf '\n\033[1m=== %s\033[0m\n' "$*"; }

# On GitHub Actions, every failure also becomes an annotation: it shows in the
# summary of the run, with the end of the output of the command.
annotate() {
    local title body
    title="$(. /etc/os-release && printf '%s' "$VERSION_CODENAME") — $1"
    title=${title//'%'/'%25'}
    title=${title//:/%3A}
    title=${title//,/%2C}
    body=$(tail -n 25 "$W/check.out")
    body=${body//'%'/'%25'}
    body=${body//$'\r'/'%0D'}
    body=${body//$'\n'/'%0A'}
    printf '::error title=%s::%s\n' "$title" "$body"
}

# check "description" command…  → the command must succeed
check() {
    local description=$1
    shift
    if "$@" >"$W/check.out" 2>&1; then
        printf '  \033[32m✔\033[0m %s\n' "$description"
        PASS=$((PASS + 1))
    else
        printf '  \033[31m✘ %s\033[0m\n' "$description"
        tail -n 25 "$W/check.out" | sed 's/^/      /'
        annotate "$description"
        FAIL=$((FAIL + 1))
    fi
}

# check_fails "description" command…  → the command must fail
check_fails() {
    local description=$1
    shift
    if "$@" >"$W/check.out" 2>&1; then
        printf '  \033[31m✘ %s (succeeded but should have failed)\033[0m\n' "$description"
        tail -n 25 "$W/check.out" | sed 's/^/      /'
        annotate "$description (should have failed)"
        FAIL=$((FAIL + 1))
    else
        printf '  \033[32m✔\033[0m %s\n' "$description"
        PASS=$((PASS + 1))
    fi
}

# seedtunnel without a terminal, as in a script, with the reduced PATH you get
# after a « su » without a dash (no /usr/sbin): the script must cope alone
app() { env PATH=/usr/local/bin:/usr/bin:/bin "$APP" "$@" </dev/null; }

# Does the output of a command contain a text? (output captured first: a
# « cmd | grep -q » can fail wrongly with pipefail)
output_has() {
    local text=$1 out
    shift
    out=$("$@" 2>&1) || true
    grep -qF -- "$text" <<<"$out"
}

# HTTP code returned by the seedbox (credentials optional)
http_code() {
    local path=$1
    shift
    curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$@" "https://127.0.0.1$path"
}
http_is() {
    local want=$1
    shift
    [[ $(http_code "$@") == "$want" ]]
}

# SFTP commands with a password or with a key
sftp_password() {
    printf '%s\n' "$2" | sshpass -p "$1" sftp -q -oBatchMode=no -oStrictHostKeyChecking=no \
        -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=no -b - "$SBU@127.0.0.1"
}
sftp_key() {
    printf '%s\n' "$1" | sftp -q -i "$W/key" -oIdentitiesOnly=yes -oBatchMode=yes \
        -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -b - "$SBU@127.0.0.1"
}

# Real WireGuard tunnel: a « client » in a separate network namespace connects
# with the configuration generated for « phone » and pings the server.
tunnel_test() {
    local conf=/etc/seedtunnel/vpn/clients/phone.conf private psk public
    private=$(awk -F' = ' '/^PrivateKey/ { print $2 }' "$conf")
    psk=$(awk -F' = ' '/^PresharedKey/ { print $2 }' "$conf")
    public=$(awk -F' = ' '/^PublicKey/ { print $2 }' "$conf")
    ip netns del st-client 2>/dev/null || true
    ip link del st-veth0 2>/dev/null || true
    ip netns add st-client
    ip link add st-veth0 type veth peer name st-veth1
    ip link set st-veth1 netns st-client
    ip addr add 192.168.250.1/24 dev st-veth0
    ip link set st-veth0 up
    ip -n st-client addr add 192.168.250.2/24 dev st-veth1
    ip -n st-client link set st-veth1 up
    ip -n st-client link set lo up
    ip -n st-client link add wgc type wireguard
    ip netns exec st-client wg set wgc private-key <(printf '%s\n' "$private") \
        peer "$public" preshared-key <(printf '%s\n' "$psk") \
        endpoint 192.168.250.1:51820 allowed-ips 10.8.0.0/24
    ip -n st-client addr add 10.8.0.2/32 dev wgc
    ip -n st-client link set wgc up
    ip -n st-client route add 10.8.0.0/24 dev wgc
    ip netns exec st-client ping -c 3 -W 2 10.8.0.1
}

# The command succeeds without any « starting / applying… » line: nothing was
# touched
nothing_changed() {
    local out
    out=$("$@" 2>&1) || {
        printf '%s\n' "$out"
        return 1
    }
    ! grep -E 'Starting|Restarting|Reloading|Stopping|Applying|Installing|Creating|Enabling|Updating' <<<"$out"
}

# Kernel network hardening applied, including on the existing interface
net_hardened() {
    local interface
    interface=$(ip -4 route show default | awk '{ print $5; exit }')
    sysctl net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route "net.ipv4.conf.$interface.accept_redirects"
    [[ $(sysctl -n net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route \
        "net.ipv4.conf.$interface.accept_redirects" | tr -d '\n') == 000 ]]
}

# « /share/<token>/ » path of the link printed by a command
share_path() {
    local url
    url=$(grep -oE 'https://[^ ]+/share/[0-9a-f]{32}/' <<<"$1" | head -n 1)
    [[ -n $url ]] || return 1
    printf '/%s' "${url#https://*/}"
}

# Gone means 404 (the watcher deletes the link right after the opening)
link_gone() {
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [[ $(http_code "$1") == 404 ]] && return 0
        sleep 1
    done
    echo "still downloadable: $1"
    return 1
}

# One-time link: the page opens (several times), the file downloads once,
# then the link is gone
share_test() {
    local out path page
    out=$(app vpn share phone 2>&1) || {
        printf '%s\n' "$out"
        return 1
    }
    path=$(share_path "$out") || {
        printf 'no link:\n%s\n' "$out"
        return 1
    }
    page=$(curl -sk --max-time 10 "https://127.0.0.1$path")
    [[ $page == *"Download phone.conf"* ]] || {
        printf 'unexpected page:\n%s\n' "$page"
        return 1
    }
    [[ $(http_code "$path") == 200 ]] || {
        echo "opening the page must not use up the link"
        return 1
    }
    curl -skf --max-time 10 -o "$W/shared.conf" "https://127.0.0.1${path}phone.conf" || return 1
    cmp "$W/shared.conf" /etc/seedtunnel/vpn/clients/phone.conf || return 1
    link_gone "${path}phone.conf"
}

# Another form of the address (here with « ?x ») does not get around the
# single use: the first download, whatever its address, uses up the link
share_variant_test() {
    local out path
    out=$(app vpn share phone 2>&1) || return 1
    path=$(share_path "$out") || return 1
    curl -skf --max-time 10 -o "$W/shared2.conf" "https://127.0.0.1${path}phone.conf?x=1" || return 1
    cmp "$W/shared2.conf" /etc/seedtunnel/vpn/clients/phone.conf || return 1
    link_gone "${path}phone.conf"
}

# No partial download: a Range request gets the whole file (200, not 206)
share_no_range_test() {
    local out path code size
    out=$(app vpn share phone 2>&1) || return 1
    path=$(share_path "$out") || return 1
    code=$(curl -sk --max-time 10 -r 0-9 -o "$W/shared3.conf" -w '%{http_code}' "https://127.0.0.1${path}phone.conf")
    size=$(stat -c %s "$W/shared3.conf")
    [[ $code == 200 && $size == "$(stat -c %s /etc/seedtunnel/vpn/clients/phone.conf)" ]] || {
        echo "code $code, $size bytes"
        return 1
    }
}

# SFTP settings: WinSCP address with the fingerprint of the server (computed
# here in another way: SHA-256 of the public key, in base64 « URL »), then
# FileZilla site downloadable
sftp_config_test() {
    local out path xml fingerprint
    fingerprint=$(awk '{ print $2 }' /etc/ssh/ssh_host_ed25519_key.pub | base64 -d \
        | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_')
    out=$(app seedbox sftp-config 2>&1) || {
        printf '%s\n' "$out"
        return 1
    }
    [[ $out == *"sftp://$SBU;fingerprint=ssh-ed25519-$fingerprint@127.0.0.1:22/"* && $out == *"SHA256:"* ]] || {
        printf 'expected: sftp://%s;fingerprint=ssh-ed25519-%s@127.0.0.1:22/\n%s\n' "$SBU" "$fingerprint" "$out"
        return 1
    }
    out=$(app seedbox sftp-config filezilla 2>&1) || {
        printf '%s\n' "$out"
        return 1
    }
    path=$(share_path "$out") || return 1
    xml=$(curl -skf --max-time 10 "https://127.0.0.1${path}seedbox-filezilla.xml") || return 1
    [[ $xml == *"<User>$SBU</User>"* && $xml == *"<Protocol>1</Protocol>"* ]] || {
        printf '%s\n' "$xml"
        return 1
    }
}

# Key created by seedtunnel for WinSCP: downloaded once as a .ppk file, it opens
# SFTP, and no copy of it stays on the server
generated_key_test() {
    local out path file="seedbox-$SBU.ppk"
    out=$(app seedbox sftp-key new 2>&1) || {
        printf '%s\n' "$out"
        return 1
    }
    path=$(share_path "$out") || {
        printf 'no link:\n%s\n' "$out"
        return 1
    }
    curl -skf --max-time 10 -o "$W/generated.ppk" "https://127.0.0.1$path$file" || return 1
    grep -q '^PuTTY-User-Key-File-2: ssh-ed25519' "$W/generated.ppk" || {
        head -n 2 "$W/generated.ppk"
        return 1
    }
    link_gone "$path$file" || return 1
    rm -f "$W/generated"
    puttygen "$W/generated.ppk" -O private-openssh-new -o "$W/generated" </dev/null || return 1
    chmod 600 "$W/generated"
    out=$(printf 'ls\n' | sftp -q -i "$W/generated" -oIdentitiesOnly=yes -oBatchMode=yes \
        -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -b - "$SBU@127.0.0.1" 2>&1)
    [[ $out == *watch* ]] || {
        printf 'SFTP with the created key failed:\n%s\n' "$out"
        return 1
    }
    # nothing left behind in the temporary folders
    if find /tmp /var/tmp \( -name key -o -name key.pub -o -name key.ppk \) -print | grep .; then
        echo "a copy of the key stayed on the server"
        return 1
    fi
}

# An address banned by the sshd jail is banned from every port
fail2ban_all_ports_test() {
    local ip=203.0.113.7 rules lines i
    fail2ban-client set sshd banip "$ip" || return 1
    # the ban action runs in the background
    for i in 1 2 3 4 5 6 7 8 9 10; do
        rules=$(nft list ruleset)
        [[ $rules == *"$ip"* ]] && break
        sleep 1
    done
    fail2ban-client set sshd unbanip "$ip" || true
    lines=$(grep -F '@addr-set-sshd' <<<"$rules" || true)
    [[ $rules == *"$ip"* && -n $lines && $lines != *dport* ]] || {
        printf '%s\n' "$lines"
        return 1
    }
}

# Small .torrent (one piece) for a file, written in bencode by hand
make_torrent() {
    local data=$1 out=$2 name size hash
    name=${data##*/}
    size=$(stat -c %s "$data")
    hash=$(sha1sum "$data" | cut -d' ' -f1)
    {
        printf 'd4:infod6:lengthi%se4:name%s:%s12:piece lengthi262144e6:pieces20:' "$size" "${#name}" "$name"
        # shellcheck disable=SC2059 # the 20 bytes of the hash, in binary
        printf "$(sed 's/../\\x&/g' <<<"$hash")"
        printf 'ee'
    } >"$out"
}

# Number of torrents in Transmission, through nginx and its RPC
torrent_count() {
    local session
    session=$(curl -sk -u "$SBU:$PW2" -D - -o /dev/null https://127.0.0.1/transmission/rpc \
        | awk -F': ' 'tolower($1) == "x-transmission-session-id" { print $2 }' | tr -d '\r')
    curl -sk -u "$SBU:$PW2" -H "X-Transmission-Session-Id: $session" \
        -d '{"method":"torrent-get","arguments":{"fields":["id"]}}' https://127.0.0.1/transmission/rpc \
        | jq '.arguments.torrents | length'
}

# waits up to 60 s for Transmission to show N torrents
wait_torrents() {
    local i count=""
    for i in $(seq 1 30); do
        count=$(torrent_count 2>/dev/null || true)
        [[ $count == "$1" ]] && return 0
        sleep 2
    done
    echo "Transmission shows ${count:-?} torrent(s) instead of $1"
    return 1
}

# A torrent dropped into watch/ appears in Transmission, and its progress is
# saved (resume file) once Transmission has restarted
torrent_test() {
    head -c 1000 /dev/urandom >"$DATA/complete/test-data.bin"
    make_torrent "$DATA/complete/test-data.bin" "$W/test.torrent"
    install -m 664 "$W/test.torrent" "$DATA/watch/test.torrent"
    wait_torrents 1 || return 1
    systemctl restart transmission-daemon
    ls /var/lib/transmission-daemon/.config/transmission-daemon/resume/*.resume
}

# The full disk protection stops Transmission, then starts it again
diskguard_test() {
    env SEEDTUNNEL_DISKGUARD_STOP_BELOW_GB=100000 PATH=/usr/local/bin:/usr/bin:/bin "$APP" diskguard-check </dev/null || return 1
    if systemctl is-active --quiet transmission-daemon; then
        echo "Transmission still running"
        return 1
    fi
    [[ -e /run/seedtunnel-diskguard.stopped ]] || return 1
    output_has 'disk almost full' app doctor || return 1
    env SEEDTUNNEL_DISKGUARD_START_ABOVE_GB=0 PATH=/usr/local/bin:/usr/bin:/bin "$APP" diskguard-check </dev/null || return 1
    systemctl is-active --quiet transmission-daemon && [[ ! -e /run/seedtunnel-diskguard.stopped ]]
}

# « seedtunnel apply » puts back in order a file changed by hand
apply_test() {
    echo '# changed by hand' >>/etc/fail2ban/jail.d/seedtunnel.local
    output_has "Restarting fail2ban" app apply || return 1
    ! grep -q 'changed by hand' /etc/fail2ban/jail.d/seedtunnel.local
}

# Download of the latest backup by a one-time link, then decryption
backup_share_test() {
    local out path name
    rm -f /etc/seedtunnel/backup.downloaded
    out=$(app backup share 2>&1) || {
        printf '%s\n' "$out"
        return 1
    }
    path=$(share_path "$out") || return 1
    name=$(curl -sk --max-time 10 "https://127.0.0.1$path" | grep -oE 'href="seedtunnel-[^"]+\.enc"' | cut -d'"' -f2)
    [[ -n $name ]] || return 1
    curl -skf --max-time 30 -o "$W/downloaded.enc" "https://127.0.0.1$path$name" || return 1
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$W/downloaded.enc" -pass file:"$W/passphrase" \
        | tar -tzf - >"$W/content.txt" || return 1
    grep -qx 'etc/seedtunnel/vpn.conf' "$W/content.txt" || return 1
    grep -q 'transmission-daemon/resume/' "$W/content.txt" || return 1
    link_gone "$path$name" || return 1
    # the download is recorded for the reminder of the diagnostics
    [[ -e /etc/seedtunnel/backup.downloaded ]]
}

# Weekly backup: the timer runs it, and only the last 4 are kept
backup_auto_test() {
    local i
    app backup auto on --passphrase-file "$W/passphrase" || return 1
    systemctl is-enabled --quiet seedtunnel-backup.timer || return 1
    for i in 1 2 3 4 5; do
        systemctl start seedtunnel-backup.service || return 1
        sleep 1
    done
    ls /var/backups/seedtunnel/
    (($(ls /var/backups/seedtunnel/*-auto.tar.gz.enc | wc -l) == 4))
}

summary() {
    printf '\n\033[1m%s passed, %s failed\033[0m\n' "$PASS" "$FAIL"
    ((FAIL == 0))
}

phase1() {
    mkdir -p "$W"
    chmod 700 "$W"
    printf '%s\n' "$PW1" >"$W/password"
    cat >"$W/ci.conf" <<EOF
VPN_PUBLIC_ADDRESS=192.168.250.1
VPN_PORT=51820
VPN_DNS=quad9
VPN_CLIENTS="phone"
SEEDBOX_USER=$SBU
SEEDBOX_PASSWORD_FILE=$W/password
SEEDBOX_DOMAIN=127.0.0.1
SEEDBOX_DATA_DIR=$DATA
SEEDBOX_LETSENCRYPT=no
EOF
    chmod 600 "$W/ci.conf" "$W/password"

    step "General"
    check "seedtunnel version" output_has "seedtunnel 1." app version
    check "seedtunnel help" output_has "vpn add NAME" app help
    check "help: new commands" output_has "backup auto on|off|status" app help
    check "help in French" output_has "Utilisation : seedtunnel" env SEEDTUNNEL_LANG=fr "$APP" help
    check_fails "unknown command refused" app whatever
    check "error message in French" output_has "Commande inconnue" env SEEDTUNNEL_LANG=fr "$APP" whatever

    step "VPN: installation from a configuration file"
    check "installation" app vpn install --config "$W/ci.conf"
    check "WireGuard service running" systemctl is-active --quiet wg-quick@wg0
    check 'client "phone" created' test -s /etc/seedtunnel/vpn/clients/phone.conf
    check "port 60001 forwarded to 10.8.0.2" output_has "dport 60001 dnat to 10.8.0.2" nft list table ip seedtunnel
    check "IPv4 routing on" test "$(sysctl -n net.ipv4.ip_forward)" = 1
    check "kernel network settings hardened" net_hardened
    check "hardening saved for the next boot" test -s /etc/sysctl.d/90-seedtunnel-network.conf
    check '« seedtunnel » command found even after a su without a dash' \
        env PATH=/usr/local/bin:/usr/bin:/bin bash -c 'command -v seedtunnel'

    step "VPN: same run again (idempotence)"
    md5sum /etc/seedtunnel/vpn/server.key /etc/wireguard/wg0.conf >"$W/vpn.md5"
    check "no change when run again" nothing_changed app vpn install --config "$W/ci.conf"
    check "keys and configuration unchanged" md5sum -c --quiet "$W/vpn.md5"

    step "VPN: commands"
    check "vpn add laptop" app vpn add laptop
    check "vpn list shows laptop" output_has "laptop" app vpn list
    check "vpn list in French" output_has "DERNIÈRE CONNEXION" env SEEDTUNNEL_LANG=fr PATH=/usr/local/bin:/usr/bin:/bin "$APP" vpn list
    check_fails "vpn remove without --yes refused" app vpn remove laptop
    check "vpn remove --yes" app vpn remove laptop --yes
    check_fails "laptop is gone" test -e /etc/seedtunnel/vpn/clients/laptop.env
    check "vpn show phone" output_has "[Interface]" app vpn show phone
    check_fails "invalid client name refused" app vpn add "invalid name!"
    check "vpn share without a seedbox: refused, says what to do" output_has "seedtunnel vpn show phone" app vpn share phone

    step "VPN: end-to-end tunnel"
    check "a client connects and reaches 10.8.0.1" tunnel_test

    step "Seedbox: installation from a configuration file"
    check "installation" app seedbox install --config "$W/ci.conf"
    check "Transmission running" systemctl is-active --quiet transmission-daemon
    check "nginx running" systemctl is-active --quiet nginx
    check "fail2ban running" systemctl is-active --quiet fail2ban
    check "full disk protection on" systemctl is-active --quiet seedtunnel-diskguard.timer
    check "web without credentials: 401" http_is 401 /transmission/web/
    check "web with credentials: 200" http_is 200 /transmission/web/ -u "$SBU:$PW1"
    check "Transmission answers behind nginx (409)" http_is 409 /transmission/rpc -u "$SBU:$PW1"
    check "wrong password refused" http_is 401 /transmission/web/ -u "$SBU:wrong"
    check "no password in clear in the configuration" bash -c "! grep -rqF -- '$PW1' /etc/seedtunnel /etc/nginx /etc/transmission-daemon"
    check "Transmission locked down by systemd" output_has "ProtectSystem=strict" systemctl show transmission-daemon -p ProtectSystem

    step "Seedbox: same run again (idempotence)"
    check "no service restarted" nothing_changed app seedbox install --config "$W/ci.conf"

    step "One-time download links"
    check "vpn share: page, single download, then the link is gone" share_test
    check "another form of the address (?x) also uses up the link" share_variant_test
    check "no partial download (Range ignored)" share_no_range_test
    check "seedbox sftp-config: WinSCP address with fingerprint, FileZilla file" sftp_config_test
    check "list of links impossible" http_is 403 /share/
    check "unknown token: 404" http_is 404 /share/0123456789abcdef0123456789abcdef/

    step "SFTP"
    check "connection and folders visible" output_has "watch" sftp_password "$PW1" "ls"
    check "upload of a file into documents/" sftp_password "$PW1" "put /etc/hostname documents/test.txt"
    check "the file arrived" test -f "$DATA/documents/test.txt"
    check_fails "cannot leave the folder (chroot)" sftp_password "$PW1" "ls /etc"
    check_fails "no SSH shell" sshpass -p "$PW1" ssh -oStrictHostKeyChecking=no \
        -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=no "$SBU@127.0.0.1" id

    step "SFTP: SSH keys"
    rm -f "$W/key" "$W/key.pub"
    ssh-keygen -q -t ed25519 -N '' -f "$W/key"
    check "key added" app seedbox sftp-key add "$W/key.pub"
    check "connection with the key" output_has "watch" sftp_key "ls"
    check "SFTP password turned off" app seedbox sftp-password off
    check_fails "connection with the password refused" sftp_password "$PW1" "ls"
    check "web still reachable with the password" http_is 200 /transmission/web/ -u "$SBU:$PW1"
    check "SFTP password allowed again" app seedbox sftp-password on
    check "sftp-key new: .ppk downloaded once, opens SFTP, no copy left" generated_key_test

    step "Change of password"
    check "seedbox password (standard input)" bash -c "printf '%s\n' '$PW2' | '$APP' seedbox password"
    check "new password accepted" http_is 409 /transmission/rpc -u "$SBU:$PW2"
    check "old password refused" http_is 401 /transmission/web/ -u "$SBU:$PW1"
    check "SFTP with the new password" output_has "watch" sftp_password "$PW2" "ls"
    printf '%s\n' "$PW2" >"$W/password"

    step "Torrents"
    check "a .torrent dropped into watch/ is added, its progress saved" torrent_test

    step "fail2ban"
    check "sshd, nginx-http-auth and recidive jails" bash -c \
        "fail2ban-client status | grep -q sshd && fail2ban-client status | grep -q nginx-http-auth && fail2ban-client status | grep -q recidive"
    check "SSH: ban from every port, whatever the port of SSH" fail2ban_all_ports_test

    step "Firewall"
    check_fails "without --yes nor terminal: refused" app firewall enable
    check "enabling" app firewall enable --yes
    nft list table inet seedtunnel_fw >"$W/fw.txt"
    check "SSH allowed" grep -Eq 'tcp dport (\{ )?22( \})? accept' "$W/fw.txt"
    check "VPN allowed" grep -q 'udp dport 51820 accept' "$W/fw.txt"
    check "web allowed" grep -q '80, 443' "$W/fw.txt"
    check "default policy: drop" grep -q 'policy drop' "$W/fw.txt"
    check "loaded again at boot" systemctl is-enabled --quiet seedtunnel-firewall.service
    check "WireGuard tunnel through the firewall" tunnel_test

    step "Full disk protection"
    check "Transmission stopped under the threshold, started again above" diskguard_test

    step "Applying the configuration again (seedtunnel apply)"
    check "puts back in order a change made by hand" apply_test
    check "run again: no change" nothing_changed app apply

    summary
}

phase2() {
    step "Diagnostics"
    check "seedtunnel doctor without problem" app doctor
    # SSH port changed in the configuration without updating the firewall
    printf 'Port 2222\n' >/etc/ssh/sshd_config.d/zz-test-port.conf
    check "doctor reports an SSH port closed by the firewall" output_has "port 2222, closed by the firewall" app doctor
    rm -f /etc/ssh/sshd_config.d/zz-test-port.conf

    step "Backups"
    printf 'a test passphrase\n' >"$W/passphrase"
    chmod 600 "$W/passphrase"
    md5sum /etc/seedtunnel/vpn/server.key /etc/seedtunnel/vpn/clients/phone.conf /etc/seedtunnel/seedbox.secrets >"$W/before.md5"
    check "encrypted backup" app backup --passphrase-file "$W/passphrase"
    check "archive unreadable without the passphrase" bash -c "! tar -tzf /var/backups/seedtunnel/*.enc 2>/dev/null"
    check "doctor: reminder to download a backup" output_has "No backup downloaded" app doctor
    check "backup share: one-time link, then decrypted" backup_share_test
    check "weekly backup: run by the timer, only the last 4 kept" backup_auto_test
    cp "$(ls -1t /var/backups/seedtunnel/*-auto.tar.gz.enc | head -n 1)" "$W/backup.enc"

    step "Removal, then restore"
    check "removing the seedbox" app seedbox uninstall --yes
    check "removing the VPN" app vpn uninstall --yes
    check "turning the firewall off" app firewall disable --yes
    check_fails "nothing left to back up: weekly backup turned off" systemctl is-enabled --quiet seedtunnel-backup.timer
    printf 'wrong passphrase\n' >"$W/wrong"
    check_fails "wrong passphrase refused" app restore "$W/backup.enc" --passphrase-file "$W/wrong" --yes
    check "restore" app restore "$W/backup.enc" --passphrase-file "$W/passphrase" --yes
    check "same VPN keys, clients and hashes" md5sum -c --quiet "$W/before.md5"
    check "WireGuard running" systemctl is-active --quiet wg-quick@wg0
    check "the old client connects without any change" tunnel_test
    check "seedbox password kept" http_is 409 /transmission/rpc -u "$SBU:$PW2"
    check "list of torrents restored" wait_torrents 1
    check "firewall restored" systemctl is-active --quiet seedtunnel-firewall.service
    check "weekly backup restored" systemctl is-enabled --quiet seedtunnel-backup.timer

    step "Removal"
    check "seedbox" app seedbox uninstall --yes
    check "VPN" app vpn uninstall --yes
    check "firewall" app firewall disable --yes
    check_fails "no SFTP rule left" test -e /etc/ssh/sshd_config.d/seedtunnel-seedbox.conf
    check_fails "no user $SBU left" id "$SBU"
    check_fails "no wg0 interface left" ip link show wg0
    check_fails "no full disk protection left" systemctl cat seedtunnel-diskguard.timer
    check_fails "no weekly backup left" systemctl cat seedtunnel-backup.timer
    check "backups kept" bash -c "ls /var/backups/seedtunnel/*.enc"
    check "data kept" test -f "$DATA/documents/test.txt"
    check "SSH still running" systemctl is-active --quiet ssh

    summary
}

case ${1-} in
    phase1) phase1 ;;
    phase2) phase2 ;;
    *)
        echo "Usage: $0 phase1|phase2" >&2
        exit 2
        ;;
esac
