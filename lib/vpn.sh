#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — VPN module (WireGuard)
#
#  Network 10.8.0.0/24: the server is 10.8.0.1, client number N gets
#  10.8.0.(N+1) and the public port 60000+N, forwarded to it in TCP and UDP
#  (handy for a torrent client at home behind the VPN).
#
#  Everything is generated again from /etc/seedtunnel/vpn/ (« vpn_apply »):
#    server.key / server.pub      keys of the server
#    clients/<name>.env           number and keys of a client
#    clients/<name>.conf          file to import into the WireGuard app
#    nat.nft                      NAT rules, loaded when wg0 starts
#  vpn_apply only changes what needs to change: it can safely run again.
# =============================================================================

VPN_INTERFACE="wg0"
VPN_SUBNET="10.8.0"
# 10.8.0.2 → 10.8.0.254
VPN_MAX_CLIENTS=253
# client number N gets the port 60000+N
VPN_FORWARDED_PORT_BASE=60000
VPN_STATE_DIR="$APP_STATE_DIR/vpn"
VPN_CONF_FILE="$APP_STATE_DIR/vpn.conf"
VPN_CLIENTS_DIR="$VPN_STATE_DIR/clients"
VPN_NAT_RULES="$VPN_STATE_DIR/nat.nft"
VPN_SYSCTL_FILE="/etc/sysctl.d/90-seedtunnel-vpn.conf"
WIREGUARD_CONF="/etc/wireguard/$VPN_INTERFACE.conf"

vpn_load() {
    VPN_PORT=51820
    VPN_PUBLIC_ADDRESS=""
    VPN_DNS="9.9.9.9, 149.112.112.112"
    VPN_OUT_INTERFACE=""
    state_read "$VPN_CONF_FILE"
}

vpn_save() { state_write "$VPN_CONF_FILE" VPN_PORT VPN_PUBLIC_ADDRESS VPN_DNS VPN_OUT_INTERFACE; }

vpn_installed() { [[ -f $VPN_CONF_FILE ]]; }

vpn_require_installed() {
    vpn_installed || die 'The VPN is not installed:  seedtunnel vpn install'
}

vpn_client_names() {
    local file
    for file in "$VPN_CLIENTS_DIR"/*.env; do
        [[ -e $file ]] || continue
        file=${file##*/}
        printf '%s\n' "${file%.env}"
    done
}

vpn_count_clients() {
    local count=0 file
    for file in "$VPN_CLIENTS_DIR"/*.env; do
        if [[ -e $file ]]; then count=$((count + 1)); fi
    done
    printf '%s' "$count"
}

# Connected clients: last handshake less than 3 minutes ago (WireGuard
# renews it every 2 minutes while the tunnel is in use)
vpn_connected_count() {
    local now count=0 _key handshake
    if systemctl is-active --quiet "wg-quick@$VPN_INTERFACE"; then
        now=$(date +%s)
        while read -r _key handshake; do
            if [[ $handshake =~ ^[0-9]+$ ]] && ((handshake > 0 && now - handshake < 180)); then
                count=$((count + 1))
            fi
        done < <(wg show "$VPN_INTERFACE" latest-handshakes 2>/dev/null || true)
    fi
    printf '%s' "$count"
}

# 15 characters at most: on Linux the file name becomes the interface name
vpn_is_valid_client_name() { [[ $1 =~ ^[A-Za-z0-9_-]{1,15}$ ]]; }

vpn_require_client() {
    vpn_is_valid_client_name "$1" || die 'Invalid client name: "%s".' "$1"
    [[ -e $VPN_CLIENTS_DIR/$1.env ]] || die 'Client "%s" not found (seedtunnel vpn list).' "$1"
}

# quad9 | cloudflare | IP addresses separated by commas
vpn_dns_value() {
    case ${1,,} in
        quad9 | "") printf '9.9.9.9, 149.112.112.112' ;;
        cloudflare) printf '1.1.1.1, 1.0.0.1' ;;
        *) printf '%s' "$1" ;;
    esac
}

# DNS servers of the clients: IPv4 or IPv6 addresses separated by commas
vpn_is_valid_dns() {
    local entry count=0
    local -a entries
    IFS=, read -r -a entries <<<"$1"
    for entry in "${entries[@]}"; do
        entry=${entry// /}
        [[ -n $entry ]] || return 1
        if ! is_ipv4 "$entry" && ! [[ $entry == *:*:* && $entry =~ ^[0-9A-Fa-f:]{2,39}$ ]]; then return 1; fi
        count=$((count + 1))
    done
    ((count > 0))
}

vpn_is_valid_address() { [[ $1 =~ ^[A-Za-z0-9.:-]+$ ]]; }

# Is the UDP port free (or already ours)?
vpn_port_is_free() {
    local current
    current=$(wg show "$VPN_INTERFACE" listen-port 2>/dev/null || true)
    [[ $1 == "$current" ]] && return 0
    ! port_in_use udp "$1"
}

# Can the kernel create a WireGuard interface? (fails in some OpenVZ/LXC
# containers, like the TUN/TAP module used to)
vpn_check_kernel() {
    if ip link show "$VPN_INTERFACE" &>/dev/null; then return 0; fi
    if ! ip link add dev st-wgtest type wireguard 2>/dev/null; then
        die 'The kernel cannot create a WireGuard interface.\n  On a container VPS (OpenVZ, LXC), ask the provider to enable WireGuard,\n  or choose a KVM plan.'
    fi
    ip link del dev st-wgtest
}

# --- File generation (on standard output) -----------------------------------------

vpn_generate_client_conf() {
    local name=$1 CLIENT_NUMBER CLIENT_PUBLIC_KEY CLIENT_PRESHARED_KEY CLIENT_PRIVATE_KEY address
    # shellcheck source=/dev/null
    . "$VPN_CLIENTS_DIR/$name.env"
    address=$VPN_PUBLIC_ADDRESS
    # IPv6 address → between brackets
    if [[ $address == *:* ]]; then address="[$address]"; fi
    cat <<EOF
# seedtunnel — client "$name" — IP $VPN_SUBNET.$((CLIENT_NUMBER + 1)) — open port $((VPN_FORWARDED_PORT_BASE + CLIENT_NUMBER))
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $VPN_SUBNET.$((CLIENT_NUMBER + 1))/32
DNS = $VPN_DNS

[Peer]
PublicKey = $(<"$VPN_STATE_DIR/server.pub")
PresharedKey = $CLIENT_PRESHARED_KEY
Endpoint = $address:$VPN_PORT
# ::/0 also sends IPv6 into the tunnel (where it is blocked): no IPv6 leak
AllowedIPs = 0.0.0.0/0, ::/0
# Keeps the tunnel open behind a home router: needed for the open port
PersistentKeepalive = 25
EOF
}

vpn_generate_server_conf() {
    local file name CLIENT_NUMBER CLIENT_PUBLIC_KEY CLIENT_PRESHARED_KEY CLIENT_PRIVATE_KEY
    cat <<EOF
# Written by seedtunnel — use the menu rather than editing this file.
[Interface]
Address = $VPN_SUBNET.1/24
ListenPort = $VPN_PORT
PrivateKey = $(<"$VPN_STATE_DIR/server.key")
PostUp = nft -f $VPN_NAT_RULES
PostDown = nft delete table ip seedtunnel
EOF
    for file in "$VPN_CLIENTS_DIR"/*.env; do
        [[ -e $file ]] || continue
        name=${file##*/}
        name=${name%.env}
        # shellcheck source=/dev/null
        . "$file"
        cat <<EOF || return 1

# client: $name
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
PresharedKey = $CLIENT_PRESHARED_KEY
AllowedIPs = $VPN_SUBNET.$((CLIENT_NUMBER + 1))/32
EOF
    done
}

# « table / delete / table » replaces the table in one go, whether it exists or
# not, without touching the other rules of the system.
vpn_generate_nat_rules() {
    local file name CLIENT_NUMBER CLIENT_PUBLIC_KEY CLIENT_PRESHARED_KEY CLIENT_PRIVATE_KEY
    cat <<EOF
#!/usr/sbin/nft -f
# Written by seedtunnel — NAT of the VPN, loaded when $VPN_INTERFACE starts.
table ip seedtunnel
delete table ip seedtunnel
table ip seedtunnel {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
EOF
    for file in "$VPN_CLIENTS_DIR"/*.env; do
        [[ -e $file ]] || continue
        name=${file##*/}
        name=${name%.env}
        # shellcheck source=/dev/null
        . "$file"
        printf '        # client "%s"\n' "$name"
        printf '        iifname "%s" meta l4proto { tcp, udp } th dport %s dnat to %s\n' \
            "$VPN_OUT_INTERFACE" "$((VPN_FORWARDED_PORT_BASE + CLIENT_NUMBER))" "$VPN_SUBNET.$((CLIENT_NUMBER + 1))" || return 1
    done
    cat <<EOF
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # clients go out to the Internet with the IP of the server
        ip saddr $VPN_SUBNET.0/24 oifname "$VPN_OUT_INTERFACE" masquerade
    }
}
EOF
}

# --- Applying ----------------------------------------------------------------------

# Applies the configuration live, without disconnecting the clients. Each step
# is checked: if WireGuard refuses the configuration, « run » shows « failed »
# with the error, instead of « ok ».
vpn_sync() {
    local stripped
    stripped=$(wg-quick strip "$VPN_INTERFACE") || return 1
    wg syncconf "$VPN_INTERFACE" <(printf '%s\n' "$stripped") || return 1
    nft -f "$VPN_NAT_RULES" || return 1
}

# Puts the server in the state described in /etc/seedtunnel (idempotent)
vpn_apply() {
    local interface name changed=0
    apt_install wireguard-tools qrencode
    install -d -m 700 "$VPN_STATE_DIR" "$VPN_CLIENTS_DIR" /etc/wireguard
    if [[ ! -s $VPN_STATE_DIR/server.key ]]; then
        (umask 077 && wg genkey >"$VPN_STATE_DIR/server.key")
    fi
    write_if_changed "$VPN_STATE_DIR/server.pub" 600 root:root wg pubkey <"$VPN_STATE_DIR/server.key" || true

    # the network interface may change (restore on another server)
    interface=$(default_interface)
    if [[ -n $interface ]]; then VPN_OUT_INTERFACE=$interface; fi
    [[ -n $VPN_OUT_INTERFACE ]] || die 'Main network interface not found (no default route?).'
    vpn_save
    # the port of the VPN is opened in the firewall before starting
    firewall_refresh

    # the server must forward the packets of the clients to the Internet
    if write_if_changed "$VPN_SYSCTL_FILE" 644 root:root \
        printf '%s\n' '# Written by seedtunnel: routing for the VPN clients' 'net.ipv4.ip_forward = 1' \
        || [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) != 1 ]]; then
        run 'Enabling IPv4 routing' sysctl -q -p "$VPN_SYSCTL_FILE"
    fi
    net_hardening_apply

    while IFS= read -r name; do
        write_if_changed "$VPN_CLIENTS_DIR/$name.conf" 600 root:root vpn_generate_client_conf "$name" || true
    done < <(vpn_client_names)
    if write_if_changed "$WIREGUARD_CONF" 600 root:root vpn_generate_server_conf; then changed=1; fi
    if write_if_changed "$VPN_NAT_RULES" 600 root:root vpn_generate_nat_rules; then changed=1; fi
    vpn_reconcile "$changed"
}

# vpn_reconcile CHANGED — puts the running VPN in line with its files. Even when
# no file changed, the clients and the NAT are synchronized again (quietly): a
# change whose application failed earlier (a revoked client, for example) is
# applied at the next run instead of being forgotten. It cuts no connection.
vpn_reconcile() {
    local changed=$1 current_port
    if ! systemctl is-active --quiet "wg-quick@$VPN_INTERFACE"; then
        run 'Starting the VPN' systemctl enable --now "wg-quick@$VPN_INTERFACE"
        return 0
    fi
    current_port=$(wg show "$VPN_INTERFACE" listen-port 2>/dev/null || true)
    if [[ $current_port != "$VPN_PORT" ]]; then
        run 'Restarting the VPN (new port)' systemctl restart "wg-quick@$VPN_INTERFACE"
    elif ((changed)); then
        run 'Applying the configuration' vpn_sync
    elif ! vpn_sync >>"$APP_LOG" 2>&1; then
        die 'The running VPN does not match its configuration and cannot be updated (details in %s):  seedtunnel vpn restart' "$APP_LOG"
    fi
    systemctl enable --quiet "wg-quick@$VPN_INTERFACE" 2>/dev/null || true
}

vpn_next_client_number() {
    local number file used=" "
    for file in "$VPN_CLIENTS_DIR"/*.env; do
        [[ -e $file ]] || continue
        used+="$(
            # shellcheck source=/dev/null
            . "$file"
            printf '%s' "$CLIENT_NUMBER"
        ) "
    done
    for ((number = 1; number <= VPN_MAX_CLIENTS; number++)); do
        if [[ $used != *" $number "* ]]; then
            printf '%s' "$number"
            return 0
        fi
    done
    return 1
}

# --- Clients --------------------------------------------------------------------------

vpn_add_client() {
    local name=$1 CLIENT_NUMBER CLIENT_PUBLIC_KEY CLIENT_PRESHARED_KEY CLIENT_PRIVATE_KEY
    vpn_is_valid_client_name "$name" || die 'Invalid client name: "%s" (letters, digits, - and _, 15 characters at most).' "$name"
    [[ ! -e $VPN_CLIENTS_DIR/$name.env ]] || die 'Client "%s" already exists.' "$name"
    if ! CLIENT_NUMBER=$(vpn_next_client_number); then die 'Maximum number of clients reached (%s).' "$VPN_MAX_CLIENTS"; fi
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(printf '%s' "$CLIENT_PRIVATE_KEY" | wg pubkey)
    CLIENT_PRESHARED_KEY=$(wg genpsk)
    (umask 077 && state_write "$VPN_CLIENTS_DIR/$name.env" CLIENT_NUMBER CLIENT_PUBLIC_KEY CLIENT_PRESHARED_KEY CLIENT_PRIVATE_KEY)
    vpn_apply
    ok 'Client "%s" created: IP %s, open port %s, file %s' "$name" "$VPN_SUBNET.$((CLIENT_NUMBER + 1))" \
        "$((VPN_FORWARDED_PORT_BASE + CLIENT_NUMBER))" "$VPN_CLIENTS_DIR/$name.conf"
}

vpn_remove_client() {
    local name=$1
    vpn_require_client "$name"
    rm -f "$VPN_CLIENTS_DIR/$name.env" "$VPN_CLIENTS_DIR/$name.conf"
    vpn_apply
    ok 'Client "%s" revoked: its key can no longer connect.' "$name"
}

vpn_show_client() {
    local name=$1 CLIENT_NUMBER CLIENT_PUBLIC_KEY CLIENT_PRESHARED_KEY CLIENT_PRIVATE_KEY port
    vpn_require_client "$name"
    # shellcheck source=/dev/null
    . "$VPN_CLIENTS_DIR/$name.env"
    port=$((VPN_FORWARDED_PORT_BASE + CLIENT_NUMBER))
    banner
    section 'VPN CLIENT "%s"' "$name"
    qrencode -t ansiutf8 <"$VPN_CLIENTS_DIR/$name.conf"
    echo
    text vpn_client_help
    echo
    if ((INTERACTIVE)); then
        if confirm 'Show the content of the file (to copy and paste)?' n; then
            echo
            cat "$VPN_CLIENTS_DIR/$name.conf"
            echo
        fi
    else
        cat "$VPN_CLIENTS_DIR/$name.conf"
    fi
}

# One-time download link for the file of a client (see share.sh)
vpn_share_client() {
    local name=$1
    vpn_require_client "$name"
    share_require "$(t 'Without a seedbox:  seedtunnel vpn show %s  (QR code, or content to copy and paste).' "$name")"
    share_create "$VPN_CLIENTS_DIR/$name.conf" "$name.conf" "$(t 'VPN configuration "%s"' "$name")" \
        "$(text share_steps_vpn)" "$(t 'This file holds the secret key of "%s": delete it once imported.' "$name")"
}

# vpn_pick_client VARIABLE "Question (already translated)" — numbered list, pick
# by number or by name
vpn_pick_client() {
    local _pick_var=$1 _pick_question=$2 _pick_answer _pick_index=0 _pick_name
    local -a _pick_names
    mapfile -t _pick_names < <(vpn_client_names)
    if ((${#_pick_names[@]} == 0)); then
        warn 'No client yet.'
        return 1
    fi
    for _pick_name in "${_pick_names[@]}"; do
        _pick_index=$((_pick_index + 1))
        printf '  %2d) %s\n' "$_pick_index" "$_pick_name"
    done
    echo
    ask _pick_answer "$(t '%s (number or name, empty to cancel)' "$_pick_question")" ""
    [[ -n $_pick_answer ]] || return 1
    if [[ ! $_pick_answer =~ ^[A-Za-z0-9_-]{1,15}$ ]]; then
        warn 'Invalid name.'
        return 1
    fi
    if [[ $_pick_answer =~ ^[0-9]+$ ]] && ((_pick_answer >= 1 && _pick_answer <= ${#_pick_names[@]})); then
        _pick_answer=${_pick_names[_pick_answer - 1]}
    fi
    if [[ ! -e $VPN_CLIENTS_DIR/$_pick_answer.env ]]; then
        warn 'Client "%s" not found.' "$_pick_answer"
        return 1
    fi
    printf -v "$_pick_var" '%s' "$_pick_answer"
}

vpn_ask_client_name() {
    local _client_var=$1 _client_default=${2-} _client_name
    while true; do
        ask _client_name 'Client name (e.g. phone, laptop)' "$_client_default"
        if ! vpn_is_valid_client_name "$_client_name"; then
            warn 'Letters, digits, - and _ only, 15 characters at most.'
        elif [[ -e $VPN_CLIENTS_DIR/$_client_name.env ]]; then
            warn 'Client "%s" already exists.' "$_client_name"
        else
            break
        fi
    done
    printf -v "$_client_var" '%s' "$_client_name"
}

# Table of the clients with the state of their connection
vpn_status_table() {
    local -A handshakes=() received=() sent=()
    local key _psk _endpoint _ips handshake rx tx _keepalive file name now ago
    local CLIENT_NUMBER CLIENT_PUBLIC_KEY CLIENT_PRESHARED_KEY CLIENT_PRIVATE_KEY
    if systemctl is-active --quiet "wg-quick@$VPN_INTERFACE"; then
        while IFS=$'\t' read -r key _psk _endpoint _ips handshake rx tx _keepalive; do
            handshakes[$key]=$handshake
            received[$key]=$rx
            sent[$key]=$tx
        done < <(wg show "$VPN_INTERFACE" dump | tail -n +2)
    fi
    now=$(date +%s)
    printf '%s%-16s %-12s %-7s %-20s %s%s\n' "$C_BOLD" "$(t 'CLIENT')" "IP" "PORT" \
        "$(t 'RECEIVED / SENT')" "$(t 'LAST CONNECTION')" "$C_RESET"
    for file in "$VPN_CLIENTS_DIR"/*.env; do
        [[ -e $file ]] || continue
        name=${file##*/}
        name=${name%.env}
        # shellcheck source=/dev/null
        . "$file"
        handshake=${handshakes[$CLIENT_PUBLIC_KEY]:-0}
        if ((handshake == 0)); then
            ago="$C_DIM$(t 'never')$C_RESET"
        else
            ago=$((now - handshake))
            if ((ago < 180)); then
                ago="$C_GREEN$(t 'connected')$C_RESET $(t '(%s s)' "$ago")"
            elif ((ago < 3600)); then
                ago=$(t '%s min ago' "$((ago / 60))")
            elif ((ago < 86400)); then
                ago=$(t '%s h ago' "$((ago / 3600))")
            else
                ago=$(t '%s days ago' "$((ago / 86400))")
            fi
        fi
        printf '%-16s %-12s %-7s %-20s %s\n' "$name" "$VPN_SUBNET.$((CLIENT_NUMBER + 1))" \
            "$((VPN_FORWARDED_PORT_BASE + CLIENT_NUMBER))" \
            "$(human_size "${received[$CLIENT_PUBLIC_KEY]:-0}") / $(human_size "${sent[$CLIENT_PUBLIC_KEY]:-0}")" "$ago"
    done
}

# --- Settings, installation, removal ---------------------------------------------

vpn_ask_dns() {
    local choice
    echo
    say 'DNS servers used by the VPN clients:'
    say '  1) Quad9      — blocks malicious domains (Swiss foundation)'
    say '  2) Cloudflare — usually the fastest'
    say '  3) Other      — type the addresses'
    while true; do
        ask choice 'Your choice [1-3]' "1"
        case $choice in
            1)
                VPN_DNS=$(vpn_dns_value quad9)
                return 0
                ;;
            2)
                VPN_DNS=$(vpn_dns_value cloudflare)
                return 0
                ;;
            3)
                ask VPN_DNS 'DNS IP address(es), separated by commas' "$VPN_DNS"
                if vpn_is_valid_dns "$VPN_DNS"; then return 0; fi
                warn 'Expected format: 9.9.9.9, 149.112.112.112'
                ;;
        esac
    done
}

# Questions shared by the installation and the change of settings
vpn_ask_settings() {
    while true; do
        ask VPN_PUBLIC_ADDRESS 'Public address of the server (IP or domain name)' "$VPN_PUBLIC_ADDRESS"
        if ! vpn_is_valid_address "$VPN_PUBLIC_ADDRESS"; then
            warn 'Invalid address.'
            continue
        fi
        ask VPN_PORT 'UDP port of the VPN' "$VPN_PORT"
        if ! is_valid_port "$VPN_PORT"; then
            warn 'Invalid port (1 to 65535).'
            continue
        fi
        if ! vpn_port_is_free "$VPN_PORT"; then
            warn 'UDP port %s is already used on this server.' "$VPN_PORT"
            continue
        fi
        vpn_ask_dns
        echo
        say 'Summary:'
        say '  Address : %s' "$VPN_PUBLIC_ADDRESS"
        say '  Port    : %s/udp' "$VPN_PORT"
        say '  DNS     : %s' "$VPN_DNS"
        say '  Out     : interface %s' "${VPN_OUT_INTERFACE:-?}"
        echo
        if confirm 'Is that right?' y; then return 0; fi
    done
}

vpn_install_interactive() {
    local first
    banner
    section 'WIREGUARD VPN INSTALLATION'
    vpn_check_kernel
    base_setup
    echo
    printf '%s ' "$(t 'Looking for the public IP address…')"
    VPN_PUBLIC_ADDRESS=$(public_ipv4)
    echo "${VPN_PUBLIC_ADDRESS:-$(t 'not found')}"
    # if the seedbox has a domain name, it makes a better address
    if seedbox_installed && [[ -n $SEEDBOX_DOMAIN ]] && ! is_ipv4 "$SEEDBOX_DOMAIN"; then
        VPN_PUBLIC_ADDRESS=$SEEDBOX_DOMAIN
    fi
    VPN_OUT_INTERFACE=$(default_interface)
    echo
    vpn_ask_settings
    echo
    vpn_ask_client_name first "client1"
    echo
    vpn_apply
    vpn_add_client "$first"
    echo
    ok 'VPN installed — no restart needed.'
    pause
    vpn_show_client "$first"
    pause
}

# Installation (or putting back in order) from a --config file. Run again with
# the same file, it changes nothing: existing clients are kept.
vpn_install_from_config() {
    local name port dns
    local -a names=()
    vpn_check_kernel
    base_setup
    VPN_PUBLIC_ADDRESS=$(config_get VPN_PUBLIC_ADDRESS "$VPN_PUBLIC_ADDRESS")
    if [[ -z $VPN_PUBLIC_ADDRESS ]]; then VPN_PUBLIC_ADDRESS=$(public_ipv4); fi
    vpn_is_valid_address "$VPN_PUBLIC_ADDRESS" || die 'Invalid VPN_PUBLIC_ADDRESS: "%s"' "$VPN_PUBLIC_ADDRESS"
    port=$(config_get VPN_PORT "$VPN_PORT")
    is_valid_port "$port" || die 'Invalid VPN_PORT: "%s"' "$port"
    vpn_port_is_free "$port" || die 'UDP port %s is already used on this server.' "$port"
    VPN_PORT=$port
    dns=$(vpn_dns_value "$(config_get VPN_DNS "$VPN_DNS")")
    vpn_is_valid_dns "$dns" || die 'Invalid VPN_DNS: "%s"' "$dns"
    VPN_DNS=$dns
    IFS=', ' read -r -a names <<<"$(config_get VPN_CLIENTS)"
    for name in "${names[@]}"; do
        vpn_is_valid_client_name "$name" || die 'VPN_CLIENTS: invalid name "%s"' "$name"
    done

    vpn_apply
    for name in "${names[@]}"; do
        if [[ ! -e $VPN_CLIENTS_DIR/$name.env ]]; then vpn_add_client "$name"; fi
    done
    ok 'VPN ready: %s, %s client(s) in %s' "$VPN_PUBLIC_ADDRESS:$VPN_PORT/udp" "$(vpn_count_clients)" "$VPN_CLIENTS_DIR/"
}

vpn_change_settings() {
    banner
    section 'VPN SETTINGS'
    warn 'After a change, every client will have to import its configuration again.'
    echo
    vpn_ask_settings
    vpn_apply
    ok 'Settings saved. Show the clients again to get their new QR codes.'
}

vpn_uninstall() {
    banner
    section 'REMOVING THE VPN'
    warn 'All the clients (%s) will be deleted for good.' "$(vpn_count_clients)"
    if ! confirm 'Remove the VPN?' n; then return 0; fi
    echo
    systemctl disable --now "wg-quick@$VPN_INTERFACE" >>"$APP_LOG" 2>&1 || true
    nft delete table ip seedtunnel >>"$APP_LOG" 2>&1 || true
    rm -rf "${VPN_STATE_DIR:?}" "$VPN_CONF_FILE" "$WIREGUARD_CONF" "$VPN_SYSCTL_FILE"
    net_hardening_cleanup
    apt_purge wireguard-tools qrencode
    firewall_refresh
    backup_auto_stop_if_unused
    ok 'VPN removed (IPv4 routing will be turned off at the next restart).'
    pause
}

vpn_menu() {
    local choice name
    while true; do
        vpn_load
        vpn_installed || return 0
        banner
        section 'VPN MANAGEMENT'
        say '  State   : %s' "$(service_state "wg-quick@$VPN_INTERFACE")"
        say '  Address : %s (UDP)' "$VPN_PUBLIC_ADDRESS:$VPN_PORT"
        say '  Clients : %s (%s connected right now)' "$(vpn_count_clients)" "$(vpn_connected_count)"
        echo
        say '1) Add a client'
        say '2) Show a client (QR code, file)'
        say '3) Download link for a client (one time only)'
        say '4) Revoke a client'
        say '5) Clients and connections'
        echo
        say '6) Change the settings (address, port, DNS)'
        say '7) Restart the VPN'
        say '8) Remove the VPN'
        echo
        say 'Q) Back'
        echo
        ask choice 'Your choice' ""
        case ${choice,,} in
            1)
                banner
                section 'ADD A CLIENT'
                if (($(vpn_count_clients) >= VPN_MAX_CLIENTS)); then
                    warn 'Maximum number of clients reached (%s).' "$VPN_MAX_CLIENTS"
                else
                    vpn_ask_client_name name ""
                    vpn_add_client "$name"
                    pause
                    vpn_show_client "$name"
                fi
                pause
                ;;
            2)
                banner
                section 'SHOW A CLIENT'
                if vpn_pick_client name "$(t 'Client to show')"; then vpn_show_client "$name"; fi
                pause
                ;;
            3)
                banner
                section 'DOWNLOAD LINK'
                if ! seedbox_installed; then
                    warn 'Links go through the HTTPS site of the seedbox, which is not installed:'
                    warn 'use "Show a client" instead (QR code, or content to copy and paste).'
                elif vpn_pick_client name "$(t 'Client to send')"; then
                    vpn_share_client "$name"
                fi
                pause
                ;;
            4)
                banner
                section 'REVOKE A CLIENT'
                if vpn_pick_client name "$(t 'Client to revoke')" \
                    && confirm "$(t 'Revoke "%s" for good?' "$name")" n; then
                    vpn_remove_client "$name"
                fi
                pause
                ;;
            5)
                banner
                section 'CLIENTS AND CONNECTIONS'
                vpn_status_table
                echo
                pause
                ;;
            6)
                vpn_change_settings
                pause
                ;;
            7)
                echo
                run 'Restarting the VPN' systemctl restart "wg-quick@$VPN_INTERFACE"
                pause
                ;;
            8) vpn_uninstall ;;
            q) return 0 ;;
        esac
    done
}

vpn_main() {
    vpn_load
    if vpn_installed && (($(vpn_count_clients) == 0)) && ! systemctl is-active --quiet "wg-quick@$VPN_INTERFACE"; then
        # settings saved but neither client nor service: interrupted installation
        warn 'The previous installation of the VPN was interrupted: starting it again.'
        pause
        vpn_install_interactive
    elif vpn_installed; then
        vpn_menu
    else
        vpn_install_interactive
    fi
}

# seedtunnel vpn <command> …
vpn_cli() {
    local command=${1-}
    if (($#)); then shift; fi
    case $command in
        "")
            require_terminal
            vpn_main
            ;;
        install)
            if [[ -n $OPT_CONFIG_FILE ]]; then
                config_load "$OPT_CONFIG_FILE"
                vpn_install_from_config
                if [[ $(config_get FIREWALL) == yes ]]; then firewall_enable; fi
            else
                require_terminal
                if vpn_installed; then die 'The VPN is already installed (seedtunnel vpn to manage it).'; fi
                vpn_install_interactive
            fi
            ;;
        add)
            vpn_require_installed
            [[ -n ${1-} ]] || die 'Usage: seedtunnel vpn add NAME [--qr]'
            vpn_add_client "$1"
            if ((OPT_QR)); then vpn_show_client "$1"; fi
            ;;
        remove)
            vpn_require_installed
            [[ -n ${1-} ]] || die 'Usage: seedtunnel vpn remove NAME --yes'
            vpn_require_client "$1"
            if confirm "$(t 'Revoke "%s" for good?' "$1")" n; then vpn_remove_client "$1"; fi
            ;;
        list)
            vpn_require_installed
            vpn_status_table
            ;;
        show)
            vpn_require_installed
            [[ -n ${1-} ]] || die 'Usage: seedtunnel vpn show NAME'
            vpn_show_client "$1"
            ;;
        share)
            vpn_require_installed
            [[ -n ${1-} ]] || die 'Usage: seedtunnel vpn share NAME'
            vpn_share_client "$1"
            ;;
        restart)
            vpn_require_installed
            run 'Restarting the VPN' systemctl restart "wg-quick@$VPN_INTERFACE"
            ;;
        uninstall)
            vpn_require_installed
            vpn_uninstall
            ;;
        *) die 'Unknown command: vpn %s   (help: seedtunnel help)' "$command" ;;
    esac
}
