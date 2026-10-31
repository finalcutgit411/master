#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — firewall (nftables)
#
#  Everything that reaches the server is refused, except:
#    - replies to connections already open, ICMP (ping, IPv6);
#    - SSH on the port(s) really used by sshd and by the current session;
#    - the VPN and the seedbox if they are installed.
#  The rules live in their own table (inet seedtunnel_fw): fail2ban, Docker or
#  other tools keep theirs.
#
#  Safety when enabling: an automatic undo is scheduled 2 minutes later; the
#  firewall is only kept if confirmed from a NEW SSH connection.
# =============================================================================

FIREWALL_CONF_FILE="$APP_STATE_DIR/firewall.conf"
FIREWALL_RULES="$APP_STATE_DIR/firewall.nft"
FIREWALL_UNIT="/etc/systemd/system/seedtunnel-firewall.service"
FIREWALL_TABLE="seedtunnel_fw"
FIREWALL_ROLLBACK_UNIT="seedtunnel-firewall-rollback"

firewall_load() {
    FIREWALL_ENABLED=0
    state_read "$FIREWALL_CONF_FILE"
}

firewall_enabled() {
    firewall_load
    ((FIREWALL_ENABLED == 1))
}

# SSH ports: those of sshd, plus the one of the current connection (just in case)
firewall_ssh_ports() {
    local settings ports
    settings=$(sshd -T 2>/dev/null || true)
    ports=$(awk '$1 == "port" { print $2 }' <<<"$settings")
    if [[ -n ${SSH_CONNECTION-} ]]; then ports+=$'\n'"${SSH_CONNECTION##* }"; fi
    ports=$(awk '/^[0-9]+$/ && !seen[$0]++' <<<"$ports" | paste -sd, -)
    ports=${ports:-22}
    printf '%s' "${ports//,/, }"
}

# Ports on which SSH really listens, plus those of its configuration (used at
# the next restart of SSH)
firewall_sshd_ports() {
    {
        sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'
        ss -Hltnp 2>/dev/null | awk '/"sshd"/ { n = split($4, a, ":"); print a[n] }'
    } | awk '/^[0-9]+$/ && !seen[$0]++' || true
}

# TCP ports accepted by loaded rules (text of « nft list » on standard input)
firewall_open_tcp_ports() {
    { grep -oE 'tcp dport (\{[^}]*\}|[0-9]+) accept' || true; } | { grep -oE '[0-9]+' || true; } | sort -un
}

# What is open, in words
firewall_summary() {
    local summary
    summary="SSH ($(firewall_ssh_ports)/tcp)"
    if vpn_installed; then summary+=", VPN ($VPN_PORT/udp)"; fi
    if seedbox_installed; then summary+=", $(t 'web (80, 443/tcp), BitTorrent (%s)' "$TORRENT_PORT")"; fi
    printf '%s' "$summary"
}

firewall_generate_rules() {
    local extra=""
    if vpn_installed; then
        extra+="        # WireGuard VPN, and everything coming from the clients of the VPN
        udp dport $VPN_PORT accept
        iifname \"$VPN_INTERFACE\" accept
"
    fi
    if seedbox_installed; then
        extra+="        # seedbox: web site (HTTP for Let's Encrypt, then HTTPS) and BitTorrent peers
        tcp dport { 80, 443 } accept
        meta l4proto { tcp, udp } th dport $TORRENT_PORT accept
"
    fi
    cat <<EOF
#!/usr/sbin/nft -f
# Written by seedtunnel — firewall: anything not allowed here is refused.
table inet $FIREWALL_TABLE
delete table inet $FIREWALL_TABLE
table inet $FIREWALL_TABLE {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop
        iifname "lo" accept
        # ping and the ICMP messages IPv6 cannot work without; protocol
        # numbers (1 = ICMP, 58 = ICMPv6): names depend on /etc/protocols,
        # missing from some minimal images
        meta l4proto { 1, 58 } accept
        # IPv6 address obtained by DHCPv6
        ip6 saddr fe80::/10 udp dport 546 accept
        # SSH and SFTP
        tcp dport { $(firewall_ssh_ports) } accept
$extra    }
}
EOF
}

firewall_generate_unit() {
    cat <<EOF
# Written by seedtunnel — loads the firewall at boot, before the network
[Unit]
Description=seedtunnel firewall (nftables)
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $FIREWALL_RULES
ExecReload=/usr/sbin/nft -f $FIREWALL_RULES
ExecStop=-/usr/sbin/nft delete table inet $FIREWALL_TABLE

[Install]
WantedBy=sysinit.target
EOF
}

# Rules loaded + loaded again at boot + state saved
firewall_activate() {
    run 'Applying the rules' nft -f "$FIREWALL_RULES"
    if write_if_changed "$FIREWALL_UNIT" 644 root:root firewall_generate_unit; then
        run 'Reloading systemd' systemctl daemon-reload
    fi
    run 'Enabling at boot' systemctl enable --now seedtunnel-firewall.service
    FIREWALL_ENABLED=1
    state_write "$FIREWALL_CONF_FILE" FIREWALL_ENABLED
}

firewall_enable() {
    local answer
    banner
    section 'FIREWALL'
    apt_install nftables
    write_if_changed "$FIREWALL_RULES" 600 root:root firewall_generate_rules || true
    run 'Checking the rules' nft -c -f "$FIREWALL_RULES"
    say '  Open: %s' "$(firewall_summary)"
    echo
    if ((INTERACTIVE)); then
        say 'For safety, the firewall will undo itself in 2 minutes unless you'
        say 'confirm from a NEW SSH connection.'
        echo
        if ! confirm 'Enable the firewall?' y; then return 0; fi
        systemctl stop "$FIREWALL_ROLLBACK_UNIT.timer" &>/dev/null || true
        systemctl reset-failed "$FIREWALL_ROLLBACK_UNIT.timer" "$FIREWALL_ROLLBACK_UNIT.service" &>/dev/null || true
        run 'Scheduling the automatic undo (2 min)' \
            systemd-run --quiet --unit="$FIREWALL_ROLLBACK_UNIT" --on-active=120 /usr/sbin/nft delete table inet "$FIREWALL_TABLE"
        run 'Applying the rules (temporarily)' nft -f "$FIREWALL_RULES"
        echo
        say 'Now open a NEW SSH connection to this server, without closing this one.'
        if IFS= read -r -t 110 -p "$(t 'Does it work? Type "yes" to keep the firewall:') " answer \
            && [[ ${answer,,} == yes || ${answer,,} == oui ]]; then
            systemctl stop "$FIREWALL_ROLLBACK_UNIT.timer" &>/dev/null || true
        else
            echo
            nft delete table inet "$FIREWALL_TABLE" &>/dev/null || true
            systemctl stop "$FIREWALL_ROLLBACK_UNIT.timer" &>/dev/null || true
            warn 'Firewall cancelled: nothing was kept.'
            pause
            return 0
        fi
    fi
    firewall_activate
    ok 'Firewall on: everything not allowed is refused.'
    pause
}

firewall_disable() {
    banner
    section 'FIREWALL'
    if ! confirm 'Turn the firewall off?' n; then return 0; fi
    systemctl disable --now seedtunnel-firewall.service >>"$APP_LOG" 2>&1 || true
    nft delete table inet "$FIREWALL_TABLE" >>"$APP_LOG" 2>&1 || true
    rm -f "$FIREWALL_UNIT" "$FIREWALL_RULES" "$FIREWALL_CONF_FILE"
    systemctl daemon-reload 2>/dev/null || true
    ok 'Firewall off.'
    pause
}

# Called after every change of the VPN or of the seedbox
firewall_refresh() {
    firewall_enabled || return 0
    if write_if_changed "$FIREWALL_RULES" 600 root:root firewall_generate_rules; then
        run 'Updating the firewall' nft -f "$FIREWALL_RULES"
    fi
}

firewall_status() {
    if firewall_enabled; then
        if nft list table inet "$FIREWALL_TABLE" &>/dev/null; then
            ok 'Firewall on — open: %s' "$(firewall_summary)"
        else
            warn 'Firewall enabled but rules missing:  seedtunnel firewall enable --yes'
        fi
    else
        say 'seedtunnel firewall off (everything is open, apart from the fail2ban rules).'
    fi
}

firewall_menu() {
    local choice
    while true; do
        banner
        section 'FIREWALL'
        firewall_status
        echo
        say '1) Enable / update the firewall'
        say '2) Turn the firewall off'
        echo
        say 'Q) Back'
        echo
        ask choice 'Your choice' ""
        case ${choice,,} in
            1) firewall_enable ;;
            2) firewall_disable ;;
            q) return 0 ;;
        esac
    done
}

# seedtunnel firewall <command>
firewall_cli() {
    case ${1-} in
        "")
            require_terminal
            firewall_menu
            ;;
        enable)
            # in a terminal: enabled with the automatic undo
            if [[ -t 0 ]] && ((!OPT_YES)); then
                INTERACTIVE=1
            elif ((!OPT_YES)); then
                die 'Without a terminal:  seedtunnel firewall enable --yes'
            fi
            firewall_enable
            ;;
        disable) firewall_disable ;;
        status) firewall_status ;;
        *) die 'Usage: seedtunnel firewall enable|disable|status' ;;
    esac
}
