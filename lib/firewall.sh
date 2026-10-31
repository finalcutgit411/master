#!/usr/bin/env bash
# =============================================================================
#  finalcut — pare-feu (nftables)
#
#  Tout ce qui arrive sur le serveur est refusé, sauf :
#    - les réponses aux connexions déjà ouvertes, l'ICMP (ping, IPv6) ;
#    - SSH sur le(s) port(s) réellement utilisé(s) par sshd et la session en cours ;
#    - le VPN et la seedbox s'ils sont installés.
#  Les règles sont dans une table à part (inet finalcut_fw) : fail2ban, Docker
#  ou d'autres outils gardent les leurs.
#
#  Sécurité à l'activation : une annulation automatique est programmée 2 minutes
#  plus tard ; il faut confirmer depuis une NOUVELLE connexion SSH pour la garder.
# =============================================================================

FW_CONF="$FC_ETC/firewall.conf"
FW_NFT="$FC_ETC/firewall.nft"
FW_UNIT="/etc/systemd/system/finalcut-firewall.service"
FW_TABLE="finalcut_fw"
FW_ROLLBACK="finalcut-fw-rollback"

fw_load() {
    FW_ENABLED=0
    conf_read "$FW_CONF"
}

fw_enabled() {
    fw_load
    ((FW_ENABLED == 1))
}

# Ports SSH : ceux de sshd, plus celui de la connexion en cours (au cas où)
fw_ssh_ports() {
    local t ports
    t=$(sshd -T 2>/dev/null || true)
    ports=$(awk '$1 == "port" { print $2 }' <<<"$t")
    if [[ -n ${SSH_CONNECTION-} ]]; then ports+=$'\n'"${SSH_CONNECTION##* }"; fi
    ports=$(awk '/^[0-9]+$/ && !seen[$0]++' <<<"$ports" | paste -sd, -)
    ports=${ports:-22}
    printf '%s' "${ports//,/, }"
}

# Résumé lisible des ouvertures
fw_summary() {
    local s
    s="SSH ($(fw_ssh_ports)/tcp)"
    if vpn_installed; then s+=", VPN ($VPN_PORT/udp)"; fi
    if sb_installed; then s+=", web (80, 443/tcp), BitTorrent ($SB_PEER_PORT)"; fi
    printf '%s' "$s"
}

fw_gen() {
    local extra=""
    if vpn_installed; then
        extra+="        # VPN WireGuard, et tout ce qui vient des clients du VPN
        udp dport $VPN_PORT accept
        iifname \"$VPN_IF\" accept
"
    fi
    if sb_installed; then
        extra+="        # seedbox : site web (HTTP pour Let's Encrypt, puis HTTPS) et pairs BitTorrent
        tcp dport { 80, 443 } accept
        meta l4proto { tcp, udp } th dport $SB_PEER_PORT accept
"
    fi
    cat <<EOF
#!/usr/sbin/nft -f
# Généré par finalcut — pare-feu : tout ce qui n'est pas autorisé ici est refusé.
table inet $FW_TABLE
delete table inet $FW_TABLE
table inet $FW_TABLE {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop
        iifname "lo" accept
        # ping et messages ICMP indispensables (IPv6 ne fonctionne pas sans) ;
        # numéros de protocole (1 = ICMP, 58 = ICMPv6) : les noms dépendent
        # de /etc/protocols, absent de certaines images minimales
        meta l4proto { 1, 58 } accept
        # adresse IPv6 obtenue par DHCPv6
        ip6 saddr fe80::/10 udp dport 546 accept
        # SSH et SFTP
        tcp dport { $(fw_ssh_ports) } accept
$extra    }
}
EOF
}

fw_gen_unit() {
    cat <<EOF
# Généré par finalcut — recharge le pare-feu au démarrage, avant le réseau
[Unit]
Description=Pare-feu finalcut (nftables)
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $FW_NFT
ExecReload=/usr/sbin/nft -f $FW_NFT
ExecStop=-/usr/sbin/nft delete table inet $FW_TABLE

[Install]
WantedBy=sysinit.target
EOF
}

# Règles chargées + rechargement au démarrage + état enregistré
fw_activate() {
    run "Application des règles" nft -f "$FW_NFT"
    if write_if_changed "$FW_UNIT" 644 < <(fw_gen_unit); then
        run "Rechargement de systemd" systemctl daemon-reload
    fi
    run "Activation au démarrage" systemctl enable --now finalcut-firewall.service
    FW_ENABLED=1
    conf_write "$FW_CONF" FW_ENABLED
}

fw_enable() {
    local rep
    titre
    section "PARE-FEU"
    apt_install nftables
    write_if_changed "$FW_NFT" 600 < <(fw_gen) || true
    run "Vérification des règles" nft -c -f "$FW_NFT"
    echo "  Ouvertures : $(fw_summary)"
    echo
    if ((FC_INTERACTIVE)); then
        echo "Par sécurité, le pare-feu sera annulé tout seul dans 2 minutes si vous ne"
        echo "confirmez pas depuis une NOUVELLE connexion SSH."
        echo
        if ! confirm "Activer le pare-feu ?" o; then return 0; fi
        systemctl stop "$FW_ROLLBACK.timer" &>/dev/null || true
        systemctl reset-failed "$FW_ROLLBACK.timer" "$FW_ROLLBACK.service" &>/dev/null || true
        run "Programmation de l'annulation automatique (2 min)" \
            systemd-run --quiet --unit="$FW_ROLLBACK" --on-active=120 /usr/sbin/nft delete table inet "$FW_TABLE"
        run "Application des règles (provisoire)" nft -f "$FW_NFT"
        echo
        echo "Ouvrez maintenant une NOUVELLE connexion SSH vers ce serveur, sans fermer celle-ci."
        if IFS= read -r -t 110 -p "Elle fonctionne ? Tapez « oui » pour garder le pare-feu : " rep && [[ ${rep,,} == oui ]]; then
            systemctl stop "$FW_ROLLBACK.timer" &>/dev/null || true
        else
            echo
            nft delete table inet "$FW_TABLE" &>/dev/null || true
            systemctl stop "$FW_ROLLBACK.timer" &>/dev/null || true
            warn "Pare-feu annulé : rien n'a été conservé."
            pause
            return 0
        fi
    fi
    fw_activate
    ok "Pare-feu actif : tout ce qui n'est pas autorisé est refusé."
    pause
}

fw_disable() {
    titre
    section "PARE-FEU"
    if ! confirm "Désactiver le pare-feu ?" n; then return 0; fi
    systemctl disable --now finalcut-firewall.service >>"$FC_LOG" 2>&1 || true
    nft delete table inet "$FW_TABLE" >>"$FC_LOG" 2>&1 || true
    rm -f "$FW_UNIT" "$FW_NFT" "$FW_CONF"
    systemctl daemon-reload 2>/dev/null || true
    ok "Pare-feu désactivé."
    pause
}

# Appelé après chaque changement du VPN ou de la seedbox
fw_refresh() {
    fw_enabled || return 0
    if write_if_changed "$FW_NFT" 600 < <(fw_gen); then
        run "Mise à jour du pare-feu" nft -f "$FW_NFT"
    fi
}

fw_status() {
    if fw_enabled; then
        if nft list table inet "$FW_TABLE" &>/dev/null; then
            ok "Pare-feu actif — ouvertures : $(fw_summary)"
        else
            warn "Pare-feu activé mais règles absentes : finalcut firewall enable --yes"
        fi
    else
        echo "Pare-feu finalcut désactivé (tout est ouvert, hors règles de fail2ban)."
    fi
}

fw_menu() {
    local choix
    while true; do
        titre
        section "PARE-FEU"
        fw_status
        echo
        cat <<EOF
1) Activer / mettre à jour le pare-feu
2) Désactiver le pare-feu

Q) Retour
EOF
        echo
        ask choix "Votre choix" ""
        case ${choix,,} in
            1) fw_enable ;;
            2) fw_disable ;;
            q) return 0 ;;
        esac
    done
}

# finalcut firewall <commande>
fw_cli() {
    case ${1-} in
        "")
            require_tty
            fw_menu
            ;;
        enable)
            # dans un terminal : activation avec annulation automatique
            if [[ -t 0 ]] && ((!FC_YES)); then
                FC_INTERACTIVE=1
            elif ((!FC_YES)); then
                die "Sans terminal :  finalcut firewall enable --yes"
            fi
            fw_enable
            ;;
        disable) fw_disable ;;
        status) fw_status ;;
        *) die "Usage : finalcut firewall enable|disable|status" ;;
    esac
}
