#!/usr/bin/env bash
# =============================================================================
#  finalcut — diagnostic (« finalcut doctor »)
#
#  Vérifie d'un coup ce qui cause la plupart des pannes : services arrêtés,
#  DNS qui ne pointe pas sur le serveur, certificat bientôt expiré, port
#  fermé, disque plein, horloge fausse… Chaque ligne dit quoi faire.
#  Code de sortie : 0 si aucun problème, 1 sinon (utilisable dans un script).
# =============================================================================

DOC_FAIL=0
DOC_WARN=0

d_ok() { ok "$*"; }
d_warn() {
    DOC_WARN=$((DOC_WARN + 1))
    printf '%s!%s %s\n' "$C_YEL" "$C_END" "$*"
}
d_fail() {
    DOC_FAIL=$((DOC_FAIL + 1))
    printf '%s✘%s %s\n' "$C_RED" "$C_END" "$*"
}
d_title() { printf '\n%s%s%s\n' "$C_BLD" "$*" "$C_END"; }

d_svc() {
    if systemctl is-active --quiet "$1"; then
        d_ok "$2 : actif"
    else
        d_fail "$2 : arrêté   → journalctl -u $1 -n 30"
    fi
}

# Jours restants avant expiration d'un certificat (vide si illisible)
d_cert_days() {
    local end e n
    end=$(openssl x509 -in "$1" -noout -enddate 2>/dev/null | cut -d= -f2 || true)
    [[ -n $end ]] || return 0
    e=$(date -d "$end" +%s 2>/dev/null) || return 0
    n=$(date +%s)
    printf '%s' "$(((e - n) / 86400))"
}

# Espace libre en Go sur la partition d'un dossier
d_free_gb() {
    df -Pk "$1" 2>/dev/null | awk 'NR == 2 { printf "%d", $4 / 1048576 }'
}

doctor_system() {
    local free sync
    d_title "Système"
    d_ok "$FC_OS_DESC, finalcut $FC_VERSION"
    free=$(d_free_gb /)
    if [[ -z $free ]]; then
        d_warn "Espace disque de / illisible"
    elif ((free < 2)); then
        d_fail "Disque presque plein : ${free} Go libres sur /"
    else
        d_ok "Espace libre sur / : ${free} Go"
    fi
    if grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
        d_ok "Mises à jour de sécurité automatiques activées"
    else
        d_warn "Mises à jour de sécurité automatiques désactivées"
    fi
    if [[ -e /run/reboot-required ]]; then
        d_warn "Redémarrage conseillé (mise à jour du noyau ou d'une bibliothèque)"
    fi
    sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
    if [[ $sync == yes ]]; then
        d_ok "Horloge synchronisée"
    else
        d_warn "Horloge non synchronisée : les certificats et WireGuard en dépendent (timedatectl)"
    fi
}

doctor_vpn() {
    local ip=$1 ips total=0 conn=0 pk _a _b _c h _r _t _k now
    d_title "VPN WireGuard"
    d_svc "wg-quick@$VPN_IF" "Service WireGuard"
    if [[ $(wg show "$VPN_IF" listen-port 2>/dev/null || true) == "$VPN_PORT" ]]; then
        d_ok "Écoute sur le port $VPN_PORT/udp"
    else
        d_fail "WireGuard n'écoute pas sur le port $VPN_PORT/udp   → finalcut vpn restart"
    fi
    if [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == 1 ]]; then
        d_ok "Routage IPv4 activé"
    else
        d_fail "Routage IPv4 désactivé : les clients n'auront pas Internet   → finalcut vpn install --config …"
    fi
    if nft list table ip finalcut &>/dev/null; then
        d_ok "Règles NAT en place"
    else
        d_fail "Règles NAT absentes   → finalcut vpn restart"
    fi
    if is_ipv4 "$VPN_ENDPOINT"; then
        if [[ $VPN_ENDPOINT == "$ip" ]]; then
            d_ok "Adresse des clients ($VPN_ENDPOINT) = IP publique du serveur"
        else
            d_warn "Les clients se connectent à $VPN_ENDPOINT, mais l'IP publique est ${ip:-inconnue}"
        fi
    else
        ips=$(sb_dns_ips "$VPN_ENDPOINT")
        if [[ -n $ip ]] && grep -qxF "$ip" <<<"$ips"; then
            d_ok "« $VPN_ENDPOINT » pointe vers ce serveur"
        else
            d_warn "« $VPN_ENDPOINT » pointe vers ${ips:-rien} et non vers ${ip:-ce serveur}"
        fi
    fi
    now=$(date +%s)
    if systemctl is-active --quiet "wg-quick@$VPN_IF"; then
        while IFS=$'\t' read -r pk _a _b _c h _r _t _k; do
            total=$((total + 1))
            if ((h > 0 && now - h < 180)); then conn=$((conn + 1)); fi
        done < <(wg show "$VPN_IF" dump 2>/dev/null | tail -n +2)
    fi
    d_ok "Clients : $total, dont $conn connecté(s) en ce moment"
    echo "  (le port UDP ne peut pas être testé de l'extérieur depuis le serveur : en cas de"
    echo "   doute, vérifiez le pare-feu du panneau de l'hébergeur)"
}

doctor_seedbox() {
    local ip=$1 crt days code free t
    d_title "Seedbox"
    d_svc transmission-daemon "Transmission"
    d_svc nginx "nginx"
    d_svc fail2ban "fail2ban"
    d_svc ssh.service "SSH / SFTP"

    if is_ipv4 "$SB_DOMAIN"; then
        d_warn "Pas de nom de domaine (accès par IP, certificat auto-signé)"
    elif sb_dns_points_here "$SB_DOMAIN" "$ip"; then
        d_ok "« $SB_DOMAIN » pointe vers ce serveur ($ip)"
    else
        d_fail "« $SB_DOMAIN » ne pointe pas vers ce serveur (${ip:-IP inconnue}) : vérifiez le DNS"
    fi

    if [[ $SB_CERT == selfsigned ]]; then crt="$SB_SSL/selfsigned.crt"; else crt="$SB_LE_DIR/cert.pem"; fi
    days=$(d_cert_days "$crt")
    if [[ -z $days ]]; then
        d_fail "Certificat illisible : $crt   → finalcut seedbox domain $SB_DOMAIN"
    elif [[ $SB_CERT == selfsigned ]]; then
        d_warn "Certificat auto-signé (alerte du navigateur)   → finalcut seedbox domain $SB_DOMAIN"
    elif ((days < 7)); then
        d_fail "Certificat Let's Encrypt : expire dans $days jour(s), le renouvellement échoue   → certbot renew"
    elif ((days < 21)); then
        d_warn "Certificat Let's Encrypt : expire dans $days jours (il aurait dû être renouvelé)"
    else
        d_ok "Certificat $(sb_cert_label) : encore $days jours"
    fi
    if [[ $SB_CERT != selfsigned ]]; then
        if systemctl is-active --quiet certbot.timer; then
            d_ok "Renouvellement automatique programmé (certbot.timer)"
        else
            d_fail "certbot.timer inactif : le certificat ne sera pas renouvelé   → systemctl enable --now certbot.timer"
        fi
    fi

    code=$(sb_http_code /transmission/web/)
    if [[ $code == 401 ]]; then
        d_ok "Interface web en ligne et protégée par mot de passe"
    else
        d_fail "Interface web : réponse inattendue (code ${code:-aucun}) sur https://$SB_DOMAIN/"
    fi
    if [[ -n $ip ]]; then
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 \
            --resolve "$SB_DOMAIN:443:$ip" "https://$SB_DOMAIN/transmission/web/" 2>/dev/null || true)
        if [[ $code == 401 ]]; then
            d_ok "HTTPS joignable par l'IP publique (test depuis le serveur lui-même)"
        else
            d_warn "HTTPS injoignable par l'IP publique $ip (code ${code:-aucun}) : pare-feu ?"
        fi
    fi

    t=$(sshd -T -C "user=$SB_USER,host=localhost,addr=127.0.0.1" 2>/dev/null || true)
    if [[ $t == *"chrootdirectory $SB_DATA"* ]]; then
        d_ok "SFTP enfermé dans $SB_DATA"
    else
        d_fail "Règle SFTP inactive pour $SB_USER   → finalcut seedbox install --config … ou menu"
    fi
    if sb_check_data_path "$SB_DATA" 2>/dev/null; then
        d_ok "Droits du dossier des données corrects"
    else
        d_fail "Droits du dossier $SB_DATA incompatibles avec le SFTP enfermé"
    fi
    free=$(d_free_gb "$SB_DATA")
    if [[ -n $free ]] && ((free < 5)); then
        d_warn "Peu d'espace pour les téléchargements : ${free} Go libres"
    elif [[ -n $free ]]; then
        d_ok "Espace libre pour les téléchargements : ${free} Go"
    fi
    t=$(fail2ban-client status 2>/dev/null || true)
    if [[ $t == *sshd* && $t == *nginx-http-auth* && $t == *recidive* ]]; then
        d_ok "fail2ban surveille SSH, l'interface web et les récidivistes"
    else
        d_warn "Règles fail2ban incomplètes   → finalcut seedbox restart"
    fi
    if [[ -z $SB_HASH_WEB ]]; then
        d_warn "Empreintes du mot de passe absentes (installation 2.0)   → finalcut seedbox password"
    fi
}

doctor_firewall() {
    local rules port
    local -a ports
    d_title "Pare-feu"
    if fw_enabled; then
        rules=$(nft list table inet "$FW_TABLE" 2>/dev/null || true)
        if [[ -z $rules ]]; then
            d_fail "Pare-feu activé mais règles absentes   → finalcut firewall enable --yes"
        else
            d_ok "Actif — ouvertures : $(fw_summary)"
            IFS=', ' read -r -a ports <<<"$(fw_ssh_ports)"
            for port in "${ports[@]}"; do
                if [[ $rules != *"$port"* ]]; then d_fail "Le port SSH $port n'est pas ouvert !"; fi
            done
        fi
    else
        d_warn "Pare-feu finalcut désactivé   → finalcut firewall enable"
    fi
    if systemctl is-enabled --quiet nftables.service 2>/dev/null \
        && grep -qs 'flush ruleset' /etc/nftables.conf; then
        d_warn "nftables.service est activé et vide toutes les règles au démarrage (/etc/nftables.conf)"
    fi
}

doctor_main() {
    local ip
    DOC_FAIL=0
    DOC_WARN=0
    titre
    section "DIAGNOSTIC"
    printf "Recherche de l'adresse IP publique… "
    ip=$(public_ipv4)
    echo "${ip:-introuvable}"
    doctor_system
    if vpn_installed; then doctor_vpn "$ip"; fi
    if sb_installed; then doctor_seedbox "$ip"; fi
    doctor_firewall
    echo
    if ((DOC_FAIL)); then
        err "$DOC_FAIL problème(s), $DOC_WARN avertissement(s)."
    elif ((DOC_WARN)); then
        warn "Aucun problème bloquant, $DOC_WARN avertissement(s)."
    else
        ok "Tout est en ordre."
    fi
    pause
}
