#!/usr/bin/env bash
# =============================================================================
#  finalcut — module VPN (WireGuard)
#
#  Réseau 10.8.0.0/24 : le serveur est 10.8.0.1, le client n°N reçoit
#  10.8.0.(N+1) et le port public 60000+N, redirigé vers lui en TCP et UDP
#  (pratique pour un client torrent à la maison derrière le VPN).
#
#  Tout est régénéré à partir de /etc/finalcut/vpn/ (« vpn_apply ») :
#    server.key / server.pub      clés du serveur
#    clients/<nom>.env            numéro et clés d'un client
#    clients/<nom>.conf           fichier à importer dans l'application WireGuard
#    nat.nft                      règles NAT, chargées au démarrage de wg0
#  vpn_apply ne modifie que ce qui a changé : on peut le relancer sans risque.
# =============================================================================

VPN_IF="wg0"
VPN_NET="10.8.0"
# 10.8.0.2 → 10.8.0.254
VPN_MAX=253
# le client n°N reçoit le port 60000+N
VPN_PORT_BASE=60000
VPN_DIR="$FC_ETC/vpn"
VPN_CONF="$FC_ETC/vpn.conf"
VPN_CLIENTS="$VPN_DIR/clients"
VPN_NFT="$VPN_DIR/nat.nft"
VPN_SYSCTL="/etc/sysctl.d/90-finalcut-vpn.conf"
WG_CONF="/etc/wireguard/$VPN_IF.conf"

vpn_load() {
    VPN_PORT=51820
    VPN_ENDPOINT=""
    VPN_DNS="9.9.9.9, 149.112.112.112"
    VPN_NIC=""
    conf_read "$VPN_CONF"
}

vpn_save() { conf_write "$VPN_CONF" VPN_PORT VPN_ENDPOINT VPN_DNS VPN_NIC; }

vpn_installed() { [[ -f $VPN_CONF ]]; }

vpn_require_installed() {
    vpn_installed || die "Le VPN n'est pas installé :  finalcut vpn install"
}

vpn_client_names() {
    local f
    for f in "$VPN_CLIENTS"/*.env; do
        [[ -e $f ]] || continue
        f=${f##*/}
        printf '%s\n' "${f%.env}"
    done
}

vpn_count_clients() {
    local n=0 f
    for f in "$VPN_CLIENTS"/*.env; do
        if [[ -e $f ]]; then n=$((n + 1)); fi
    done
    printf '%s' "$n"
}

# Clients connectés : dernière « poignée de main » il y a moins de 3 minutes
# (WireGuard la renouvelle toutes les 2 minutes tant que le tunnel sert)
vpn_connected_count() {
    local now n=0 _pk h
    if systemctl is-active --quiet "wg-quick@$VPN_IF"; then
        now=$(date +%s)
        while read -r _pk h; do
            if [[ $h =~ ^[0-9]+$ ]] && ((h > 0 && now - h < 180)); then n=$((n + 1)); fi
        done < <(wg show "$VPN_IF" latest-handshakes 2>/dev/null || true)
    fi
    printf '%s' "$n"
}

# 15 caractères max : sous Linux, le nom du fichier devient celui de l'interface
vpn_valid_name() { [[ $1 =~ ^[A-Za-z0-9_-]{1,15}$ ]]; }

vpn_require_client() {
    vpn_valid_name "$1" || die "Nom de client invalide : « $1 »."
    [[ -e $VPN_CLIENTS/$1.env ]] || die "Client « $1 » introuvable (finalcut vpn list)."
}

# quad9 | cloudflare | adresses IP séparées par des virgules
vpn_dns_value() {
    case ${1,,} in
        quad9 | "") printf '9.9.9.9, 149.112.112.112' ;;
        cloudflare) printf '1.1.1.1, 1.0.0.1' ;;
        *) printf '%s' "$1" ;;
    esac
}

vpn_valid_dns() { [[ $1 =~ ^[0-9A-Fa-f:.,\ ]+$ ]]; }

vpn_valid_endpoint() { [[ $1 =~ ^[A-Za-z0-9.:-]+$ ]]; }

# Le port UDP est-il libre (ou déjà le nôtre) ?
vpn_port_free() {
    local cur
    cur=$(wg show "$VPN_IF" listen-port 2>/dev/null || true)
    [[ $1 == "$cur" ]] && return 0
    ! port_in_use udp "$1"
}

# Le noyau sait-il créer une interface WireGuard ? (échoue dans certains
# conteneurs OpenVZ/LXC, comme le module TUN/TAP à l'époque)
vpn_check_kernel() {
    if ip link show "$VPN_IF" &>/dev/null; then return 0; fi
    if ! ip link add dev fc-wgtest type wireguard 2>/dev/null; then
        die "Le noyau ne permet pas de créer une interface WireGuard.
  Sur un VPS en conteneur (OpenVZ, LXC), demandez à l'hébergeur d'activer
  WireGuard, ou choisissez une offre KVM."
    fi
    ip link del dev fc-wgtest
}

# --- Génération des fichiers (sur la sortie standard) -----------------------

vpn_gen_client() {
    local name=$1 ID PUB PSK PRIV ep
    # shellcheck source=/dev/null
    . "$VPN_CLIENTS/$name.env"
    ep=$VPN_ENDPOINT
    # adresse IPv6 → entre crochets
    if [[ $ep == *:* ]]; then ep="[$ep]"; fi
    cat <<EOF
# finalcut — client « $name » — IP $VPN_NET.$((ID + 1)) — port ouvert $((VPN_PORT_BASE + ID))
[Interface]
PrivateKey = $PRIV
Address = $VPN_NET.$((ID + 1))/32
DNS = $VPN_DNS

[Peer]
PublicKey = $(<"$VPN_DIR/server.pub")
PresharedKey = $PSK
Endpoint = $ep:$VPN_PORT
# ::/0 envoie aussi l'IPv6 dans le tunnel (où il est bloqué) : pas de fuite IPv6
AllowedIPs = 0.0.0.0/0, ::/0
# Garde le tunnel ouvert derrière une box : indispensable pour le port ouvert
PersistentKeepalive = 25
EOF
}

vpn_gen_server() {
    local f name ID PUB PSK PRIV
    cat <<EOF
# Généré par finalcut — utilisez le menu plutôt que de modifier ce fichier.
[Interface]
Address = $VPN_NET.1/24
ListenPort = $VPN_PORT
PrivateKey = $(<"$VPN_DIR/server.key")
PostUp = nft -f $VPN_NFT
PostDown = nft delete table ip finalcut
EOF
    for f in "$VPN_CLIENTS"/*.env; do
        [[ -e $f ]] || continue
        name=${f##*/}
        name=${name%.env}
        # shellcheck source=/dev/null
        . "$f"
        cat <<EOF

# client : $name
[Peer]
PublicKey = $PUB
PresharedKey = $PSK
AllowedIPs = $VPN_NET.$((ID + 1))/32
EOF
    done
}

# « table / delete / table » : remplace la table d'un seul coup, qu'elle
# existe déjà ou non, sans toucher aux autres règles du système.
vpn_gen_nat() {
    local f name ID PUB PSK PRIV
    cat <<EOF
#!/usr/sbin/nft -f
# Généré par finalcut — NAT du VPN, chargé au démarrage de $VPN_IF.
table ip finalcut
delete table ip finalcut
table ip finalcut {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
EOF
    for f in "$VPN_CLIENTS"/*.env; do
        [[ -e $f ]] || continue
        name=${f##*/}
        name=${name%.env}
        # shellcheck source=/dev/null
        . "$f"
        printf '        # client « %s »\n' "$name"
        printf '        iifname "%s" meta l4proto { tcp, udp } th dport %s dnat to %s\n' \
            "$VPN_NIC" "$((VPN_PORT_BASE + ID))" "$VPN_NET.$((ID + 1))"
    done
    cat <<EOF
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # les clients sortent sur Internet avec l'IP du serveur
        ip saddr $VPN_NET.0/24 oifname "$VPN_NIC" masquerade
    }
}
EOF
}

# --- Application -------------------------------------------------------------------

# Applique la configuration à chaud, sans couper les clients connectés
vpn_sync() {
    wg syncconf "$VPN_IF" <(wg-quick strip "$VPN_IF")
    nft -f "$VPN_NFT"
}

# Met le serveur dans l'état décrit par /etc/finalcut (idempotent)
vpn_apply() {
    local nic name changed=0 cur_port
    apt_install wireguard-tools qrencode
    install -d -m 700 "$VPN_DIR" "$VPN_CLIENTS" /etc/wireguard
    if [[ ! -s $VPN_DIR/server.key ]]; then
        (umask 077 && wg genkey >"$VPN_DIR/server.key")
    fi
    write_if_changed "$VPN_DIR/server.pub" 600 < <(wg pubkey <"$VPN_DIR/server.key") || true

    # l'interface réseau peut changer (restauration sur un autre serveur)
    nic=$(default_iface)
    if [[ -n $nic ]]; then VPN_NIC=$nic; fi
    [[ -n $VPN_NIC ]] || die "Interface réseau principale introuvable (pas de route par défaut ?)."
    vpn_save
    # port du VPN ouvert dans le pare-feu avant le démarrage
    fw_refresh

    # le serveur doit faire suivre les paquets des clients vers Internet
    if write_if_changed "$VPN_SYSCTL" 644 < <(printf '# Généré par finalcut : routage des clients du VPN\nnet.ipv4.ip_forward = 1\n') \
        || [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) != 1 ]]; then
        run "Activation du routage IPv4" sysctl -q -p "$VPN_SYSCTL"
    fi
    net_hardening_apply

    while IFS= read -r name; do
        write_if_changed "$VPN_CLIENTS/$name.conf" 600 < <(vpn_gen_client "$name") || true
    done < <(vpn_client_names)
    if write_if_changed "$WG_CONF" 600 < <(vpn_gen_server); then changed=1; fi
    if write_if_changed "$VPN_NFT" 600 < <(vpn_gen_nat); then changed=1; fi

    if ! systemctl is-active --quiet "wg-quick@$VPN_IF"; then
        run "Démarrage du VPN" systemctl enable --now "wg-quick@$VPN_IF"
    else
        cur_port=$(wg show "$VPN_IF" listen-port 2>/dev/null || true)
        if [[ $cur_port != "$VPN_PORT" ]]; then
            run "Redémarrage du VPN (nouveau port)" systemctl restart "wg-quick@$VPN_IF"
        elif ((changed)); then
            run "Application de la configuration" vpn_sync
        fi
        systemctl enable --quiet "wg-quick@$VPN_IF" 2>/dev/null || true
    fi
}

vpn_next_id() {
    local id f used=" "
    for f in "$VPN_CLIENTS"/*.env; do
        [[ -e $f ]] || continue
        used+="$(
            # shellcheck source=/dev/null
            . "$f"
            printf '%s' "$ID"
        ) "
    done
    for ((id = 1; id <= VPN_MAX; id++)); do
        if [[ $used != *" $id "* ]]; then
            printf '%s' "$id"
            return 0
        fi
    done
    return 1
}

# --- Clients -------------------------------------------------------------------

vpn_add_client() {
    local name=$1 ID PUB PSK PRIV
    vpn_valid_name "$name" || die "Nom de client invalide : « $name » (lettres, chiffres, - et _, 15 caractères max)."
    [[ ! -e $VPN_CLIENTS/$name.env ]] || die "Le client « $name » existe déjà."
    if ! ID=$(vpn_next_id); then die "Nombre maximum de clients atteint ($VPN_MAX)."; fi
    PRIV=$(wg genkey)
    PUB=$(printf '%s' "$PRIV" | wg pubkey)
    PSK=$(wg genpsk)
    (umask 077 && conf_write "$VPN_CLIENTS/$name.env" ID PUB PSK PRIV)
    vpn_apply
    ok "Client « $name » créé : IP $VPN_NET.$((ID + 1)), port ouvert $((VPN_PORT_BASE + ID)), fichier $VPN_CLIENTS/$name.conf"
}

vpn_remove_client() {
    local name=$1
    vpn_require_client "$name"
    rm -f "$VPN_CLIENTS/$name.env" "$VPN_CLIENTS/$name.conf"
    vpn_apply
    ok "Client « $name » révoqué : sa clé ne peut plus se connecter."
}

vpn_show_client() {
    local name=$1 ID PUB PSK PRIV port
    vpn_require_client "$name"
    # shellcheck source=/dev/null
    . "$VPN_CLIENTS/$name.env"
    port=$((VPN_PORT_BASE + ID))
    titre
    section "CLIENT VPN « $name »"
    qrencode -t ansiutf8 <"$VPN_CLIENTS/$name.conf"
    cat <<EOF

Téléphone  : application WireGuard → « + » → « Scanner un code QR ».
Ordinateur : application WireGuard → « Importer » avec le fichier
             $VPN_CLIENTS/$name.conf, à récupérer par un lien de
             téléchargement :  finalcut vpn share $name

Port ouvert pour ce client : ${C_BLD}$port${C_END} (TCP et UDP)
  Les connexions entrantes sur $VPN_ENDPOINT:$port arrivent chez ce client
  quand il est connecté : mettez ce port dans votre logiciel torrent.

EOF
    if ((FC_INTERACTIVE)); then
        if confirm "Afficher le contenu du fichier (pour un copier-coller) ?" n; then
            echo
            cat "$VPN_CLIENTS/$name.conf"
            echo
        fi
    else
        cat "$VPN_CLIENTS/$name.conf"
    fi
}

# Lien de téléchargement à usage unique du fichier d'un client (voir share.sh)
vpn_share_client() {
    local name=$1
    vpn_require_client "$name"
    share_require "Sans seedbox :  finalcut vpn show $name  (QR code, ou contenu à copier-coller)."
    share_create "$VPN_CLIENTS/$name.conf" "$name.conf" "Configuration VPN « $name »" \
        "<li>Ordinateur : application WireGuard → importer un tunnel depuis un fichier → choisissez ce fichier.</li>
<li>Téléphone : application WireGuard → « + » → importer depuis un fichier.</li>" \
        "Ce fichier contient la clé secrète de « $name » : supprimez-le une fois importé."
}

# vpn_pick_client VAR "Question" — liste numérotée, choix par numéro ou par nom
vpn_pick_client() {
    local _pc_var=$1 _pc_q=$2 _pc_rep _pc_i=0 _pc_n
    local -a _pc_names
    mapfile -t _pc_names < <(vpn_client_names)
    if ((${#_pc_names[@]} == 0)); then
        warn "Aucun client pour l'instant."
        return 1
    fi
    for _pc_n in "${_pc_names[@]}"; do
        _pc_i=$((_pc_i + 1))
        printf '  %2d) %s\n' "$_pc_i" "$_pc_n"
    done
    echo
    ask _pc_rep "$_pc_q (numéro ou nom, vide pour annuler)" ""
    [[ -n $_pc_rep ]] || return 1
    if [[ ! $_pc_rep =~ ^[A-Za-z0-9_-]{1,15}$ ]]; then
        warn "Nom invalide."
        return 1
    fi
    if [[ $_pc_rep =~ ^[0-9]+$ ]] && ((_pc_rep >= 1 && _pc_rep <= ${#_pc_names[@]})); then
        _pc_rep=${_pc_names[_pc_rep - 1]}
    fi
    if [[ ! -e $VPN_CLIENTS/$_pc_rep.env ]]; then
        warn "Client « $_pc_rep » introuvable."
        return 1
    fi
    printf -v "$_pc_var" '%s' "$_pc_rep"
}

vpn_ask_client_name() {
    local _cn_var=$1 _cn_def=${2-} _cn_name
    while true; do
        ask _cn_name "Nom du client (ex. telephone, pc-salon)" "$_cn_def"
        if ! vpn_valid_name "$_cn_name"; then
            warn "Lettres, chiffres, - et _ uniquement, 15 caractères maximum."
        elif [[ -e $VPN_CLIENTS/$_cn_name.env ]]; then
            warn "Le client « $_cn_name » existe déjà."
        else
            break
        fi
    done
    printf -v "$_cn_var" '%s' "$_cn_name"
}

# Tableau des clients avec l'état de leur connexion
vpn_status_table() {
    local -A hs=() rx=() tx=()
    local pk _psk _ep _ips h r t _ka f name ID PUB PSK PRIV now last ago
    if systemctl is-active --quiet "wg-quick@$VPN_IF"; then
        while IFS=$'\t' read -r pk _psk _ep _ips h r t _ka; do
            hs[$pk]=$h
            rx[$pk]=$r
            tx[$pk]=$t
        done < <(wg show "$VPN_IF" dump | tail -n +2)
    fi
    now=$(date +%s)
    printf '%s%-16s %-12s %-7s %-20s %s%s\n' "$C_BLD" "CLIENT" "IP" "PORT" "REÇU / ENVOYÉ" "DERNIÈRE CONNEXION" "$C_END"
    for f in "$VPN_CLIENTS"/*.env; do
        [[ -e $f ]] || continue
        name=${f##*/}
        name=${name%.env}
        # shellcheck source=/dev/null
        . "$f"
        last=${hs[$PUB]:-0}
        if ((last == 0)); then
            ago="${C_DIM}jamais${C_END}"
        else
            ago=$((now - last))
            if ((ago < 180)); then
                ago="${C_GRN}connecté${C_END} (${ago} s)"
            elif ((ago < 3600)); then
                ago="il y a $((ago / 60)) min"
            elif ((ago < 86400)); then
                ago="il y a $((ago / 3600)) h"
            else
                ago="il y a $((ago / 86400)) j"
            fi
        fi
        printf '%-16s %-12s %-7s %-20s %s\n' "$name" "$VPN_NET.$((ID + 1))" "$((VPN_PORT_BASE + ID))" \
            "$(numfmt --to=iec --suffix=o "${rx[$PUB]:-0}") / $(numfmt --to=iec --suffix=o "${tx[$PUB]:-0}")" "$ago"
    done
}

# --- Réglages, installation, désinstallation ----------------------------------

vpn_ask_dns() {
    local c
    echo
    echo "DNS utilisés par les clients du VPN :"
    echo "  1) Quad9      — bloque les domaines malveillants (fondation suisse)"
    echo "  2) Cloudflare — généralement le plus rapide"
    echo "  3) Autre      — saisie manuelle"
    while true; do
        ask c "Votre choix [1-3]" "1"
        case $c in
            1)
                VPN_DNS=$(vpn_dns_value quad9)
                return 0
                ;;
            2)
                VPN_DNS=$(vpn_dns_value cloudflare)
                return 0
                ;;
            3)
                ask VPN_DNS "Adresse(s) IP des DNS, séparées par des virgules" "$VPN_DNS"
                if vpn_valid_dns "$VPN_DNS"; then return 0; fi
                warn "Format attendu : 9.9.9.9, 149.112.112.112"
                ;;
        esac
    done
}

# Questions communes à l'installation et à la modification des réglages
vpn_ask_settings() {
    while true; do
        ask VPN_ENDPOINT "Adresse publique du serveur (IP ou nom de domaine)" "$VPN_ENDPOINT"
        if ! vpn_valid_endpoint "$VPN_ENDPOINT"; then
            warn "Adresse invalide."
            continue
        fi
        ask VPN_PORT "Port UDP du VPN" "$VPN_PORT"
        if ! valid_port "$VPN_PORT"; then
            warn "Port invalide (1 à 65535)."
            continue
        fi
        if ! vpn_port_free "$VPN_PORT"; then
            warn "Le port UDP $VPN_PORT est déjà utilisé sur ce serveur."
            continue
        fi
        vpn_ask_dns
        printf '\nRécapitulatif :\n  Adresse : %s\n  Port    : %s/udp\n  DNS     : %s\n  Sortie  : interface %s\n\n' \
            "$VPN_ENDPOINT" "$VPN_PORT" "$VPN_DNS" "${VPN_NIC:-?}"
        if confirm "C'est bon ?" o; then return 0; fi
    done
}

vpn_install_interactive() {
    local first
    titre
    section "INSTALLATION DU VPN WIREGUARD"
    vpn_check_kernel
    base_setup
    echo
    printf "Recherche de l'adresse IP publique… "
    VPN_ENDPOINT=$(public_ipv4)
    echo "${VPN_ENDPOINT:-introuvable}"
    # si la seedbox a un nom de domaine, il fait une meilleure adresse
    if sb_installed && [[ -n $SB_DOMAIN ]] && ! is_ipv4 "$SB_DOMAIN"; then VPN_ENDPOINT=$SB_DOMAIN; fi
    VPN_NIC=$(default_iface)
    echo
    vpn_ask_settings
    echo
    vpn_ask_client_name first "client1"
    echo
    vpn_apply
    vpn_add_client "$first"
    echo
    ok "VPN installé — aucun redémarrage nécessaire."
    pause
    vpn_show_client "$first"
    pause
}

# Installation (ou remise en ordre) à partir d'un fichier --config. Relancée
# avec le même fichier, elle ne change rien : les clients existants sont gardés.
vpn_install_config() {
    local name port dns
    local -a names=()
    vpn_check_kernel
    base_setup
    VPN_ENDPOINT=$(cfg VPN_ENDPOINT "$VPN_ENDPOINT")
    if [[ -z $VPN_ENDPOINT ]]; then VPN_ENDPOINT=$(public_ipv4); fi
    vpn_valid_endpoint "$VPN_ENDPOINT" || die "VPN_ENDPOINT invalide : « $VPN_ENDPOINT »"
    port=$(cfg VPN_PORT "$VPN_PORT")
    valid_port "$port" || die "VPN_PORT invalide : « $port »"
    vpn_port_free "$port" || die "Le port UDP $port est déjà utilisé sur ce serveur."
    VPN_PORT=$port
    dns=$(vpn_dns_value "$(cfg VPN_DNS "$VPN_DNS")")
    vpn_valid_dns "$dns" || die "VPN_DNS invalide : « $dns »"
    VPN_DNS=$dns
    IFS=', ' read -r -a names <<<"$(cfg VPN_CLIENTS)"
    for name in "${names[@]}"; do
        vpn_valid_name "$name" || die "VPN_CLIENTS : nom invalide « $name »"
    done

    vpn_apply
    for name in "${names[@]}"; do
        if [[ ! -e $VPN_CLIENTS/$name.env ]]; then vpn_add_client "$name"; fi
    done
    ok "VPN prêt : $VPN_ENDPOINT:$VPN_PORT/udp, $(vpn_count_clients) client(s) dans $VPN_CLIENTS/"
}

vpn_change_settings() {
    titre
    section "RÉGLAGES DU VPN"
    warn "Après modification, chaque client devra réimporter sa configuration."
    echo
    vpn_ask_settings
    vpn_apply
    ok "Réglages enregistrés. Réaffichez les clients pour récupérer leurs nouveaux QR codes."
}

vpn_uninstall() {
    titre
    section "DÉSINSTALLATION DU VPN"
    warn "Tous les clients ($(vpn_count_clients)) seront supprimés définitivement."
    if ! confirm "Désinstaller le VPN ?" n; then return 0; fi
    echo
    systemctl disable --now "wg-quick@$VPN_IF" >>"$FC_LOG" 2>&1 || true
    nft delete table ip finalcut >>"$FC_LOG" 2>&1 || true
    rm -rf "${VPN_DIR:?}" "$VPN_CONF" "$WG_CONF" "$VPN_SYSCTL"
    net_hardening_cleanup
    apt_purge wireguard-tools qrencode
    fw_refresh
    ok "VPN désinstallé (le routage IPv4 sera désactivé au prochain redémarrage)."
    pause
}

vpn_menu() {
    local choix name
    while true; do
        vpn_load
        vpn_installed || return 0
        titre
        section "GESTION DU VPN"
        printf '  État    : %s\n' "$(svc_state "wg-quick@$VPN_IF")"
        printf '  Adresse : %s:%s (UDP)\n' "$VPN_ENDPOINT" "$VPN_PORT"
        printf '  Clients : %s (%s connecté(s) en ce moment)\n\n' "$(vpn_count_clients)" "$(vpn_connected_count)"
        cat <<EOF
1) Ajouter un client
2) Afficher un client (QR code, fichier)
3) Lien de téléchargement d'un client (usage unique)
4) Révoquer un client
5) Clients et connexions

6) Modifier les réglages (adresse, port, DNS)
7) Redémarrer le VPN
8) Désinstaller le VPN

Q) Retour
EOF
        echo
        ask choix "Votre choix" ""
        case ${choix,,} in
            1)
                titre
                section "AJOUTER UN CLIENT"
                if (($(vpn_count_clients) >= VPN_MAX)); then
                    warn "Nombre maximum de clients atteint ($VPN_MAX)."
                else
                    vpn_ask_client_name name ""
                    vpn_add_client "$name"
                    pause
                    vpn_show_client "$name"
                fi
                pause
                ;;
            2)
                titre
                section "AFFICHER UN CLIENT"
                if vpn_pick_client name "Client à afficher"; then vpn_show_client "$name"; fi
                pause
                ;;
            3)
                titre
                section "LIEN DE TÉLÉCHARGEMENT"
                if ! sb_installed; then
                    warn "Les liens passent par le site HTTPS de la seedbox, qui n'est pas installée :"
                    warn "utilisez « Afficher un client » (QR code, ou contenu à copier-coller)."
                elif vpn_pick_client name "Client à envoyer"; then
                    vpn_share_client "$name"
                fi
                pause
                ;;
            4)
                titre
                section "RÉVOQUER UN CLIENT"
                if vpn_pick_client name "Client à révoquer" \
                    && confirm "Révoquer définitivement « $name » ?" n; then
                    vpn_remove_client "$name"
                fi
                pause
                ;;
            5)
                titre
                section "CLIENTS ET CONNEXIONS"
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
                run "Redémarrage du VPN" systemctl restart "wg-quick@$VPN_IF"
                pause
                ;;
            8) vpn_uninstall ;;
            q) return 0 ;;
        esac
    done
}

vpn_main() {
    vpn_load
    if vpn_installed && (($(vpn_count_clients) == 0)) && ! systemctl is-active --quiet "wg-quick@$VPN_IF"; then
        # réglages enregistrés mais ni client ni service : installation interrompue
        warn "L'installation précédente du VPN s'est interrompue : on la reprend."
        pause
        vpn_install_interactive
    elif vpn_installed; then
        vpn_menu
    else
        vpn_install_interactive
    fi
}

# finalcut vpn <commande> …
vpn_cli() {
    local cmd=${1-}
    if (($#)); then shift; fi
    case $cmd in
        "")
            require_tty
            vpn_main
            ;;
        install)
            if [[ -n $FC_CONFIG ]]; then
                config_load "$FC_CONFIG"
                vpn_install_config
                if [[ $(cfg FIREWALL) == yes ]]; then fw_enable; fi
            else
                require_tty
                if vpn_installed; then die "Le VPN est déjà installé (finalcut vpn pour le gérer)."; fi
                vpn_install_interactive
            fi
            ;;
        add)
            vpn_require_installed
            [[ -n ${1-} ]] || die "Usage : finalcut vpn add NOM [--qr]"
            vpn_add_client "$1"
            if ((FC_QR)); then vpn_show_client "$1"; fi
            ;;
        remove)
            vpn_require_installed
            [[ -n ${1-} ]] || die "Usage : finalcut vpn remove NOM --yes"
            vpn_require_client "$1"
            if confirm "Révoquer définitivement « $1 » ?" n; then vpn_remove_client "$1"; fi
            ;;
        list)
            vpn_require_installed
            vpn_status_table
            ;;
        show)
            vpn_require_installed
            [[ -n ${1-} ]] || die "Usage : finalcut vpn show NOM"
            vpn_show_client "$1"
            ;;
        share)
            vpn_require_installed
            [[ -n ${1-} ]] || die "Usage : finalcut vpn share NOM"
            vpn_share_client "$1"
            ;;
        restart)
            vpn_require_installed
            run "Redémarrage du VPN" systemctl restart "wg-quick@$VPN_IF"
            ;;
        uninstall)
            vpn_require_installed
            vpn_uninstall
            ;;
        *) die "Commande inconnue : vpn $cmd   (aide : finalcut help)" ;;
    esac
}
