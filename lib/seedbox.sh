#!/usr/bin/env bash
# =============================================================================
#  finalcut — module seedbox
#
#  Transmission  : n'écoute que sur 127.0.0.1, protégé par son propre mot de
#                  passe, et enfermé par systemd (ProtectSystem=strict…)
#  nginx         : seule porte d'entrée, HTTPS + mot de passe (même identifiant)
#  Let's Encrypt : validation « webroot » par nginx, donc le renouvellement
#                  automatique fonctionne (certbot.timer) ; repli auto-signé
#  SFTP          : remplace le FTP ; utilisateur enfermé dans le dossier des
#                  données, sans shell ni tunnel ; mot de passe et/ou clés SSH
#  fail2ban      : SSH/SFTP, mot de passe web, récidivistes (pare-feu nftables)
#
#  Les mots de passe ne sont jamais stockés en clair : seules leurs empreintes
#  (système, nginx, Transmission) sont gardées dans /etc/finalcut/seedbox.secrets,
#  ce qui permet de tout réappliquer ou restaurer sans redemander le mot de passe.
#
#  Dossiers : <données>/complete    téléchargements terminés (et en partage)
#             <données>/incomplete  téléchargements en cours
#             <données>/watch       déposez-y un .torrent, il démarre tout seul
#             <données>/documents   espace personnel (Transmission n'y a pas accès)
# =============================================================================

SB_CONF="$FC_ETC/seedbox.conf"
SB_SECRETS="$FC_ETC/seedbox.secrets"
SB_SSL="$FC_ETC/ssl"
SB_NGINX_SITE="/etc/nginx/sites-available/finalcut"
SB_NGINX_LINK="/etc/nginx/sites-enabled/finalcut"
SB_HTPASSWD="/etc/nginx/finalcut.htpasswd"
SB_SSHD="/etc/ssh/sshd_config.d/finalcut-seedbox.conf"
SB_KEYS_DIR="/etc/ssh/finalcut_authorized_keys"
SB_F2B_JAIL="/etc/fail2ban/jail.d/finalcut.local"
SB_F2B_MAIN="/etc/fail2ban/fail2ban.d/finalcut.local"
SB_TR_DROPIN="/etc/systemd/system/transmission-daemon.service.d/finalcut.conf"
SB_WEBROOT="/var/www/letsencrypt"
SB_LE_NAME="finalcut"
SB_LE_DIR="/etc/letsencrypt/live/$SB_LE_NAME"
SB_TR_USER="debian-transmission"
SB_RPC_PORT=9091
# les clients VPN utilisent 60001 et suivants
SB_PEER_PORT=60000
# mot de passe en cours de changement (jamais écrit sur le disque)
SB_PASS=""

# Réglages imposés à Transmission. DHT, PEX, LPD et uTP sont coupés : réglage
# adapté aux trackers privés (modifiable dans l'interface web, Préférences).
read -r -d '' SB_TR_FILTER <<'JQ' || true
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

sb_load() {
    SB_USER=""
    SB_DOMAIN=""
    SB_DATA=""
    # selfsigned | letsencrypt | staging : certificat actuellement servi
    SB_CERT="selfsigned"
    # auto | yes | no : faut-il demander un certificat Let's Encrypt ?
    SB_LETSENCRYPT="auto"
    # production | staging : serveurs Let's Encrypt utilisés
    SB_ACME="production"
    # yes | no : le SFTP accepte-t-il le mot de passe (sinon clés SSH seules)
    SB_SFTP_PASSWORD="yes"
    SB_HASH_SYS=""
    SB_HASH_WEB=""
    SB_HASH_TR=""
    conf_read "$SB_CONF"
    conf_read "$SB_SECRETS"
}

sb_save() {
    conf_write "$SB_CONF" SB_USER SB_DOMAIN SB_DATA SB_CERT SB_LETSENCRYPT SB_ACME SB_SFTP_PASSWORD
}

sb_installed() { [[ -f $SB_CONF ]]; }

sb_require_installed() {
    sb_installed || die "La seedbox n'est pas installée :  finalcut seedbox install"
}

# Fichier de réglages réel de Transmission (Debian le place dans /etc)
sb_tr_settings() {
    local link=/var/lib/transmission-daemon/.config/transmission-daemon/settings.json
    if [[ -e $link ]]; then readlink -f "$link"; else printf '%s' /etc/transmission-daemon/settings.json; fi
}

sb_cert_label() {
    case $SB_CERT in
        letsencrypt) printf "Let's Encrypt" ;;
        staging) printf "Let's Encrypt (serveur de test, non reconnu par les navigateurs)" ;;
        *) printf 'auto-signé' ;;
    esac
}

# --- Vérifications ------------------------------------------------------------

sb_valid_user() { [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }

sb_valid_domain() {
    [[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || is_ipv4 "$1"
}

# Adresses IPv4 d'un nom, demandées à un DNS public (pas au cache local)
sb_dns_ips() {
    dig +short +time=3 +tries=2 A "$1" @9.9.9.9 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' || true
}

sb_dns_points_here() {
    [[ -n $2 ]] && grep -qxF "$2" <<<"$(sb_dns_ips "$1")"
}

# Propose un nom qui pointe déjà sur ce serveur : nom de la machine, ou nom
# inverse fourni par l'hébergeur (ex. vps-1234abcd.vps.ovh.net). Sinon l'IP.
sb_guess_domain() {
    local ip=$1 cand ptr
    ptr=$(dig +short -x "$ip" @9.9.9.9 2>/dev/null | sed -n '1s/\.$//p' || true)
    for cand in "$(hostname --fqdn 2>/dev/null || true)" "$ptr"; do
        cand=${cand,,}
        if [[ -n $cand ]] && ! is_ipv4 "$cand" && sb_valid_domain "$cand" \
            && sb_dns_points_here "$cand" "$ip"; then
            printf '%s' "$cand"
            return 0
        fi
    done
    printf '%s' "$ip"
}

# Plus grande partition locale ; si c'est « / », on utilise /srv/seedbox
sb_default_data() {
    local mnt
    mnt=$(df -lP -x tmpfs -x devtmpfs -x overlay -x squashfs -x vfat 2>/dev/null \
        | awk 'NR > 1 { print $4, $6 }' | sort -nr | awk 'NR == 1 { print $2 }' || true)
    case $mnt in
        "" | / | /boot*) printf '/srv/seedbox' ;;
        *) printf '%s/seedbox' "${mnt%/}" ;;
    esac
}

# sshd exige que chaque dossier du chemin du chroot SFTP appartienne à root
# et ne soit modifiable par personne d'autre.
sb_check_data_path() {
    local p=$1 cur="" part owner mode
    local -a parts
    if [[ ! $p =~ ^(/[A-Za-z0-9._-]+)+$ || $p == *..* ]]; then
        warn "Chemin invalide : /dossier/sous-dossier (lettres, chiffres, . _ -)."
        return 1
    fi
    case $p in
        /bin | /boot | /dev | /etc | /home | /lib | /lib64 | /media | /mnt | /opt | /proc | /root | /run | /sbin | /srv | /sys | /tmp | /usr | /var)
            warn "Choisissez un sous-dossier, pas un dossier système (ex. $p/seedbox)."
            return 1
            ;;
    esac
    IFS=/ read -r -a parts <<<"${p#/}"
    for part in "${parts[@]}"; do
        cur+="/$part"
        # la suite sera créée par le script (root, 755)
        [[ -e $cur ]] || break
        if [[ ! -d $cur ]]; then
            warn "$cur existe mais n'est pas un dossier."
            return 1
        fi
        read -r owner mode < <(stat -L -c '%u %a' "$cur")
        if ((owner != 0 || (8#$mode & 8#022))); then
            warn "$cur doit appartenir à root et n'être modifiable que par lui (exigence du SFTP enfermé)."
            return 1
        fi
    done
    return 0
}

sb_check_web_ports() {
    local out
    out=$(ss -Hltnp '( sport = :80 or sport = :443 )' 2>/dev/null || true)
    if [[ -n $out && $out != *nginx* ]]; then
        die "Les ports 80/443 sont déjà utilisés par un autre logiciel :
$out
  Arrêtez-le (apache2 par exemple) avant d'installer la seedbox."
    fi
}

# --- Mots de passe (empreintes uniquement) -----------------------------------

# Transmission stocke « { » + sha1(mot de passe + sel) en hexadécimal + sel de
# 8 caractères. On le calcule ici : le mot de passe n'est jamais écrit en clair.
sb_tr_hash() {
    local salt="" s sum
    while ((${#salt} < 8)); do
        s=$(openssl rand -base64 12)
        salt+=${s//[^A-Za-z0-9]/}
    done
    salt=${salt:0:8}
    sum=$(printf '%s%s' "$1" "$salt" | sha1sum)
    printf '{%s%s' "${sum%% *}" "$salt"
}

# Calcule et enregistre les trois empreintes de SB_PASS (l'utilisateur doit exister)
sb_hash_password() {
    # printf est interne à bash : le mot de passe n'apparaît pas dans « ps »
    printf '%s:%s\n' "$SB_USER" "$SB_PASS" | chpasswd
    SB_HASH_SYS=$(getent shadow "$SB_USER" | cut -d: -f2)
    SB_HASH_WEB=$(printf '%s\n' "$SB_PASS" | openssl passwd -6 -stdin)
    SB_HASH_TR=$(sb_tr_hash "$SB_PASS")
    conf_write "$SB_SECRETS" SB_HASH_SYS SB_HASH_WEB SB_HASH_TR
}

# Le mot de passe donné est-il déjà celui enregistré ? (relance idempotente)
sb_password_matches() {
    local salt calc
    [[ $SB_HASH_WEB == '$6$'* ]] || return 1
    salt=${SB_HASH_WEB#\$6\$}
    salt=${salt%%\$*}
    calc=$(printf '%s\n' "$1" | openssl passwd -6 -salt "$salt" -stdin)
    [[ $calc == "$SB_HASH_WEB" ]]
}

# --- Questions (mode interactif) -------------------------------------------------

sb_ask_user() {
    local current=${1-} name
    while true; do
        ask name "Nom d'utilisateur (web et SFTP)" "${SB_USER:-lancelot}"
        if ! sb_valid_user "$name"; then
            warn "Minuscules, chiffres, - et _ uniquement (32 caractères maximum)."
        elif [[ $name != "$current" ]] && id "$name" &>/dev/null; then
            warn "« $name » existe déjà sur ce système : choisissez un autre nom."
        else
            break
        fi
    done
    FC_NEWUSER=$name
    ask_password SB_PASS
}

# Demande le nom de domaine et vérifie qu'il pointe bien sur ce serveur.
# Règle SB_LETSENCRYPT : auto si Let's Encrypt a une chance, sinon no.
sb_ask_domain() {
    local ip=$1 ips c
    cat <<EOF
Nom de domaine de la seedbox. Sans domaine à vous, l'hébergeur en fournit
souvent un (ex. vps-1234abcd.vps.ovh.net). À défaut, entrez l'adresse IP :
un certificat auto-signé sera utilisé (alerte du navigateur à accepter).

EOF
    while true; do
        ask SB_DOMAIN "Nom de domaine ou IP" "$SB_DOMAIN"
        SB_DOMAIN=${SB_DOMAIN,,}
        SB_DOMAIN=${SB_DOMAIN#http://}
        SB_DOMAIN=${SB_DOMAIN#https://}
        SB_DOMAIN=${SB_DOMAIN%/}
        if ! sb_valid_domain "$SB_DOMAIN"; then
            warn "Nom de domaine invalide."
            continue
        fi
        if is_ipv4 "$SB_DOMAIN"; then
            SB_LETSENCRYPT=no
            return 0
        fi
        ips=$(sb_dns_ips "$SB_DOMAIN")
        if [[ -z $ips ]]; then
            warn "« $SB_DOMAIN » ne pointe vers aucune adresse IPv4."
        elif ! grep -qxF "$ip" <<<"$ips"; then
            warn "« $SB_DOMAIN » pointe vers ${ips//$'\n'/, } et non vers ce serveur ($ip)."
        else
            ok "« $SB_DOMAIN » pointe bien vers ce serveur ($ip)."
            SB_LETSENCRYPT=auto
            return 0
        fi
        echo "  Let's Encrypt ne pourra pas délivrer de certificat pour ce nom."
        echo "  (après une modification DNS, comptez de quelques minutes à quelques heures)"
        echo "  R) Recommencer    C) Continuer avec un certificat auto-signé"
        ask c "Votre choix" "R"
        if [[ ${c,,} == c ]]; then
            SB_LETSENCRYPT=no
            return 0
        fi
    done
}

# --- Application (idempotente) ---------------------------------------------------

sb_apply_user() {
    local cur
    if ! id "$SB_USER" &>/dev/null; then
        run "Création de l'utilisateur $SB_USER" useradd --no-create-home --home-dir / \
            --shell /usr/sbin/nologin --user-group --groups "$SB_TR_USER" \
            --comment "finalcut seedbox" "$SB_USER"
    fi
    if [[ " $(id -nG "$SB_USER") " != *" $SB_TR_USER "* ]]; then
        usermod -aG "$SB_TR_USER" "$SB_USER"
    fi
    if [[ -n $SB_PASS ]]; then
        sb_hash_password
    elif [[ -z $SB_HASH_SYS || -z $SB_HASH_WEB || -z $SB_HASH_TR ]]; then
        die "Aucun mot de passe connu pour $SB_USER : définissez-en un avec  finalcut seedbox password"
    else
        cur=$(getent shadow "$SB_USER" | cut -d: -f2)
        if [[ $cur != "$SB_HASH_SYS" ]]; then
            printf '%s:%s\n' "$SB_USER" "$SB_HASH_SYS" | chpasswd -e
        fi
    fi
}

sb_apply_dirs() {
    install -d -m 755 -o root -g root "$SB_DATA"
    # setgid (le 2 de 2775) : tout ce qui est créé dedans appartient au groupe de
    # Transmission, donc l'utilisateur SFTP peut lire et supprimer les fichiers.
    install -d -m 2775 -o "$SB_TR_USER" -g "$SB_TR_USER" \
        "$SB_DATA/complete" "$SB_DATA/incomplete" "$SB_DATA/watch"
    install -d -m 700 -o "$SB_USER" -g "$SB_USER" "$SB_DATA/documents"
}

sb_tr_desired() {
    jq -n --arg dl "$SB_DATA/complete" --arg inc "$SB_DATA/incomplete" \
        --arg watch "$SB_DATA/watch" --arg user "$SB_USER" --arg hash "$SB_HASH_TR" \
        --argjson rpcport "$SB_RPC_PORT" --argjson peerport "$SB_PEER_PORT" "$SB_TR_FILTER"
}

# Les réglages voulus sont-ils déjà en place ? (« umask » ignoré : Transmission
# le réécrit à sa façon selon les versions)
sb_tr_uptodate() {
    [[ -s $1 ]] || return 1
    jq -e --argjson d "$2" '. as $c | $d | del(.umask) | to_entries | all(.value == $c[.key])' "$1" &>/dev/null
}

# Durcissement systemd : si Transmission était compromis, il ne pourrait écrire
# que dans ses propres dossiers et dans celui des téléchargements.
sb_gen_tr_dropin() {
    local home=yes
    case $SB_DATA in
        /home/* | /root/* | /run/user/*) home=no ;;
    esac
    cat <<EOF
# Généré par finalcut — Transmission enfermé par systemd
[Service]
UMask=0002
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=-/var/lib/transmission-daemon -/etc/transmission-daemon -$SB_DATA
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

sb_apply_transmission() {
    local tr desired restart=0
    tr=$(sb_tr_settings)
    desired=$(sb_tr_desired)
    install -d -m 755 "${SB_TR_DROPIN%/*}"
    if write_if_changed "$SB_TR_DROPIN" 644 < <(sb_gen_tr_dropin); then
        run "Rechargement de systemd" systemctl daemon-reload
        restart=1
    fi
    if ! sb_tr_uptodate "$tr" "$desired"; then
        # Transmission réécrit ses réglages en s'arrêtant : on modifie à l'arrêt
        run "Arrêt de Transmission" systemctl stop transmission-daemon
        [[ -s $tr ]] || printf '{}\n' >"$tr"
        if ! jq --argjson d "$desired" '. + $d' "$tr" >"$tr.tmp"; then
            rm -f "$tr.tmp"
            die "Impossible de lire $tr (JSON invalide ?)."
        fi
        # « cat > » conserve le fichier (Debian y pointe par un lien)
        cat "$tr.tmp" >"$tr"
        rm -f "$tr.tmp"
        chown "$SB_TR_USER:$SB_TR_USER" "$tr"
        chmod 600 "$tr"
        restart=1
    fi
    systemctl enable --quiet transmission-daemon 2>/dev/null || true
    if ((restart)) || ! systemctl is-active --quiet transmission-daemon; then
        run "Démarrage de Transmission" systemctl restart transmission-daemon
    fi
}

sb_apply_htpasswd() {
    write_if_changed "$SB_HTPASSWD" 640 root:www-data < <(printf '%s:%s\n' "$SB_USER" "$SB_HASH_WEB") || true
}

# Certificat auto-signé de secours, recréé seulement s'il ne correspond plus
sb_selfsigned_ensure() {
    local san="DNS:$SB_DOMAIN" check=""
    if is_ipv4 "$SB_DOMAIN"; then san="IP:$SB_DOMAIN"; fi
    install -d -m 700 "$SB_SSL"
    if [[ -s $SB_SSL/selfsigned.crt && -s $SB_SSL/selfsigned.key ]]; then
        if is_ipv4 "$SB_DOMAIN"; then
            check=$(openssl x509 -in "$SB_SSL/selfsigned.crt" -noout -checkip "$SB_DOMAIN" 2>/dev/null || true)
        else
            check=$(openssl x509 -in "$SB_SSL/selfsigned.crt" -noout -checkhost "$SB_DOMAIN" 2>/dev/null || true)
        fi
        [[ $check == *"does match"* ]] && return 0
    fi
    run "Création d'un certificat auto-signé (solution de secours)" \
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
        -subj "/CN=$SB_DOMAIN" -addext "subjectAltName=$san" \
        -keyout "$SB_SSL/selfsigned.key" -out "$SB_SSL/selfsigned.crt"
}

# Le certificat Let's Encrypt existant est-il bien pour ce nom ?
sb_le_matches_domain() {
    local check
    [[ -e $SB_LE_DIR/cert.pem ]] || return 1
    check=$(openssl x509 -in "$SB_LE_DIR/cert.pem" -noout -checkhost "$SB_DOMAIN" 2>/dev/null || true)
    [[ $check == *"does match"* ]]
}

# … et utilisable pour le type demandé (production | staging), encore valide 1 jour ?
sb_le_usable() {
    local issuer
    sb_le_matches_domain || return 1
    openssl x509 -in "$SB_LE_DIR/cert.pem" -noout -checkend 86400 &>/dev/null || return 1
    issuer=$(openssl x509 -in "$SB_LE_DIR/cert.pem" -noout -issuer 2>/dev/null || true)
    if [[ $issuer == *STAGING* ]]; then [[ $1 == staging ]]; else [[ $1 == production ]]; fi
}

sb_cert_mode() {
    if [[ $SB_ACME == staging ]]; then printf staging; else printf letsencrypt; fi
}

# Demande le certificat Let's Encrypt. Code 1 en cas d'échec.
sb_letsencrypt() {
    local -a extra=()
    install -d -m 755 "$SB_WEBROOT"
    # Certificat existant pour un autre nom ou un autre serveur : on repart de zéro
    if [[ -e $SB_LE_DIR/cert.pem ]] && ! sb_le_usable "$SB_ACME"; then
        certbot delete --cert-name "$SB_LE_NAME" --non-interactive >>"$FC_LOG" 2>&1 || true
    fi
    local label=""
    if [[ $SB_ACME == staging ]]; then
        extra=(--test-cert)
        label=" (serveur de test)"
    fi
    printf "  Demande du certificat Let's Encrypt%s pour %s… " "$label" "$SB_DOMAIN"
    printf '\n=== %(%F %T)T · certbot pour %s\n' -1 "$SB_DOMAIN" >>"$FC_LOG"
    if certbot certonly --webroot -w "$SB_WEBROOT" --cert-name "$SB_LE_NAME" -d "$SB_DOMAIN" \
        --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring \
        --deploy-hook "systemctl reload nginx" "${extra[@]}" >>"$FC_LOG" 2>&1; then
        printf '%sok%s\n' "$C_GRN" "$C_END"
        return 0
    fi
    printf '%séchec%s\n' "$C_RED" "$C_END"
    return 1
}

sb_gen_nginx() {
    local crt key hsts="" v6_80="" v6_443=""
    if [[ $SB_CERT == selfsigned ]]; then
        crt="$SB_SSL/selfsigned.crt"
        key="$SB_SSL/selfsigned.key"
    else
        crt="$SB_LE_DIR/fullchain.pem"
        key="$SB_LE_DIR/privkey.pem"
    fi
    # HSTS seulement avec un vrai certificat : sinon le navigateur interdirait
    # ensuite de passer outre l'alerte de sécurité.
    if [[ $SB_CERT == letsencrypt ]]; then
        hsts=$'\n    add_header Strict-Transport-Security "max-age=31536000" always;'
    fi
    if [[ -e /proc/net/if_inet6 ]]; then
        v6_80=$'\n    listen [::]:80;'
        v6_443=$'\n    listen [::]:443 ssl;'
    fi
    cat <<EOF
# Généré par finalcut — utilisez le menu plutôt que de modifier ce fichier.

server {
    listen 80;$v6_80
    server_name $SB_DOMAIN;

    # Validation et renouvellement Let's Encrypt
    location ^~ /.well-known/acme-challenge/ {
        root $SB_WEBROOT;
        default_type text/plain;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;$v6_443
    server_name $SB_DOMAIN;

    ssl_certificate     $crt;
    ssl_certificate_key $key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:finalcut:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    server_tokens off;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;$hsts

    auth_basic "Seedbox";
    auth_basic_user_file $SB_HTPASSWD;

    # Ajout de fichiers .torrent depuis l'interface web
    client_max_body_size 32m;
$(share_gen_nginx "${hsts//$'\n    '/$'\n        '}")

    location = / {
        return 302 /transmission/web/;
    }
    location /transmission/ {
        proxy_pass http://127.0.0.1:$SB_RPC_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
EOF
}

sb_apply_nginx() {
    local changed=0
    if write_if_changed "$SB_NGINX_SITE" 644 < <(sb_gen_nginx); then changed=1; fi
    if [[ ! -L $SB_NGINX_LINK ]]; then
        ln -sf "$SB_NGINX_SITE" "$SB_NGINX_LINK"
        changed=1
    fi
    if [[ -e /etc/nginx/sites-enabled/default || -L /etc/nginx/sites-enabled/default ]]; then
        rm -f /etc/nginx/sites-enabled/default
        changed=1
    fi
    if ((changed)) || ! systemctl is-active --quiet nginx; then
        run "Vérification de la configuration nginx" nginx -t
        run "Rechargement de nginx" systemctl reload-or-restart nginx
    fi
}

# Choisit le certificat servi : Let's Encrypt s'il est disponible ou obtenu,
# sinon le certificat auto-signé.
sb_apply_https() {
    local want=0 ip
    sb_selfsigned_ensure
    if is_ipv4 "$SB_DOMAIN" || [[ $SB_LETSENCRYPT == no ]]; then
        SB_CERT=selfsigned
    elif sb_le_usable "$SB_ACME"; then
        # certificat déjà en place (relance, restauration) : rien à demander
        SB_CERT=$(sb_cert_mode)
    else
        if [[ $SB_LETSENCRYPT == yes ]]; then
            want=1
        else
            ip=$(public_ipv4)
            if sb_dns_points_here "$SB_DOMAIN" "$ip"; then
                want=1
            else
                warn "« $SB_DOMAIN » ne pointe pas vers ce serveur ($ip) : certificat auto-signé."
            fi
        fi
        if ((want)); then
            # nginx doit déjà répondre sur le port 80 pour la validation
            if [[ $SB_CERT != selfsigned ]] && ! sb_le_matches_domain; then SB_CERT=selfsigned; fi
            sb_apply_nginx
            if sb_letsencrypt; then
                SB_CERT=$(sb_cert_mode)
                ok "Certificat Let's Encrypt installé, renouvelé automatiquement."
            elif sb_le_usable "$SB_ACME"; then
                SB_CERT=$(sb_cert_mode)
                warn "Let's Encrypt n'a pas répondu, le certificat existant (encore valide) est conservé."
            else
                SB_CERT=selfsigned
                warn "Let's Encrypt n'a pas délivré de certificat : l'auto-signé reste en place."
                cat <<EOF
  Causes fréquentes : port 80 bloqué par le pare-feu de l'hébergeur, DNS pas
  encore propagé, ou plus de 5 certificats demandés cette semaine pour ce nom
  (pour vos essais, utilisez --staging). Détails dans $FC_LOG.
  Pour réessayer :  finalcut seedbox domain $SB_DOMAIN
EOF
            fi
        else
            SB_CERT=selfsigned
        fi
    fi
    sb_apply_nginx
    # renouvellement automatique (installé avec le paquet certbot)
    if [[ $SB_CERT != selfsigned ]] && ! systemctl is-active --quiet certbot.timer; then
        run "Activation du renouvellement automatique" systemctl enable --now certbot.timer
    fi
}

sb_has_keys() { [[ -s $SB_KEYS_DIR/$SB_USER ]] && grep -q '^ssh-\|^ecdsa-\|^sk-' "$SB_KEYS_DIR/$SB_USER"; }

sb_gen_sshd() {
    cat <<EOF
# Généré par finalcut — accès SFTP de la seedbox, enfermé dans $SB_DATA
Match User $SB_USER
    ChrootDirectory $SB_DATA
    ForceCommand internal-sftp -u 0002
    AuthorizedKeysFile $SB_KEYS_DIR/%u
    PasswordAuthentication $SB_SFTP_PASSWORD
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTunnel no
EOF
}

sb_apply_sftp() {
    local t
    install -d -m 755 "$SB_KEYS_DIR"
    if [[ ! -e $SB_KEYS_DIR/$SB_USER ]]; then install -m 644 /dev/null "$SB_KEYS_DIR/$SB_USER"; fi
    if [[ $SB_SFTP_PASSWORD == no ]] && ! sb_has_keys; then
        warn "Aucune clé SSH enregistrée : le mot de passe SFTP reste autorisé."
        SB_SFTP_PASSWORD=yes
    fi
    if [[ -e $SB_SSHD ]]; then cp -p "$SB_SSHD" "$SB_SSHD.precedent"; fi
    if write_if_changed "$SB_SSHD" 644 < <(sb_gen_sshd); then
        # On ne recharge SSH que si la configuration est valide : pas de risque
        # de se retrouver enfermé dehors. Sinon, retour à la version précédente.
        if ! sshd -t >>"$FC_LOG" 2>&1; then
            if [[ -e $SB_SSHD.precedent ]]; then mv -f "$SB_SSHD.precedent" "$SB_SSHD"; else rm -f "$SB_SSHD"; fi
            die "sshd refuse la configuration générée (détails dans $FC_LOG). SSH n'a pas été modifié."
        fi
        run "Rechargement de SSH" systemctl try-reload-or-restart ssh.service
    fi
    rm -f "$SB_SSHD.precedent"

    # La règle s'applique-t-elle bien ? (Include présent, pas de AllowUsers bloquant…)
    t=$(sshd -T -C "user=$SB_USER,host=localhost,addr=127.0.0.1" 2>/dev/null || true)
    if [[ $t != *"chrootdirectory $SB_DATA"* ]]; then
        warn "La règle SFTP ne semble pas prise en compte : /etc/ssh/sshd_config doit contenir"
        warn "« Include /etc/ssh/sshd_config.d/*.conf » (présent par défaut sur Debian)."
    fi
    if [[ $t == *$'\nallowusers '* || $t == *$'\nallowgroups '* ]]; then
        warn "Votre SSH utilise AllowUsers/AllowGroups : ajoutez-y $SB_USER pour qu'il puisse se connecter."
    fi
}

sb_gen_f2b_main() {
    # Journal fichier explicite : la règle « recidive » le lit
    cat <<'EOF'
# Généré par finalcut
[DEFAULT]
logtarget = /var/log/fail2ban.log

[Definition]
logtarget = /var/log/fail2ban.log
EOF
}

sb_gen_f2b_jail() {
    cat <<'EOF'
# Généré par finalcut — protection contre les essais de mots de passe
[DEFAULT]
# La machine elle-même et les clients du VPN ne sont jamais bannis
ignoreip  = 127.0.0.1/8 ::1 10.8.0.0/24
bantime   = 1h
findtime  = 10m
maxretry  = 5
banaction = nftables-multiport
banaction_allports = nftables[type=allports]

# SSH et SFTP : 5 échecs en 10 min → banni 1 h de tous les ports, ce qui
# reste efficace même si SSH n'écoute pas sur le port 22
# (Debian 12+ n'a plus /var/log/auth.log : on lit le journal systemd)
[sshd]
enabled   = true
backend   = systemd
mode      = aggressive
banaction = %(banaction_allports)s

# Mot de passe de l'interface web
[nginx-http-auth]
enabled = true
backend = auto
port    = http,https
logpath = /var/log/nginx/error.log

# Récidive : banni 3 fois en 24 h → banni 1 semaine de tous les ports
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

sb_apply_fail2ban() {
    local changed=0
    if write_if_changed "$SB_F2B_MAIN" 644 < <(sb_gen_f2b_main); then changed=1; fi
    touch /var/log/fail2ban.log
    if write_if_changed "$SB_F2B_JAIL" 644 < <(sb_gen_f2b_jail); then changed=1; fi
    if ((changed)) || ! systemctl is-active --quiet fail2ban; then
        systemctl enable --quiet fail2ban 2>/dev/null || true
        run "Redémarrage de fail2ban" systemctl restart fail2ban
    fi
}

# Met la seedbox dans l'état décrit par /etc/finalcut (idempotent)
sb_apply() {
    apt_install transmission-daemon nginx certbot fail2ban python3-systemd bind9-dnsutils
    net_hardening_apply
    sb_apply_user
    sb_save
    # ports 80/443 ouverts avant la demande de certificat Let's Encrypt
    fw_refresh
    sb_apply_dirs
    sb_apply_transmission
    sb_apply_htpasswd
    sb_apply_https
    sb_apply_sftp
    sb_apply_fail2ban
    sb_save
}

# --- Vérification et récapitulatif ------------------------------------------------

# Requête authentifiée sans jeton de session : Transmission répond 409 si
# HTTPS, nginx et les deux mots de passe fonctionnent. Sans mot de passe
# connu, on vérifie seulement que l'accès est bien refusé (401).
sb_curl_auth() {
    local s="$SB_USER:$SB_PASS"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    printf 'user = "%s"\n' "$s"
}

sb_http_code() {
    local -a target
    if is_ipv4 "$SB_DOMAIN"; then
        target=(-H "Host: $SB_DOMAIN" "https://127.0.0.1$1")
    else
        target=(--resolve "$SB_DOMAIN:443:127.0.0.1" "https://$SB_DOMAIN$1")
    fi
    if [[ ${2-} == auth ]]; then
        sb_curl_auth | curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -K - "${target[@]}" 2>/dev/null || true
    else
        curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "${target[@]}" 2>/dev/null || true
    fi
}

sb_selftest() {
    local code="" i
    for i in 1 2 3 4 5; do
        if [[ -n $SB_PASS ]]; then code=$(sb_http_code /transmission/rpc auth); else code=$(sb_http_code /transmission/web/); fi
        # 502 : Transmission encore en train de démarrer
        [[ $code == 502 ]] || break
        sleep 2
    done
    case $code in
        409) ok "Test de connexion à l'interface web : réussi" ;;
        401)
            if [[ -n $SB_PASS ]]; then
                warn "Test de connexion : identifiants refusés (détails dans $FC_LOG)."
            else
                ok "Interface web en ligne et protégée par mot de passe"
            fi
            ;;
        502) warn "Test de connexion : nginx ne joint pas Transmission (journalctl -u transmission-daemon)." ;;
        *) warn "Test de connexion : réponse inattendue (code ${code:-aucun})." ;;
    esac
}

sb_ssh_port() {
    local t
    t=$(sshd -T 2>/dev/null || true)
    awk '$1 == "port" && !p { print $2; p = 1 }' <<<"$t"
}

sb_recap() {
    local port
    port=$(sb_ssh_port)
    cat <<EOF

${C_BLD}Interface web${C_END} : https://$SB_DOMAIN/   (certificat $(sb_cert_label))
${C_BLD}SFTP${C_END}          : $SB_DOMAIN, port ${port:-22} (FileZilla, WinSCP, Cyberduck : protocole SFTP)
                réglages prêts à importer :  finalcut seedbox sftp-config
${C_BLD}Utilisateur${C_END}   : $SB_USER
EOF
    if [[ -n $SB_PASS ]]; then
        printf '%sMot de passe%s  : %s\n' "$C_BLD" "$C_END" "$SB_PASS"
    fi
    cat <<EOF

Dossiers (vus en SFTP) :
  watch/       déposez un .torrent ici, le téléchargement démarre tout seul
  incomplete/  téléchargements en cours
  complete/    téléchargements terminés
  documents/   espace personnel

EOF
    if [[ $SB_CERT == selfsigned ]]; then
        echo "Certificat auto-signé : le navigateur affichera une alerte à accepter une fois."
        echo
    fi
    if [[ -n $SB_PASS ]]; then
        echo "Notez ces informations : le mot de passe n'est enregistré nulle part en clair."
    fi
}

# --- Fichier de connexion SFTP (FileZilla, WinSCP) ------------------------------------

# Empreinte de la clé du serveur, que le logiciel SFTP montre à la première
# connexion (ex. « SHA256:szUj…NT8 ED25519 ») : vide si introuvable
sb_host_fingerprint() {
    local f=/etc/ssh/ssh_host_ed25519_key.pub
    [[ -r $f ]] || return 0
    ssh-keygen -l -E sha256 -f "$f" 2>/dev/null | awk '{ gsub(/[()]/, "", $NF); print $2, $NF }' || true
}

# Site à importer dans FileZilla (Fichier → Importer…). Logontype 2 : le
# mot de passe est demandé à la connexion, il n'est pas dans le fichier.
sb_gen_filezilla() {
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3>
    <Servers>
        <Server>
            <Host>$SB_DOMAIN</Host>
            <Port>$1</Port>
            <Protocol>1</Protocol>
            <Type>0</Type>
            <User>$SB_USER</User>
            <Logontype>2</Logontype>
            <TimezoneOffset>0</TimezoneOffset>
            <PasvMode>MODE_DEFAULT</PasvMode>
            <MaximumMultipleConnections>0</MaximumMultipleConnections>
            <EncodingType>Auto</EncodingType>
            <BypassProxy>0</BypassProxy>
            <Name>Seedbox $SB_DOMAIN</Name>
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

# Réglages de connexion SFTP + lien vers le fichier FileZilla
sb_sftp_config() {
    local port fp url tmp keys=""
    port=$(sb_ssh_port)
    port=${port:-22}
    fp=$(sb_host_fingerprint)
    url="sftp://$SB_USER@$SB_DOMAIN:$port/"
    if [[ $SB_SFTP_PASSWORD == no ]]; then keys=" (clé SSH uniquement)"; fi
    titre
    section "CONNEXION SFTP À LA SEEDBOX"
    printf '  Protocole   : SFTP\n  Hôte        : %s\n  Port        : %s\n  Utilisateur : %s%s\n' \
        "$SB_DOMAIN" "$port" "$SB_USER" "$keys"
    if [[ -n $fp ]]; then printf '  Empreinte   : %s\n' "$fp"; fi
    cat <<EOF

WinSCP    : fenêtre de connexion → « Nouveau site », puis collez dans « Nom d'hôte » :
              $url
FileZilla : « Fichier » → « Importer… », avec le fichier du lien ci-dessous.

À la première connexion, le logiciel demande s'il peut faire confiance au
serveur : l'empreinte qu'il affiche doit être celle ci-dessus.
EOF
    if ! systemctl is-active --quiet nginx; then
        warn "nginx est arrêté : pas de lien pour FileZilla (finalcut seedbox restart)."
        return 0
    fi
    tmp=$(mktemp)
    sb_gen_filezilla "$port" >"$tmp"
    share_create "$tmp" "seedbox-filezilla.xml" "Connexion SFTP à la seedbox" \
        "<li>FileZilla : « Fichier » → « Importer… » → choisissez ce fichier. Le site « Seedbox $SB_DOMAIN » apparaît dans le gestionnaire de sites.</li>
<li>WinSCP : « Nouveau site », puis collez <code>$url</code> dans « Nom d'hôte ».</li>
<li>À la première connexion, l'empreinte du serveur doit être : <code>${fp:-inconnue}</code></li>" \
        "Le fichier ne contient pas de mot de passe : il sera demandé à la connexion."
    rm -f "$tmp"
}

# --- Clés SSH du SFTP ----------------------------------------------------------------

# Ajoute les clés publiques valides d'un fichier (- = entrée standard), sans doublon
sb_keys_import() {
    local src=$1 line tmp n=0 file="$SB_KEYS_DIR/$SB_USER"
    install -d -m 755 "$SB_KEYS_DIR"
    if [[ ! -e $file ]]; then install -m 644 /dev/null "$file"; fi
    tmp=$(mktemp)
    if [[ $src == - ]]; then cat >"$tmp"; else cat -- "$src" >"$tmp"; fi
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        [[ -z $line || $line == \#* ]] && continue
        if ! ssh-keygen -l -f - <<<"$line" &>/dev/null; then
            rm -f "$tmp"
            die "Clé SSH invalide : ${line:0:40}…"
        fi
        if ! grep -qxF -- "$line" "$file"; then
            printf '%s\n' "$line" >>"$file"
            n=$((n + 1))
        fi
    done <"$tmp"
    rm -f "$tmp"
    if ((n)); then
        ok "$n clé(s) SSH ajoutée(s) pour $SB_USER."
    else
        ok "Clé(s) déjà enregistrée(s) pour $SB_USER."
    fi
}

sb_keys_list() {
    local i=0 line
    if ! sb_has_keys; then
        echo "Aucune clé SSH enregistrée pour $SB_USER."
        return 0
    fi
    while IFS= read -r line; do
        [[ -z $line || $line == \#* ]] && continue
        i=$((i + 1))
        printf '  %2d) %s\n' "$i" "$(ssh-keygen -l -f - <<<"$line" 2>/dev/null || printf '%s' "${line:0:50}")"
    done <"$SB_KEYS_DIR/$SB_USER"
}

sb_keys_remove() {
    local num=$1 file="$SB_KEYS_DIR/$SB_USER" i=0 line tmp found=0
    [[ $num =~ ^[0-9]+$ ]] || die "Indiquez le numéro de la clé (finalcut seedbox sftp-key list)."
    tmp=$(mktemp)
    while IFS= read -r line; do
        if [[ -n $line && $line != \#* ]]; then
            i=$((i + 1))
            if ((i == num)); then
                found=1
                continue
            fi
        fi
        printf '%s\n' "$line" >>"$tmp"
    done <"$file"
    if ((!found)); then
        rm -f "$tmp"
        die "Clé n°$num introuvable."
    fi
    cat "$tmp" >"$file"
    rm -f "$tmp"
    if [[ $SB_SFTP_PASSWORD == no ]] && ! sb_has_keys; then
        SB_SFTP_PASSWORD=yes
        sb_save
        warn "Plus aucune clé : le mot de passe SFTP est de nouveau autorisé."
    fi
    sb_apply_sftp
    ok "Clé n°$num supprimée."
}

sb_set_sftp_password() {
    case $1 in
        on | yes) SB_SFTP_PASSWORD=yes ;;
        off | no)
            sb_has_keys || die "Ajoutez d'abord une clé SSH (finalcut seedbox sftp-key add FICHIER)."
            SB_SFTP_PASSWORD=no
            ;;
        *) die "Usage : finalcut seedbox sftp-password on|off" ;;
    esac
    sb_save
    sb_apply_sftp
    if [[ $SB_SFTP_PASSWORD == yes ]]; then
        ok "SFTP : mot de passe autorisé."
    else
        ok "SFTP : clés SSH uniquement (le mot de passe reste valable pour l'interface web)."
    fi
}

sb_keys_menu() {
    local choix num
    while true; do
        sb_load
        titre
        section "CLÉS SSH POUR LE SFTP"
        echo "Une clé SSH remplace avantageusement le mot de passe pour le SFTP."
        echo "Collez la clé PUBLIQUE (fichier .pub, commence par ssh-ed25519 ou ssh-rsa)."
        echo
        sb_keys_list
        echo
        printf '  Mot de passe SFTP : %s\n\n' \
            "$([[ $SB_SFTP_PASSWORD == yes ]] && printf 'autorisé' || printf 'refusé (clés uniquement)')"
        cat <<EOF
1) Ajouter une clé
2) Supprimer une clé
3) Autoriser / refuser le mot de passe pour le SFTP

Q) Retour
EOF
        echo
        ask choix "Votre choix" ""
        case ${choix,,} in
            1)
                ask num "Clé publique" ""
                if [[ -n $num ]]; then
                    sb_keys_import - <<<"$num"
                    sb_apply_sftp
                fi
                pause
                ;;
            2)
                ask num "Numéro de la clé à supprimer" ""
                if [[ -n $num ]]; then sb_keys_remove "$num"; fi
                pause
                ;;
            3)
                if [[ $SB_SFTP_PASSWORD == yes ]]; then sb_set_sftp_password off; else sb_set_sftp_password on; fi
                pause
                ;;
            q) return 0 ;;
        esac
    done
}

# --- Actions ---------------------------------------------------------------------

sb_install_interactive() {
    local ip cert
    titre
    section "INSTALLATION DE LA SEEDBOX"
    sb_check_web_ports
    base_setup
    apt_install bind9-dnsutils
    echo
    printf "Recherche de l'adresse IP publique… "
    ip=$(public_ipv4)
    echo "${ip:-introuvable}"
    SB_DOMAIN=$(sb_guess_domain "$ip")
    SB_DATA=$(sb_default_data)
    if ((FC_STAGING)); then SB_ACME=staging; fi
    echo
    while true; do
        sb_ask_user ""
        SB_USER=$FC_NEWUSER
        echo
        sb_ask_domain "$ip"
        echo
        while true; do
            ask SB_DATA "Dossier des données" "$SB_DATA"
            if sb_check_data_path "$SB_DATA"; then break; fi
        done
        cert="Let's Encrypt"
        if [[ $SB_ACME == staging ]]; then cert="Let's Encrypt (serveur de test)"; fi
        if [[ $SB_LETSENCRYPT == no ]]; then cert="auto-signé"; fi
        printf '\nRécapitulatif :\n  Utilisateur : %s\n  Adresse     : https://%s/\n  Certificat  : %s\n  Données     : %s\n\n' \
            "$SB_USER" "$SB_DOMAIN" "$cert" "$SB_DATA"
        if confirm "Lancer l'installation ?" o; then break; fi
        echo
    done
    echo
    sb_apply
    echo
    sb_selftest
    titre
    section "SEEDBOX INSTALLÉE — aucun redémarrage nécessaire"
    sb_recap
    SB_PASS=""
    echo
    pause
}

# Installation (ou remise en ordre) à partir d'un fichier --config
sb_install_config() {
    local pw pwfile ip generated=0 first=1 keys cur_user=$SB_USER
    if sb_installed; then first=0; fi
    base_setup
    apt_install bind9-dnsutils

    SB_USER=$(cfg SB_USER "${SB_USER:-lancelot}")
    sb_valid_user "$SB_USER" || die "SB_USER invalide : « $SB_USER »"
    if ((first)) && id "$SB_USER" &>/dev/null; then
        die "SB_USER : l'utilisateur « $SB_USER » existe déjà sur ce système."
    fi
    if ((!first)) && [[ $cur_user != "$SB_USER" ]]; then
        die "Renommer l'utilisateur passe par :  finalcut seedbox password --user $SB_USER"
    fi

    SB_DATA=$(cfg SB_DATA "${SB_DATA:-$(sb_default_data)}")
    sb_check_data_path "$SB_DATA" || die "SB_DATA refusé : « $SB_DATA »"

    SB_DOMAIN=$(cfg SB_DOMAIN "$SB_DOMAIN")
    SB_DOMAIN=${SB_DOMAIN,,}
    if [[ -z $SB_DOMAIN ]]; then
        ip=$(public_ipv4)
        SB_DOMAIN=$(sb_guess_domain "$ip")
    fi
    sb_valid_domain "$SB_DOMAIN" || die "SB_DOMAIN invalide : « $SB_DOMAIN »"

    SB_LETSENCRYPT=$(cfg SB_LETSENCRYPT "$SB_LETSENCRYPT")
    [[ $SB_LETSENCRYPT =~ ^(auto|yes|no)$ ]] || die "SB_LETSENCRYPT : auto, yes ou no"
    SB_ACME=$(cfg SB_ACME "$SB_ACME")
    if ((FC_STAGING)); then SB_ACME=staging; fi
    [[ $SB_ACME =~ ^(production|staging)$ ]] || die "SB_ACME : production ou staging"
    SB_SFTP_PASSWORD=$(cfg SB_SFTP_PASSWORD "$SB_SFTP_PASSWORD")
    [[ $SB_SFTP_PASSWORD =~ ^(yes|no)$ ]] || die "SB_SFTP_PASSWORD : yes ou no"

    # Mot de passe : fichier, valeur, ou généré à la première installation.
    # S'il est identique à celui déjà en place, rien n'est modifié.
    pw=$(cfg SB_PASSWORD)
    pwfile=$(cfg SB_PASSWORD_FILE)
    if [[ -n $pwfile ]]; then
        [[ -r $pwfile ]] || die "SB_PASSWORD_FILE introuvable : $pwfile"
        IFS= read -r pw <"$pwfile" || true
    fi
    if [[ -n $pw ]]; then
        ((${#pw} >= 10)) || die "Mot de passe de la seedbox : 10 caractères minimum."
        if sb_password_matches "$pw"; then SB_PASS=""; else SB_PASS=$pw; fi
    elif [[ -z $SB_HASH_WEB ]]; then
        SB_PASS=$(gen_password)
        generated=1
    fi

    keys=$(cfg SB_SSH_KEYS_FILE)
    if ((first)); then sb_check_web_ports; fi
    if [[ -n $keys ]]; then
        [[ -r $keys ]] || die "SB_SSH_KEYS_FILE introuvable : $keys"
        sb_keys_import "$keys"
    fi

    sb_apply
    sb_selftest
    sb_recap
    if ((generated)); then warn "Mot de passe généré automatiquement : notez-le, il ne sera plus affiché."; fi
    SB_PASS=""
}

# Change le mot de passe (et éventuellement le nom) de l'utilisateur seedbox
sb_set_credentials() {
    local new=$1 old=$SB_USER
    if [[ $new != "$old" ]]; then
        sb_valid_user "$new" || die "Nom d'utilisateur invalide : « $new »"
        if id "$new" &>/dev/null; then die "« $new » existe déjà sur ce système."; fi
        run "Renommage de $old en $new" usermod --login "$new" "$old"
        if getent group "$old" >/dev/null; then
            run "Renommage du groupe $old" groupmod --new-name "$new" "$old"
        fi
        if [[ -e $SB_KEYS_DIR/$old ]]; then mv -f "$SB_KEYS_DIR/$old" "$SB_KEYS_DIR/$new"; fi
        SB_USER=$new
        sb_save
    fi
    sb_apply
}

sb_change_credentials() {
    titre
    section "UTILISATEUR ET MOT DE PASSE"
    sb_ask_user "$SB_USER"
    echo
    sb_set_credentials "$FC_NEWUSER"
    echo
    sb_selftest
    sb_recap
    SB_PASS=""
}

# finalcut seedbox password [--user NOM] : mot de passe saisi, ou lu sur l'entrée standard
sb_cli_password() {
    local new=${FC_NEWUSER:-$SB_USER}
    if [[ -t 0 ]]; then
        FC_INTERACTIVE=1
        ask_password SB_PASS
    else
        IFS= read -r SB_PASS || true
        ((${#SB_PASS} >= 10)) || die "Mot de passe : 10 caractères minimum (lu sur l'entrée standard)."
    fi
    sb_set_credentials "$new"
    sb_selftest
    SB_PASS=""
    ok "Identifiants mis à jour pour $SB_USER."
}

sb_set_domain() {
    local name=${1,,}
    sb_valid_domain "$name" || die "Nom de domaine invalide : « $name »"
    SB_DOMAIN=$name
    SB_LETSENCRYPT=auto
    if ((FC_STAGING)); then SB_ACME=staging; else SB_ACME=production; fi
    sb_apply_https
    sb_save
    ok "Seedbox accessible sur https://$SB_DOMAIN/ (certificat $(sb_cert_label))"
}

sb_change_domain() {
    local ip
    titre
    section "NOM DE DOMAINE ET CERTIFICAT HTTPS"
    printf 'Actuellement : https://%s/ (certificat %s)\n\n' "$SB_DOMAIN" "$(sb_cert_label)"
    printf "Recherche de l'adresse IP publique… "
    ip=$(public_ipv4)
    echo "${ip:-introuvable}"
    echo
    sb_ask_domain "$ip"
    if ((FC_STAGING)); then SB_ACME=staging; else SB_ACME=production; fi
    echo
    sb_apply_https
    sb_save
    echo
    ok "Seedbox accessible sur https://$SB_DOMAIN/ (certificat $(sb_cert_label))"
}

sb_bans_print() {
    local jail out cur total ips
    for jail in sshd nginx-http-auth recidive; do
        out=$(fail2ban-client status "$jail" 2>/dev/null || true)
        cur=$(sed -n 's/.*Currently banned:[[:space:]]*//p' <<<"$out")
        total=$(sed -n 's/.*Total banned:[[:space:]]*//p' <<<"$out")
        ips=$(sed -n 's/.*Banned IP list:[[:space:]]*//p' <<<"$out")
        printf '%s%-16s%s bannies : %-4s depuis le démarrage : %s\n' "$C_BLD" "$jail" "$C_END" "${cur:-?}" "${total:-?}"
        if [[ -n ${ips// /} ]]; then printf '    %s\n' "$ips"; fi
    done
    echo
    echo "  sshd = SSH/SFTP · nginx-http-auth = interface web · recidive = bannis 1 semaine"
}

sb_unban() {
    [[ $1 =~ ^[0-9A-Fa-f.:]+$ ]] || die "Adresse IP invalide : « $1 »"
    run "Débannissement de $1" fail2ban-client unban "$1"
}

sb_bans() {
    local ip
    titre
    section "ADRESSES IP BANNIES (fail2ban)"
    sb_bans_print
    echo
    ask ip "IP à débannir (vide pour revenir)" ""
    if [[ -n $ip ]]; then
        sb_unban "$ip"
        pause
    fi
}

sb_restart() {
    local s
    echo
    for s in transmission-daemon nginx fail2ban; do
        run "Redémarrage de $s" systemctl restart "$s"
    done
}

sb_uninstall() {
    local del_data=0
    titre
    section "DÉSINSTALLATION DE LA SEEDBOX"
    echo "Seront supprimés : Transmission, nginx, certbot, fail2ban, l'utilisateur $SB_USER"
    echo "et le certificat. Les données dans $SB_DATA sont conservées, sauf avec --purge-data"
    echo "(ou si vous le demandez ci-dessous)."
    echo
    if ! confirm "Désinstaller la seedbox ?" n; then return 0; fi
    if ((FC_INTERACTIVE)); then
        if confirm "Supprimer AUSSI toutes les données de $SB_DATA ?" n; then del_data=1; fi
    elif ((FC_PURGE)); then
        del_data=1
    fi
    echo
    systemctl disable --now transmission-daemon >>"$FC_LOG" 2>&1 || true
    if [[ -f $SB_SSHD ]]; then
        rm -f "$SB_SSHD"
        run "Rechargement de SSH" systemctl try-reload-or-restart ssh.service
    fi
    if [[ -n $SB_USER ]] && id "$SB_USER" &>/dev/null; then
        # les documents restent accessibles à root une fois l'utilisateur supprimé
        if [[ -d $SB_DATA/documents ]]; then chown -R root:root "$SB_DATA/documents"; fi
        if ! userdel "$SB_USER" >>"$FC_LOG" 2>&1; then
            warn "Impossible de supprimer l'utilisateur $SB_USER (session SFTP ouverte ?)."
        fi
    fi
    if command -v certbot >/dev/null; then
        certbot delete --cert-name "$SB_LE_NAME" --non-interactive >>"$FC_LOG" 2>&1 || true
    fi
    # liens de téléchargement en cours
    systemctl stop 'finalcut-partage-*' >>"$FC_LOG" 2>&1 || true
    rm -rf "$SHARE_DIR"
    rm -f "$SB_NGINX_LINK" "$SB_NGINX_SITE" "$SB_HTPASSWD" "$SB_F2B_JAIL" "$SB_F2B_MAIN" "$SB_TR_DROPIN" "$SHARE_LOG"
    rm -f "$SB_KEYS_DIR/$SB_USER"
    rmdir "$SB_KEYS_DIR" "${SB_TR_DROPIN%/*}" 2>/dev/null || true
    rm -rf "$SB_SSL" "$SB_WEBROOT"
    systemctl daemon-reload 2>/dev/null || true
    apt_purge transmission-daemon transmission-common nginx nginx-common certbot fail2ban
    if ((del_data)) && [[ -n $SB_DATA && $SB_DATA != / ]]; then
        run "Suppression des données" rm -rf "${SB_DATA:?}"
    fi
    rm -f "$SB_CONF" "$SB_SECRETS"
    net_hardening_cleanup
    fw_refresh
    echo
    if ((del_data)); then
        ok "Seedbox et données supprimées."
    else
        ok "Seedbox désinstallée. Vos données restent dans $SB_DATA."
    fi
    pause
}

sb_menu() {
    local choix free cert
    while true; do
        sb_load
        sb_installed || return 0
        free=$(disk_free_txt "$SB_DATA")
        if [[ $SB_CERT == selfsigned ]]; then
            cert="${C_YEL}auto-signé${C_END} (option 2 pour retenter Let's Encrypt)"
        else
            cert=$(sb_cert_label)
        fi
        titre
        section "GESTION DE LA SEEDBOX"
        printf '  Interface web : https://%s/\n' "$SB_DOMAIN"
        printf '  Certificat    : %s\n' "$cert"
        printf '  SFTP          : %s@%s — %s\n' "$SB_USER" "$SB_DOMAIN" "$free"
        printf '  Services      : transmission %s · nginx %s · fail2ban %s\n\n' \
            "$(svc_state transmission-daemon)" "$(svc_state nginx)" "$(svc_state fail2ban)"
        cat <<EOF
1) Changer l'utilisateur ou le mot de passe
2) Nom de domaine et certificat HTTPS
3) Clés SSH pour le SFTP
4) Connexion SFTP : réglages pour FileZilla et WinSCP
5) Adresses IP bannies (fail2ban)

6) Redémarrer les services
7) Désinstaller la seedbox

Q) Retour
EOF
        echo
        ask choix "Votre choix" ""
        case ${choix,,} in
            1)
                sb_change_credentials
                echo
                pause
                ;;
            2)
                sb_change_domain
                echo
                pause
                ;;
            3) sb_keys_menu ;;
            4)
                sb_sftp_config
                pause
                ;;
            5) sb_bans ;;
            6)
                sb_restart
                echo
                pause
                ;;
            7) sb_uninstall ;;
            q) return 0 ;;
        esac
    done
}

sb_main() {
    sb_load
    if sb_installed; then sb_menu; else sb_install_interactive; fi
}

# finalcut seedbox <commande> …
sb_cli() {
    local cmd=${1-}
    if (($#)); then shift; fi
    case $cmd in
        "")
            require_tty
            sb_main
            ;;
        install)
            if [[ -n $FC_CONFIG ]]; then
                config_load "$FC_CONFIG"
                sb_install_config
                if [[ $(cfg FIREWALL) == yes ]]; then fw_enable; fi
            else
                require_tty
                if sb_installed; then die "La seedbox est déjà installée (finalcut seedbox pour la gérer)."; fi
                sb_install_interactive
            fi
            ;;
        password)
            sb_require_installed
            sb_cli_password
            ;;
        domain)
            sb_require_installed
            [[ -n ${1-} ]] || die "Usage : finalcut seedbox domain NOM [--staging]"
            sb_set_domain "$1"
            ;;
        sftp-key)
            sb_require_installed
            case ${1-} in
                add)
                    [[ -n ${2-} ]] || die "Usage : finalcut seedbox sftp-key add FICHIER.pub   (- pour l'entrée standard)"
                    sb_keys_import "$2"
                    sb_apply_sftp
                    ;;
                list) sb_keys_list ;;
                remove) sb_keys_remove "${2-}" ;;
                *) die "Usage : finalcut seedbox sftp-key add|list|remove" ;;
            esac
            ;;
        sftp-password)
            sb_require_installed
            sb_set_sftp_password "${1-}"
            ;;
        sftp-config)
            sb_require_installed
            sb_sftp_config
            ;;
        bans)
            sb_require_installed
            sb_bans_print
            ;;
        unban)
            sb_require_installed
            sb_unban "${1-}"
            ;;
        restart)
            sb_require_installed
            sb_restart
            ;;
        uninstall)
            sb_require_installed
            sb_uninstall
            ;;
        *) die "Commande inconnue : seedbox $cmd   (aide : finalcut help)" ;;
    esac
}
