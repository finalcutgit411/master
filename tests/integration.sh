#!/usr/bin/env bash
# =============================================================================
#  Tests d'intégration de finalcut
#
#  Lancés par GitHub Actions dans un conteneur Debian vierge avec systemd
#  (voir .github/workflows/ci.yml et tests/Dockerfile). Ils installent tout
#  pour de vrai, vérifient que chaque service répond, puis désinstallent.
#
#  NE PAS LANCER SUR UN VRAI SERVEUR : tout y serait installé puis supprimé.
#
#  Usage : integration.sh phase1   installation, VPN, seedbox, SFTP, pare-feu
#          integration.sh phase2   diagnostic, sauvegarde, restauration, désinstallation
# =============================================================================
set -Euo pipefail

FC=/opt/finalcut/finalcut.sh
W=/root/finalcut-tests
SBU=lancelot
PW1="motdepasse-ci-123"
PW2="nouveau-mdp-ci-456"
PASS=0
FAIL=0

[[ -f /.dockerenv || ${CI-} == true ]] || {
    echo "Refus : ces tests ne doivent tourner que dans le conteneur de test." >&2
    exit 1
}

step() { printf '\n\033[1m=== %s\033[0m\n' "$*"; }

# Sur GitHub Actions, chaque échec devient aussi une annotation : elle
# s'affiche dans le résumé du test, avec la fin de la sortie de la commande.
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

# check "description" commande…  → la commande doit réussir
check() {
    local desc=$1
    shift
    if "$@" >"$W/check.out" 2>&1; then
        printf '  \033[32m✔\033[0m %s\n' "$desc"
        PASS=$((PASS + 1))
    else
        printf '  \033[31m✘ %s\033[0m\n' "$desc"
        tail -n 25 "$W/check.out" | sed 's/^/      /'
        annotate "$desc"
        FAIL=$((FAIL + 1))
    fi
}

# check_fails "description" commande…  → la commande doit échouer
check_fails() {
    local desc=$1
    shift
    if "$@" >"$W/check.out" 2>&1; then
        printf '  \033[31m✘ %s (a réussi alors qu'"'"'elle devait échouer)\033[0m\n' "$desc"
        tail -n 25 "$W/check.out" | sed 's/^/      /'
        annotate "$desc (aurait dû échouer)"
        FAIL=$((FAIL + 1))
    else
        printf '  \033[32m✔\033[0m %s\n' "$desc"
        PASS=$((PASS + 1))
    fi
}

# finalcut sans terminal, comme dans un script, et avec le PATH réduit qu'on a
# après un « su » sans tiret (sans /usr/sbin) : le script doit s'en sortir seul
fc() { PATH=/usr/local/bin:/usr/bin:/bin "$FC" "$@" </dev/null; }

# La sortie d'une commande contient-elle un texte ? (sortie capturée d'abord :
# un « cmd | grep -q » peut échouer à tort avec pipefail)
output_has() {
    local text=$1 out
    shift
    out=$("$@" 2>&1) || true
    grep -qF -- "$text" <<<"$out"
}

# Code HTTP renvoyé par la seedbox (identifiants facultatifs)
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

# Commandes SFTP par mot de passe ou par clé
sftp_pw() {
    printf '%s\n' "$2" | sshpass -p "$1" sftp -q -oBatchMode=no -oStrictHostKeyChecking=no \
        -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=no -b - "$SBU@127.0.0.1"
}
sftp_key() {
    printf '%s\n' "$1" | sftp -q -i "$W/cle" -oIdentitiesOnly=yes -oBatchMode=yes \
        -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -b - "$SBU@127.0.0.1"
}

# Vrai tunnel WireGuard : un « client » dans un espace réseau séparé se
# connecte avec la configuration générée pour « telephone » et ping le serveur.
tunnel_test() {
    local conf=/etc/finalcut/vpn/clients/telephone.conf priv psk pub
    priv=$(awk -F' = ' '/^PrivateKey/ { print $2 }' "$conf")
    psk=$(awk -F' = ' '/^PresharedKey/ { print $2 }' "$conf")
    pub=$(awk -F' = ' '/^PublicKey/ { print $2 }' "$conf")
    ip netns del fc-client 2>/dev/null || true
    ip link del fc-veth0 2>/dev/null || true
    ip netns add fc-client
    ip link add fc-veth0 type veth peer name fc-veth1
    ip link set fc-veth1 netns fc-client
    ip addr add 192.168.250.1/24 dev fc-veth0
    ip link set fc-veth0 up
    ip -n fc-client addr add 192.168.250.2/24 dev fc-veth1
    ip -n fc-client link set fc-veth1 up
    ip -n fc-client link set lo up
    ip -n fc-client link add wgc type wireguard
    ip netns exec fc-client wg set wgc private-key <(printf '%s\n' "$priv") \
        peer "$pub" preshared-key <(printf '%s\n' "$psk") \
        endpoint 192.168.250.1:51820 allowed-ips 10.8.0.0/24
    ip -n fc-client addr add 10.8.0.2/32 dev wgc
    ip -n fc-client link set wgc up
    ip -n fc-client route add 10.8.0.0/24 dev wgc
    ip netns exec fc-client ping -c 3 -W 2 10.8.0.1
}

# La commande réussit sans aucune ligne « redémarrage / application… » :
# rien n'a été touché
nothing_changed() {
    local out
    out=$("$@" 2>&1) || {
        printf '%s\n' "$out"
        return 1
    }
    ! grep -E 'Démarrage|Redémarrage|Rechargement|Arrêt|Application|Installation de|Création' <<<"$out"
}

# Durcissement réseau du noyau appliqué, y compris sur l'interface existante
net_hardened() {
    local nic
    nic=$(ip -4 route show default | awk '{ print $5; exit }')
    sysctl net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route "net.ipv4.conf.$nic.accept_redirects"
    [[ $(sysctl -n net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route \
        "net.ipv4.conf.$nic.accept_redirects" | tr -d '\n') == 000 ]]
}

# Chemin « /partage/<jeton>/ » du lien affiché par une commande
share_path() {
    local url
    url=$(grep -oE 'https://[^ ]+/partage/[0-9a-f]{32}/' <<<"$1" | head -n 1)
    [[ -n $url ]] || return 1
    printf '/%s' "${url#https://*/}"
}

# Lien à usage unique : la page s'ouvre (plusieurs fois), le fichier se
# télécharge une fois, puis le lien disparaît
share_test() {
    local out path page i
    out=$(fc vpn share telephone 2>&1) || {
        printf '%s\n' "$out"
        return 1
    }
    path=$(share_path "$out") || {
        printf 'lien absent :\n%s\n' "$out"
        return 1
    }
    page=$(curl -sk --max-time 10 "https://127.0.0.1$path")
    [[ $page == *"Télécharger telephone.conf"* ]] || {
        printf 'page inattendue :\n%s\n' "$page"
        return 1
    }
    [[ $(http_code "$path") == 200 ]] || {
        echo "ouvrir la page ne doit pas consommer le lien"
        return 1
    }
    curl -skf --max-time 10 -o "$W/partage.conf" "https://127.0.0.1${path}telephone.conf" || return 1
    cmp "$W/partage.conf" /etc/finalcut/vpn/clients/telephone.conf || return 1
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [[ $(http_code "${path}telephone.conf") == 404 ]] && return 0
        sleep 1
    done
    echo "le fichier est toujours téléchargeable après usage (essai $i)"
    return 1
}

# Réglages SFTP et site FileZilla téléchargeable
sftp_config_test() {
    local out path xml
    out=$(fc seedbox sftp-config 2>&1) || {
        printf '%s\n' "$out"
        return 1
    }
    [[ $out == *"sftp://$SBU@127.0.0.1:22/"* && $out == *"SHA256:"* ]] || {
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

# Une adresse bannie par la prison sshd l'est de tous les ports
f2b_allports_test() {
    local ip=203.0.113.7 rules lines i
    fail2ban-client set sshd banip "$ip" || return 1
    # l'action de bannissement s'exécute en arrière-plan
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

# « finalcut apply » remet en ordre un fichier modifié à la main
apply_test() {
    echo '# modification à la main' >>/etc/fail2ban/jail.d/finalcut.local
    output_has "Redémarrage de fail2ban" fc apply || return 1
    ! grep -q 'modification à la main' /etc/fail2ban/jail.d/finalcut.local
}

summary() {
    printf '\n\033[1m%s réussis, %s échoués\033[0m\n' "$PASS" "$FAIL"
    ((FAIL == 0))
}

phase1() {
    mkdir -p "$W"
    chmod 700 "$W"
    printf '%s\n' "$PW1" >"$W/motdepasse"
    cat >"$W/ci.conf" <<EOF
VPN_ENDPOINT=192.168.250.1
VPN_PORT=51820
VPN_DNS=quad9
VPN_CLIENTS="telephone"
SB_USER=$SBU
SB_PASSWORD_FILE=$W/motdepasse
SB_DOMAIN=127.0.0.1
SB_DATA=/srv/seedbox
SB_LETSENCRYPT=no
EOF
    chmod 600 "$W/ci.conf" "$W/motdepasse"

    step "Généralités"
    check "finalcut version" output_has "finalcut 2." fc version
    check "finalcut help" output_has "vpn add NOM" fc help
    check "finalcut help : nouvelles commandes" output_has "vpn share NOM" fc help
    check_fails "commande inconnue refusée" fc nimportequoi

    step "VPN : installation par fichier de configuration"
    check "installation" fc vpn install --config "$W/ci.conf"
    check "service WireGuard actif" systemctl is-active --quiet wg-quick@wg0
    check "client « telephone » créé" test -s /etc/finalcut/vpn/clients/telephone.conf
    check "port 60001 redirigé vers 10.8.0.2" output_has "dport 60001 dnat to 10.8.0.2" nft list table ip finalcut
    check "routage IPv4 activé" test "$(sysctl -n net.ipv4.ip_forward)" = 1
    check "réglages réseau du noyau durcis" net_hardened
    check "durcissement enregistré pour le démarrage" test -s /etc/sysctl.d/90-finalcut-reseau.conf

    check "commande « finalcut » trouvée même après un su sans tiret" \
        env PATH=/usr/local/bin:/usr/bin:/bin bash -c 'command -v finalcut'

    step "VPN : relance identique (idempotence)"
    md5sum /etc/finalcut/vpn/server.key /etc/wireguard/wg0.conf >"$W/vpn.md5"
    check "aucun changement à la relance" nothing_changed fc vpn install --config "$W/ci.conf"
    check "clés et configuration inchangées" md5sum -c --quiet "$W/vpn.md5"

    step "VPN : commandes"
    check "vpn add pc-salon" fc vpn add pc-salon
    check "vpn list affiche pc-salon" output_has "pc-salon" fc vpn list
    check_fails "vpn remove sans --yes refusé" fc vpn remove pc-salon
    check "vpn remove --yes" fc vpn remove pc-salon --yes
    check_fails "pc-salon a disparu" test -e /etc/finalcut/vpn/clients/pc-salon.env
    check "vpn show telephone" output_has "[Interface]" fc vpn show telephone
    check_fails "nom de client invalide refusé" fc vpn add "nom invalide!"
    check "vpn share sans seedbox : refus qui indique quoi faire" output_has "finalcut vpn show telephone" fc vpn share telephone

    step "VPN : tunnel de bout en bout"
    check "un client se connecte et joint 10.8.0.1" tunnel_test

    step "Seedbox : installation par fichier de configuration"
    check "installation" fc seedbox install --config "$W/ci.conf"
    check "Transmission actif" systemctl is-active --quiet transmission-daemon
    check "nginx actif" systemctl is-active --quiet nginx
    check "fail2ban actif" systemctl is-active --quiet fail2ban
    check "web sans identifiants : 401" http_is 401 /transmission/web/
    check "web avec identifiants : 200" http_is 200 /transmission/web/ -u "$SBU:$PW1"
    check "Transmission répond derrière nginx (409)" http_is 409 /transmission/rpc -u "$SBU:$PW1"
    check "mauvais mot de passe refusé" http_is 401 /transmission/web/ -u "$SBU:mauvais"
    check "aucun mot de passe en clair dans /etc/finalcut" bash -c "! grep -rqF -- '$PW1' /etc/finalcut /etc/nginx /etc/transmission-daemon"
    check "Transmission enfermé par systemd" output_has "ProtectSystem=strict" systemctl show transmission-daemon -p ProtectSystem

    step "Seedbox : relance identique (idempotence)"
    check "aucun service redémarré" nothing_changed fc seedbox install --config "$W/ci.conf"

    step "Liens de téléchargement à usage unique"
    check "vpn share : page, téléchargement unique, puis lien supprimé" share_test
    check "seedbox sftp-config : réglages, empreinte et fichier FileZilla" sftp_config_test
    check "liste des liens impossible" http_is 403 /partage/
    check "jeton inconnu : 404" http_is 404 /partage/0123456789abcdef0123456789abcdef/

    step "SFTP"
    check "connexion et dossiers visibles" output_has "watch" sftp_pw "$PW1" "ls"
    check "envoi d'un fichier dans documents/" sftp_pw "$PW1" "put /etc/hostname documents/test.txt"
    check "le fichier est arrivé" test -f /srv/seedbox/documents/test.txt
    check_fails "impossible de sortir du dossier (chroot)" sftp_pw "$PW1" "ls /etc"
    check_fails "pas de shell SSH" sshpass -p "$PW1" ssh -oStrictHostKeyChecking=no \
        -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=no "$SBU@127.0.0.1" id

    step "SFTP : clés SSH"
    rm -f "$W/cle" "$W/cle.pub"
    ssh-keygen -q -t ed25519 -N '' -f "$W/cle"
    check "ajout de la clé" fc seedbox sftp-key add "$W/cle.pub"
    check "connexion par clé" output_has "watch" sftp_key "ls"
    check "mot de passe SFTP désactivé" fc seedbox sftp-password off
    check_fails "connexion par mot de passe refusée" sftp_pw "$PW1" "ls"
    check "web toujours accessible par mot de passe" http_is 200 /transmission/web/ -u "$SBU:$PW1"
    check "mot de passe SFTP réactivé" fc seedbox sftp-password on

    step "Changement de mot de passe"
    check "seedbox password (entrée standard)" bash -c "printf '%s\n' '$PW2' | '$FC' seedbox password"
    check "nouveau mot de passe accepté" http_is 409 /transmission/rpc -u "$SBU:$PW2"
    check "ancien mot de passe refusé" http_is 401 /transmission/web/ -u "$SBU:$PW1"
    check "SFTP avec le nouveau mot de passe" output_has "watch" sftp_pw "$PW2" "ls"
    printf '%s\n' "$PW2" >"$W/motdepasse"

    step "fail2ban"
    check "règles sshd, nginx-http-auth et recidive" bash -c \
        "fail2ban-client status | grep -q sshd && fail2ban-client status | grep -q nginx-http-auth && fail2ban-client status | grep -q recidive"
    check "SSH : bannissement de tous les ports, quel que soit le port de SSH" f2b_allports_test

    step "Pare-feu"
    check_fails "sans --yes ni terminal : refus" fc firewall enable
    check "activation" fc firewall enable --yes
    nft list table inet finalcut_fw >"$W/fw.txt"
    check "SSH autorisé" grep -Eq 'tcp dport (\{ )?22( \})? accept' "$W/fw.txt"
    check "VPN autorisé" grep -q 'udp dport 51820 accept' "$W/fw.txt"
    check "web autorisé" grep -q '80, 443' "$W/fw.txt"
    check "politique par défaut : refus" grep -q 'policy drop' "$W/fw.txt"
    check "rechargé au démarrage" systemctl is-enabled --quiet finalcut-firewall.service
    check "tunnel WireGuard à travers le pare-feu" tunnel_test

    step "Réapplication de la configuration (finalcut apply)"
    check "remet en ordre une modification à la main" apply_test
    check "relancée : aucun changement" nothing_changed fc apply

    summary
}

phase2() {
    step "Diagnostic"
    check "finalcut doctor sans problème" fc doctor
    # Port SSH changé dans la configuration sans mettre le pare-feu à jour
    printf 'Port 2222\n' >/etc/ssh/sshd_config.d/zz-test-port.conf
    check "doctor signale un port SSH fermé par le pare-feu" output_has "port 2222, fermé par le pare-feu" fc doctor
    rm -f /etc/ssh/sshd_config.d/zz-test-port.conf

    step "Sauvegarde et restauration"
    printf 'une phrase de passe de test\n' >"$W/phrase"
    chmod 600 "$W/phrase"
    md5sum /etc/finalcut/vpn/server.key /etc/finalcut/vpn/clients/telephone.conf /etc/finalcut/seedbox.secrets >"$W/avant.md5"
    check "sauvegarde chiffrée" fc backup --output "$W/sauvegarde.enc" --passphrase-file "$W/phrase"
    check "archive illisible sans la phrase" bash -c "! tar -tzf '$W/sauvegarde.enc' 2>/dev/null"
    check "désinstallation de la seedbox" fc seedbox uninstall --yes
    check "désinstallation du VPN" fc vpn uninstall --yes
    check "désactivation du pare-feu" fc firewall disable --yes
    printf 'mauvaise phrase\n' >"$W/mauvaise"
    check_fails "mauvaise phrase de passe refusée" fc restore "$W/sauvegarde.enc" --passphrase-file "$W/mauvaise" --yes
    check "restauration" fc restore "$W/sauvegarde.enc" --passphrase-file "$W/phrase" --yes
    check "mêmes clés VPN, clients et empreintes" md5sum -c --quiet "$W/avant.md5"
    check "WireGuard actif" systemctl is-active --quiet wg-quick@wg0
    check "l'ancien client se connecte sans rien changer" tunnel_test
    check "mot de passe de la seedbox conservé" http_is 409 /transmission/rpc -u "$SBU:$PW2"
    check "pare-feu restauré" systemctl is-active --quiet finalcut-firewall.service

    step "Désinstallation"
    check "seedbox" fc seedbox uninstall --yes
    check "VPN" fc vpn uninstall --yes
    check "pare-feu" fc firewall disable --yes
    check_fails "plus de règle SFTP" test -e /etc/ssh/sshd_config.d/finalcut-seedbox.conf
    check_fails "plus d'utilisateur $SBU" id "$SBU"
    check_fails "plus d'interface wg0" ip link show wg0
    check "données conservées" test -f /srv/seedbox/documents/test.txt
    check "SSH toujours actif" systemctl is-active --quiet ssh

    summary
}

case ${1-} in
    phase1) phase1 ;;
    phase2) phase2 ;;
    *)
        echo "Usage : $0 phase1|phase2" >&2
        exit 2
        ;;
esac
