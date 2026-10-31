#!/usr/bin/env bash
# =============================================================================
#  finalcut — bibliothèque commune
#  Affichage, saisie, journal, fichier de configuration, vérifications système.
#  Chargée par finalcut.sh : ce fichier ne s'exécute pas seul.
# =============================================================================

FC_VERSION="2.2.2"
# Dépôt GitHub utilisé par « finalcut update » (compte/projet)
FC_REPO="finalcutgit411/finalcut"
# État et secrets du script (lisible par root uniquement)
FC_ETC="/etc/finalcut"
# Sortie détaillée de toutes les commandes lancées
FC_LOG="/var/log/finalcut.log"
FC_OS_DESC=""
FC_APT_UPDATED=0

# Options de la ligne de commande (remplies par finalcut.sh)
FC_INTERACTIVE=0
FC_YES=0
FC_CONFIG=""
FC_STAGING=0
FC_OUTPUT=""
FC_PASSFILE=""
FC_PURGE=0
FC_QR=0
FC_NEWUSER=""

# --- Couleurs (désactivées si la sortie n'est pas un terminal) ----------------
if [[ -t 1 ]]; then
    C_RED=$'\e[1;31m'
    C_GRN=$'\e[1;32m'
    C_YEL=$'\e[1;33m'
    C_BLU=$'\e[1;34m'
    C_BLD=$'\e[1m'
    C_DIM=$'\e[2m'
    C_END=$'\e[0m'
else
    C_RED=""
    C_GRN=""
    C_YEL=""
    C_BLU=""
    C_BLD=""
    C_DIM=""
    C_END=""
fi

# --- Affichage ------------------------------------------------------------------
titre() {
    ((FC_INTERACTIVE)) || return 0
    clear 2>/dev/null || true
    printf '%s' "$C_BLU"
    cat <<'EOF'
___________ .___   _______       _____    .____      _________    ____ ___  ___________
\_   _____/ |   |  \      \     /  _  \   |    |     \_   ___ \  |    |   \ \__    ___/
 |    __)   |   |  /   |   \   /  /_\  \  |    |     /    \  \/  |    |   /   |    |
 |     \    |   | /    |    \ /    |    \ |    |___  \     \____ |    |  /    |    |
 \___  /    |___| \____|__  / \____|__  / |_______ \  \______  / |______/     |____|
EOF
    printf '%s%s  v%s · VPN WireGuard + seedbox · %s%s\n\n' \
        "$C_END" "$C_DIM" "$FC_VERSION" "${FC_OS_DESC:-Debian 12/13}" "$C_END"
}

section() { printf '%s%s%s\n\n' "$C_BLD" "$*" "$C_END"; }
ok() { printf '%s✔%s %s\n' "$C_GRN" "$C_END" "$*"; }
warn() { printf '%s!%s %s\n' "$C_YEL" "$C_END" "$*" >&2; }
err() { printf '%s✘ %s%s\n' "$C_RED" "$*" "$C_END" >&2; }

# Arrête le script avec un message.
# Attention : dans un $(…) elle ne quitte que le sous-shell, donc à éviter là.
die() {
    err "$*"
    exit 1
}

pause() {
    local _
    ((FC_INTERACTIVE)) || return 0
    IFS= read -r -p "Appuyez sur [Entrée] pour continuer… " _ || true
}

# Affiche l'état d'un service en couleur : actif / arrêté / absent
svc_state() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        printf '%sactif%s' "$C_GRN" "$C_END"
    elif systemctl cat "$1" &>/dev/null; then
        printf '%sarrêté%s' "$C_RED" "$C_END"
    else
        printf '%sabsent%s' "$C_DIM" "$C_END"
    fi
}

# --- Gestion des erreurs ------------------------------------------------------
# Toute commande qui échoue sans être gérée arrive ici (set -e + trap ERR) :
# on affiche où, au lieu de laisser le script continuer dans un état bancal.
fc_on_error() {
    local rc=$1 line=$2 cmd=$3 src=${4##*/}
    trap - ERR
    if ((BASH_SUBSHELL == 0)); then
        printf '\n%s✘ Erreur inattendue (code %s) dans %s, ligne %s :%s\n    %s\n' \
            "$C_RED" "$rc" "${src:-?}" "$line" "$C_END" "$cmd" >&2
        printf '  Journal détaillé : %s\n' "$FC_LOG" >&2
    fi
    exit "$rc"
}

# run "Description" commande args…
# Lance une commande en envoyant sa sortie dans le journal ; affiche « ok » ou
# les dernières lignes du journal puis arrête le script en cas d'échec.
# Ne jamais passer de mot de passe en argument : il finirait dans le journal.
run() {
    local desc=$1 rc
    shift
    printf '  %s… ' "$desc"
    printf '\n=== %(%F %T)T · %s\n$ %s\n' -1 "$desc" "$*" >>"$FC_LOG"
    if "$@" >>"$FC_LOG" 2>&1; then
        printf '%sok%s\n' "$C_GRN" "$C_END"
    else
        rc=$?
        printf '%séchec%s\n\n' "$C_RED" "$C_END"
        tail -n 15 "$FC_LOG" | sed 's/^/    /' >&2
        echo >&2
        die "« $desc » a échoué (code $rc). Journal complet : $FC_LOG"
    fi
}

# --- Saisie ---------------------------------------------------------------------
# Les variables locales ont un préfixe unique : printf -v écrit dans la
# variable de l'appelant, il ne faut pas qu'un nom local la masque.

require_tty() {
    [[ -t 0 ]] || die "Cette action est interactive : lancez-la depuis un terminal, ou utilisez --config."
    FC_INTERACTIVE=1
}

# ask VAR "Question" [valeur proposée]   (la valeur proposée est modifiable)
ask() {
    local _ask_var=$1 _ask_prompt=$2 _ask_def=${3-} _ask_rep
    ((FC_INTERACTIVE)) || die "Question hors mode interactif : $_ask_prompt"
    IFS= read -r -e -i "$_ask_def" -p "$_ask_prompt : " _ask_rep || {
        echo
        exit 130
    }
    printf -v "$_ask_var" '%s' "$_ask_rep"
}

# confirm "Question" [o|n]   → code 0 si la réponse est oui
# --yes vaut confirmation ; sans terminal, c'est la seule possible.
confirm() {
    local q=$1 def=${2:-n} rep hint="[o/N]"
    if ((FC_YES)); then return 0; fi
    [[ -t 0 ]] || die "$q → relancez avec --yes pour confirmer."
    [[ $def == o ]] && hint="[O/n]"
    while true; do
        IFS= read -r -p "$q $hint " rep || {
            echo
            exit 130
        }
        rep=${rep:-$def}
        case ${rep,,} in
            o | oui | y | yes) return 0 ;;
            n | non | no) return 1 ;;
        esac
    done
}

# Mot de passe aléatoire de 20 caractères alphanumériques (~119 bits)
gen_password() {
    local p
    p=$(openssl rand -base64 48)
    p=${p//[^A-Za-z0-9]/}
    printf '%s' "${p:0:20}"
}

# ask_password VAR — saisie masquée avec confirmation ; vide = mot de passe généré
ask_password() {
    local _ap_var=$1 _ap_p1 _ap_p2
    while true; do
        IFS= read -r -s -p "Mot de passe (laisser vide pour en générer un) : " _ap_p1 || {
            echo
            exit 130
        }
        echo
        if [[ -z $_ap_p1 ]]; then
            _ap_p1=$(gen_password)
            printf 'Mot de passe généré : %s%s%s  ← notez-le\n' "$C_BLD" "$_ap_p1" "$C_END"
            break
        fi
        if ((${#_ap_p1} < 10)); then
            warn "10 caractères minimum."
            continue
        fi
        IFS= read -r -s -p "Confirmez le mot de passe : " _ap_p2 || {
            echo
            exit 130
        }
        echo
        [[ $_ap_p1 == "$_ap_p2" ]] && break
        warn "Les deux saisies sont différentes, recommencez."
    done
    printf -v "$_ap_var" '%s' "$_ap_p1"
}

# --- Fichiers ---------------------------------------------------------------------

# conf_write fichier VAR1 VAR2…  → écrit VAR=valeur (échappée) en mode 600
conf_write() {
    local f=$1 v
    shift
    {
        printf '# Généré par finalcut — ne pas modifier à la main\n'
        for v in "$@"; do printf '%s=%q\n' "$v" "${!v}"; done
    } >"$f.tmp"
    chmod 600 "$f.tmp"
    mv -f "$f.tmp" "$f"
}

conf_read() {
    if [[ -r $1 ]]; then
        # shellcheck source=/dev/null
        . "$1"
    fi
}

# write_if_changed FICHIER [MODE] [PROPRIÉTAIRE]
# Lit le contenu voulu sur l'entrée standard et ne remplace le fichier que s'il
# change : c'est ce qui permet de relancer le script sans tout redémarrer.
# Code de retour : 0 si le fichier a été modifié, 1 s'il était déjà à jour.
write_if_changed() {
    local f=$1 mode=${2:-644} owner=${3:-root:root} tmp rc=1
    tmp=$(mktemp "$f.XXXXXX")
    cat >"$tmp"
    if [[ -f $f ]] && cmp -s "$tmp" "$f"; then
        rm -f "$tmp"
    else
        mv -f "$tmp" "$f"
        rc=0
    fi
    chmod "$mode" "$f"
    chown "$owner" "$f"
    return "$rc"
}

# --- Fichier de configuration (--config) ---------------------------------------
# Le fichier n'est jamais exécuté : il est lu ligne par ligne, et seules les
# clés ci-dessous sont acceptées. Les valeurs sont rangées dans CFG_<CLÉ>.
FC_CONFIG_KEYS=" VPN_ENDPOINT VPN_PORT VPN_DNS VPN_CLIENTS SB_USER SB_PASSWORD
 SB_PASSWORD_FILE SB_DOMAIN SB_DATA SB_LETSENCRYPT SB_ACME SB_SSH_KEYS_FILE
 SB_SFTP_PASSWORD FIREWALL "

config_load() {
    local file=$1 line key val n=0
    [[ -r $file ]] || die "Fichier de configuration introuvable : $file"
    if [[ $(stat -c '%a' "$file") != [0-7]00 ]]; then
        warn "$file est lisible par d'autres utilisateurs : faites  chmod 600 $file"
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        line=${line%$'\r'}
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ ! $line =~ ^[[:space:]]*([A-Z_]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            die "$file, ligne $n : format attendu CLÉ=valeur"
        fi
        key=${BASH_REMATCH[1]}
        val=${BASH_REMATCH[2]}
        # espaces de fin et guillemets autour de la valeur
        val=${val%"${val##*[![:space:]]}"}
        if [[ $val =~ ^\"(.*)\"$ || $val =~ ^\'(.*)\'$ ]]; then val=${BASH_REMATCH[1]}; fi
        [[ $FC_CONFIG_KEYS == *[[:space:]]"$key"[[:space:]]* ]] || die "$file, ligne $n : clé inconnue « $key »"
        printf -v "CFG_$key" '%s' "$val"
    done <"$file"
}

# cfg CLÉ [défaut] → valeur lue dans le fichier de configuration, sinon le défaut
cfg() {
    local v="CFG_$1"
    printf '%s' "${!v:-${2-}}"
}

# --- Système --------------------------------------------------------------------
check_system() {
    local id ver name
    [[ $EUID -eq 0 ]] || die "Ce script doit être lancé en root :  sudo $0"
    [[ -r /etc/os-release ]] || die "Système non reconnu (fichier /etc/os-release absent)."
    IFS='|' read -r id ver name FC_OS_DESC < <(
        # shellcheck source=/dev/null
        . /etc/os-release
        printf '%s|%s|%s|%s\n' "${ID:-?}" "${VERSION_ID:-?}" "${VERSION_CODENAME:-?}" "${PRETTY_NAME:-?}"
    )
    [[ $id == debian ]] || die "Ce script ne fonctionne que sur Debian (système détecté : $FC_OS_DESC)."
    case $ver in
        12 | 13) ;;
        *) die "Debian 12 (bookworm) ou 13 (trixie) requis — système détecté : $FC_OS_DESC." ;;
    esac
    command -v systemctl >/dev/null || die "systemd est requis."
    install -d -m 700 "$FC_ETC"
    touch "$FC_LOG"
    chmod 600 "$FC_LOG"
}

# Empêche de lancer deux fois le script en même temps
take_lock() {
    exec 9>/run/finalcut.lock
    flock -n 9 || die "finalcut est déjà en cours d'exécution dans un autre terminal."
}

pkg_installed() {
    [[ $(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true) == *" installed" ]]
}

# apt_install paquet… — n'installe que ce qui manque. La liste des paquets est
# mise à jour une fois par session ; on attend le verrou dpkg (les mises à
# jour automatiques le tiennent souvent juste après le démarrage).
apt_install() {
    local p
    local -a missing=()
    for p in "$@"; do pkg_installed "$p" || missing+=("$p"); done
    ((${#missing[@]})) || return 0
    export DEBIAN_FRONTEND=noninteractive
    if ((!FC_APT_UPDATED)); then
        run "Mise à jour de la liste des paquets" apt-get -o DPkg::Lock::Timeout=300 update
        FC_APT_UPDATED=1
    fi
    run "Installation de ${missing[*]}" apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends "${missing[@]}"
}

# apt_purge paquet… — ne supprime que ceux qui sont réellement installés
apt_purge() {
    local p
    local -a present=()
    for p in "$@"; do pkg_installed "$p" && present+=("$p"); done
    ((${#present[@]})) || return 0
    export DEBIAN_FRONTEND=noninteractive
    run "Suppression de ${present[*]}" apt-get -o DPkg::Lock::Timeout=300 purge -y "${present[@]}"
    run "Nettoyage des dépendances inutiles" apt-get -o DPkg::Lock::Timeout=300 autoremove -y
}

# Paquets de base + mises à jour de sécurité automatiques
base_setup() {
    apt_install curl ca-certificates openssl jq nftables procps iproute2 unattended-upgrades
    if [[ ! -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
        printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
            >/etc/apt/apt.conf.d/20auto-upgrades
        ok "Mises à jour de sécurité automatiques activées"
    fi
}

# --- Durcissement réseau du noyau --------------------------------------------------
# Dans /etc/sysctl.d : Debian 13 ne lit plus /etc/sysctl.conf au démarrage.
# « * » vise toutes les interfaces, y compris celles qui existent déjà ;
# « - » : ligne ignorée si l'IPv6 est désactivé sur le serveur.
FC_SYSCTL_NET="/etc/sysctl.d/90-finalcut-reseau.conf"

net_hardening_gen() {
    cat <<'EOF'
# Généré par finalcut — durcissement réseau du noyau
# Ignorer les redirections ICMP : personne ne peut détourner le trafic du serveur
net.ipv4.conf.*.accept_redirects = 0
net.ipv4.conf.*.secure_redirects = 0
-net.ipv6.conf.*.accept_redirects = 0
# … et ne pas en envoyer
net.ipv4.conf.*.send_redirects = 0
# Refuser les paquets qui imposent leur propre chemin (routage par la source)
net.ipv4.conf.*.accept_source_route = 0
-net.ipv6.conf.*.accept_source_route = 0
EOF
}

# Appelé par l'installation du VPN et de la seedbox (sans effet s'il est à jour)
net_hardening_apply() {
    if write_if_changed "$FC_SYSCTL_NET" 644 < <(net_hardening_gen) \
        || [[ $(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null) != 0 ]]; then
        printf '\n=== %(%F %T)T · durcissement réseau du noyau\n' -1 >>"$FC_LOG"
        # systemd-sysctl, comme au démarrage : il comprend « * » et « - »
        if /usr/lib/systemd/systemd-sysctl "$FC_SYSCTL_NET" >>"$FC_LOG" 2>&1; then
            ok "Réglages réseau du noyau durcis (redirections ICMP, routage par la source)"
        else
            warn "Réglages réseau du noyau non appliqués (détails dans $FC_LOG)."
        fi
    fi
}

# Retiré quand ni le VPN ni la seedbox ne sont plus installés
net_hardening_cleanup() {
    if ! vpn_installed && ! sb_installed; then rm -f "$FC_SYSCTL_NET"; fi
}

# « 36Go libres sur 40Go » pour la partition d'un dossier. L'espace libre est
# en vert, en jaune sous 10 % ou 5 Go, en rouge sous 2 Go.
disk_free_txt() {
    local size="" avail="" color
    read -r size avail < <(df -B1 --output=size,avail "$1" 2>/dev/null | tail -n 1) || true
    if [[ ! $size =~ ^[0-9]+$ || ! $avail =~ ^[0-9]+$ ]] || ((size == 0)); then
        printf '?'
        return 0
    fi
    if ((avail < 2 * 1024 ** 3)); then
        color=$C_RED
    elif ((avail < 5 * 1024 ** 3 || avail * 10 < size)); then
        color=$C_YEL
    else
        color=$C_GRN
    fi
    printf '%s%s libres%s sur %s' "$color" "$(numfmt --to=iec --suffix=o "$avail")" "$C_END" \
        "$(numfmt --to=iec --suffix=o "$size")"
}

# --- Réseau ---------------------------------------------------------------------
is_ipv4() { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

valid_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (($1 >= 1 && $1 <= 65535)); }

# Interface réseau de la route par défaut (eth0, ens3…)
default_iface() {
    ip -4 route show default 2>/dev/null \
        | awk '!found { for (i = 1; i < NF; i++) if ($i == "dev") { print $(i+1); found = 1 } }'
}

# IPv4 publique : demandée à des services externes (le serveur peut être
# derrière un NAT), sinon adresse source de la route par défaut.
public_ipv4() {
    local ip url
    for url in https://api.ipify.org https://ifconfig.me/ip https://ipv4.icanhazip.com; do
        ip=$(curl -4 -fsS --max-time 5 "$url" 2>/dev/null || true)
        ip=${ip//[[:space:]]/}
        if is_ipv4 "$ip"; then
            printf '%s' "$ip"
            return 0
        fi
    done
    ip -4 route get 1.1.1.1 2>/dev/null \
        | awk '!found { for (i = 1; i < NF; i++) if ($i == "src") { print $(i+1); found = 1 } }'
}

# Un port est-il déjà utilisé ?  port_in_use tcp|udp PORT
port_in_use() {
    local out
    if [[ $1 == udp ]]; then
        out=$(ss -Hlun "sport = :$2" 2>/dev/null || true)
    else
        out=$(ss -Hltn "sport = :$2" 2>/dev/null || true)
    fi
    [[ -n $out ]]
}

reboot_server() {
    if confirm "Redémarrer le serveur maintenant ?" n; then
        printf '\nÀ bientôt !\n'
        systemctl reboot
        exit 0
    fi
}
