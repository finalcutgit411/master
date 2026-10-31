#!/usr/bin/env bash
# =============================================================================
#  finalcut — VPN WireGuard + seedbox sécurisée, pour Debian 12 / 13
#
#  VPN     : WireGuard, un port ouvert par client, QR code pour les mobiles
#  Seedbox : Transmission derrière nginx (HTTPS Let's Encrypt), accès SFTP,
#            fail2ban, mises à jour de sécurité automatiques
#
#  Sans argument : menu interactif. Avec une commande : utilisable dans un
#  script (voir « finalcut help »).
# =============================================================================
set -Eeuo pipefail

# Sur Debian, « su » sans tiret garde le PATH de l'utilisateur, sans
# /usr/sbin : sysctl, useradd, nft… y seraient introuvables.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"
export PATH

FC_DIR=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
# shellcheck source=lib/common.sh
. "$FC_DIR/lib/common.sh"
# shellcheck source=lib/vpn.sh
. "$FC_DIR/lib/vpn.sh"
# shellcheck source=lib/seedbox.sh
. "$FC_DIR/lib/seedbox.sh"
# shellcheck source=lib/firewall.sh
. "$FC_DIR/lib/firewall.sh"
# shellcheck source=lib/doctor.sh
. "$FC_DIR/lib/doctor.sh"
# shellcheck source=lib/maintenance.sh
. "$FC_DIR/lib/maintenance.sh"

trap 'fc_on_error $? $LINENO "$BASH_COMMAND" "${BASH_SOURCE[0]:-}"' ERR

usage() {
    cat <<EOF
finalcut $FC_VERSION — VPN WireGuard + seedbox pour Debian 12/13

Usage : finalcut [commande] [options]       (sans commande : menu interactif)

VPN
  vpn install [--config FICHIER]     installer (ou remettre en ordre avec --config)
  vpn add NOM [--qr]                 ajouter un client
  vpn remove NOM [--yes]             révoquer un client
  vpn list                           clients et connexions
  vpn show NOM                       QR code et fichier d'un client
  vpn restart | uninstall [--yes]

Seedbox
  seedbox install [--config FICHIER] [--staging]
  seedbox password [--user NOM]      changer le mot de passe (et le nom)
                                     (lu sur l'entrée standard hors terminal)
  seedbox domain NOM [--staging]     changer de domaine / redemander le certificat
  seedbox sftp-key add FICHIER.pub | list | remove N
  seedbox sftp-password on|off       autoriser le mot de passe en SFTP
  seedbox bans | unban IP            adresses bannies par fail2ban
  seedbox restart | uninstall [--yes] [--purge-data]

Serveur
  firewall enable|disable|status     pare-feu (tout refusé sauf le nécessaire)
  doctor                             diagnostic complet (code 1 si problème)
  backup [--output FICHIER] [--passphrase-file FICHIER]
  restore FICHIER [--passphrase-file FICHIER] [--yes]
  update                             passer à la dernière version publiée
  version | help

Options
  -c, --config FICHIER   réglages lus dans un fichier (voir examples/finalcut.conf)
  -y, --yes              répondre oui aux confirmations
  --staging              serveurs de test de Let's Encrypt (pas de limite, certificat non reconnu)
EOF
}

# Raccourci « finalcut » pour relancer le menu de n'importe où
install_shortcut() {
    local link=/usr/local/sbin/finalcut
    if [[ ! -e $link ]]; then ln -s "$FC_DIR/finalcut.sh" "$link" 2>/dev/null || true; fi
}

main_menu() {
    local choix vpn_txt sb_txt fw_txt
    while true; do
        vpn_load
        sb_load
        if vpn_installed; then
            vpn_txt="$(svc_state "wg-quick@$VPN_IF") · port $VPN_PORT/udp · $(vpn_count_clients) client(s)"
        else
            vpn_txt="${C_DIM}non installé${C_END}"
        fi
        if sb_installed; then
            sb_txt="$(svc_state transmission-daemon) · https://$SB_DOMAIN/"
        else
            sb_txt="${C_DIM}non installée${C_END}"
        fi
        if fw_enabled; then fw_txt="${C_GRN}actif${C_END}"; else fw_txt="${C_DIM}désactivé${C_END}"; fi

        titre
        printf '  VPN       : %s\n' "$vpn_txt"
        printf '  Seedbox   : %s\n' "$sb_txt"
        printf '  Pare-feu  : %s\n\n' "$fw_txt"
        if vpn_installed; then echo "1) Gérer le VPN"; else echo "1) Installer le VPN"; fi
        if sb_installed; then echo "2) Gérer la seedbox"; else echo "2) Installer la seedbox"; fi
        cat <<EOF
3) Pare-feu
4) Diagnostic

5) Sauvegarder / restaurer
6) Mettre à jour finalcut
7) Redémarrer le serveur

Q) Quitter
EOF
        echo
        ask choix "Votre choix" ""
        case ${choix,,} in
            1) vpn_main ;;
            2) sb_main ;;
            3) fw_menu ;;
            4) doctor_main ;;
            5) maintenance_menu ;;
            6) update_main ;;
            7) reboot_server ;;
            q)
                printf '\nÀ bientôt !\n\n'
                exit 0
                ;;
        esac
    done
}

# --- Lecture des options -----------------------------------------------------------
FC_ARGS=()
need_value() { [[ -n ${2-} && ${2-} != -* ]] || die "L'option $1 attend une valeur."; }
while (($#)); do
    case $1 in
        -y | --yes) FC_YES=1 ;;
        -c | --config)
            need_value "$1" "${2-}"
            FC_CONFIG=$2
            shift
            ;;
        --staging) FC_STAGING=1 ;;
        --qr) FC_QR=1 ;;
        --purge-data) FC_PURGE=1 ;;
        --output)
            need_value "$1" "${2-}"
            FC_OUTPUT=$2
            shift
            ;;
        --passphrase-file)
            need_value "$1" "${2-}"
            FC_PASSFILE=$2
            shift
            ;;
        --user)
            need_value "$1" "${2-}"
            FC_NEWUSER=$2
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            FC_ARGS+=("$@")
            break
            ;;
        # « - » seul désigne l'entrée standard (ex. sftp-key add -)
        -) FC_ARGS+=("$1") ;;
        -*) die "Option inconnue : $1   (aide : finalcut help)" ;;
        *) FC_ARGS+=("$1") ;;
    esac
    shift
done
set -- "${FC_ARGS[@]}"

case ${1-} in
    help)
        usage
        exit 0
        ;;
    version)
        echo "finalcut $FC_VERSION"
        exit 0
        ;;
esac

check_system
take_lock
install_shortcut
vpn_load
sb_load
fw_load

case ${1-} in
    "")
        require_tty
        main_menu
        ;;
    vpn) vpn_cli "${@:2}" ;;
    seedbox) sb_cli "${@:2}" ;;
    firewall) fw_cli "${@:2}" ;;
    doctor)
        doctor_main
        ((DOC_FAIL == 0)) || exit 1
        ;;
    backup) backup_main ;;
    restore) restore_main "${2-}" ;;
    update) update_main ;;
    *) die "Commande inconnue : $1   (aide : finalcut help)" ;;
esac
