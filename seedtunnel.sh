#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — WireGuard VPN + secure seedbox, for Debian 12 / 13
#
#  VPN     : WireGuard, one open port per client, QR codes for phones
#  Seedbox : Transmission behind nginx (HTTPS with Let's Encrypt), SFTP access,
#            fail2ban, automatic security updates, weekly backups
#
#  Without arguments: interactive menu. With a command: usable from scripts
#  (see « seedtunnel help »). Messages in English or in French.
# =============================================================================
set -Eeuo pipefail

# On Debian, « su » without a dash keeps the PATH of the user, without
# /usr/sbin: sysctl, useradd, nft… would not be found.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"
export PATH

APP_DIR=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
# shellcheck source=lib/common.sh
. "$APP_DIR/lib/common.sh"
# shellcheck source=lib/i18n.sh
. "$APP_DIR/lib/i18n.sh"
# shellcheck source=lib/vpn.sh
. "$APP_DIR/lib/vpn.sh"
# shellcheck source=lib/seedbox.sh
. "$APP_DIR/lib/seedbox.sh"
# shellcheck source=lib/firewall.sh
. "$APP_DIR/lib/firewall.sh"
# shellcheck source=lib/share.sh
. "$APP_DIR/lib/share.sh"
# shellcheck source=lib/diskguard.sh
. "$APP_DIR/lib/diskguard.sh"
# shellcheck source=lib/backup.sh
. "$APP_DIR/lib/backup.sh"
# shellcheck source=lib/update.sh
. "$APP_DIR/lib/update.sh"
# shellcheck source=lib/doctor.sh
. "$APP_DIR/lib/doctor.sh"

trap 'on_error $? $LINENO "$BASH_COMMAND" "${BASH_SOURCE[0]:-}"' ERR

# « seedtunnel » shortcut to open the menu from anywhere. It goes into
# /usr/local/bin, in the PATH even after a « su » without a dash.
install_shortcut() {
    local link=/usr/local/bin/seedtunnel
    if [[ ! -e $link ]]; then ln -s "$APP_DIR/seedtunnel.sh" "$link" 2>/dev/null || true; fi
}

# State of the server at the top of the main menu
menu_status() {
    local vpn_text seedbox_text disk_text firewall_text
    if vpn_installed; then
        vpn_text="$(service_state "wg-quick@$VPN_INTERFACE") · port $VPN_PORT/udp"
        vpn_text+=" · $(t '%s connected of %s client(s)' "$(vpn_connected_count)" "$(vpn_count_clients)")"
    else
        vpn_text="$C_DIM$(t 'not installed')$C_RESET"
    fi
    if seedbox_installed; then
        if diskguard_stopped; then
            seedbox_text="$C_RED$(t 'stopped: disk almost full')$C_RESET · https://$SEEDBOX_DOMAIN/"
        else
            seedbox_text="$(service_state transmission-daemon) · https://$SEEDBOX_DOMAIN/"
        fi
        if ! systemctl is-active --quiet nginx; then seedbox_text+=" · $C_RED$(t 'nginx stopped')$C_RESET"; fi
    else
        seedbox_text="$C_DIM$(t 'not installed')$C_RESET"
    fi
    disk_text=$(disk_free_text /)
    if seedbox_installed && [[ -d $SEEDBOX_DATA_DIR ]]; then
        if [[ $(df --output=target "$SEEDBOX_DATA_DIR" 2>/dev/null | tail -n 1) == "$(df --output=target / 2>/dev/null | tail -n 1)" ]]; then
            disk_text+=" $(t '(system and downloads)')"
        else
            # downloads on another disk: both are shown
            disk_text="$(t 'system %s · downloads %s' "$disk_text" "$(disk_free_text "$SEEDBOX_DATA_DIR")")"
        fi
    fi
    if firewall_enabled; then
        firewall_text="$C_GREEN$(t 'on')$C_RESET"
    else
        firewall_text="$C_DIM$(t 'off')$C_RESET"
    fi
    printf '  %-10s: %s\n' "VPN" "$vpn_text"
    printf '  %-10s: %s\n' "Seedbox" "$seedbox_text"
    printf '  %-10s: %s\n' "$(t 'Disk')" "$disk_text"
    printf '  %-10s: %s\n\n' "$(t 'Firewall')" "$firewall_text"
}

main_menu() {
    local choice
    while true; do
        vpn_load
        seedbox_load
        banner
        menu_status
        if vpn_installed; then say '1) Manage the VPN'; else say '1) Install the VPN'; fi
        if seedbox_installed; then say '2) Manage the seedbox'; else say '2) Install the seedbox'; fi
        say '3) Firewall'
        say '4) Diagnostics'
        echo
        say '5) Backup / restore'
        say '6) Update seedtunnel'
        say '7) Restart the server'
        echo
        printf '%s\n' 'L) Language / Langue'
        say 'Q) Quit'
        echo
        ask choice 'Your choice' ""
        case ${choice,,} in
            1) vpn_main ;;
            2) seedbox_main ;;
            3) firewall_menu ;;
            4) doctor_main ;;
            5) backup_menu ;;
            6) update_main ;;
            7) reboot_server ;;
            l) language_menu ;;
            q)
                echo
                say 'See you soon!'
                echo
                exit 0
                ;;
        esac
    done
}

# --- Options ---------------------------------------------------------------------------
ARGUMENTS=()
need_value() { [[ -n ${2-} && ${2-} != -* ]] || die 'The option %s needs a value.' "$1"; }

# language first, so that even the errors below are translated
i18n_init

while (($#)); do
    case $1 in
        -y | --yes) OPT_YES=1 ;;
        -c | --config)
            need_value "$1" "${2-}"
            OPT_CONFIG_FILE=$2
            shift
            ;;
        --staging) OPT_STAGING=1 ;;
        --qr) OPT_QR=1 ;;
        --purge-data) OPT_PURGE_DATA=1 ;;
        --output)
            need_value "$1" "${2-}"
            OPT_OUTPUT_FILE=$2
            shift
            ;;
        --passphrase-file)
            need_value "$1" "${2-}"
            OPT_PASSPHRASE_FILE=$2
            shift
            ;;
        --user)
            need_value "$1" "${2-}"
            OPT_NEW_USER=$2
            shift
            ;;
        -h | --help)
            text usage
            exit 0
            ;;
        --)
            shift
            ARGUMENTS+=("$@")
            break
            ;;
        # « - » alone means standard input (e.g. sftp-key add -)
        -) ARGUMENTS+=("$1") ;;
        -*) die 'Unknown option: %s   (help: seedtunnel help)' "$1" ;;
        *) ARGUMENTS+=("$1") ;;
    esac
    shift
done
set -- "${ARGUMENTS[@]}"

case ${1-} in
    help)
        text usage
        exit 0
        ;;
    version)
        printf 'seedtunnel %s\n' "$APP_VERSION"
        exit 0
        ;;
esac

check_system
# Commands that change nothing (or only add a backup file) do not wait for the
# lock: they work even if a menu was left open in another window.
case "${1-} ${2-} ${3-}" in
    "doctor  " | "diskguard-check  " | "diskguard-prestart  " | "backup  " | "backup list " | "backup auto run" | "backup auto status" | "backup auto ") ;;
    *) take_lock ;;
esac
install_shortcut
vpn_load
seedbox_load
firewall_load

case ${1-} in
    "")
        require_terminal
        language_first_run
        main_menu
        ;;
    vpn) vpn_cli "${@:2}" ;;
    seedbox) seedbox_cli "${@:2}" ;;
    firewall) firewall_cli "${@:2}" ;;
    doctor)
        doctor_main
        ((DOCTOR_ERRORS == 0)) || exit 1
        ;;
    backup) backup_cli "${@:2}" ;;
    restore) restore_main "${2-}" ;;
    update) update_main ;;
    apply) apply_main ;;
    language) language_cli "${2-}" ;;
    diskguard-check) diskguard_check ;;
    diskguard-prestart) diskguard_prestart || exit 1 ;;
    *) die 'Unknown command: %s   (help: seedtunnel help)' "$1" ;;
esac
