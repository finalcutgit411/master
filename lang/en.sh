#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — long texts in English
#  Each text is a function text_en_<name>, shown with « text <name> ».
#  lang/fr.sh has the same functions in French (text_fr_<name>).
#  Variables are those of the function that shows the text.
# =============================================================================

text_en_usage() {
    cat <<EOF
seedtunnel $APP_VERSION — WireGuard VPN + seedbox for Debian 12/13

Usage: seedtunnel [command] [options]       (no command: interactive menu)

VPN
  vpn install [--config FILE]        install (or put back in order with --config)
  vpn add NAME [--qr]                add a client
  vpn remove NAME [--yes]            revoke a client
  vpn list                           clients and connections
  vpn show NAME                      QR code and file of a client
  vpn share NAME                     one-time download link for the file
  vpn restart | uninstall [--yes]

Seedbox
  seedbox install [--config FILE] [--staging]
  seedbox password [--user NAME]     change the password (and the name)
                                     (read from standard input without a terminal)
  seedbox domain NAME [--staging]    change the domain / request the certificate again
  seedbox sftp-config [filezilla]    SFTP settings: address for WinSCP, FileZilla file
  seedbox sftp-key add FILE.pub | list | remove N
  seedbox sftp-key new               key for WinSCP / FileZilla (one-time download link)
  seedbox sftp-password on|off       allow the password in SFTP
  seedbox bans | unban IP            addresses banned by fail2ban
  seedbox restart | uninstall [--yes] [--purge-data]

Server
  firewall enable|disable|status     firewall (everything refused but the needed)
  doctor                             full diagnostics (status 1 if a problem)
  backup [--output FILE] [--passphrase-file FILE]
  backup list | share                list the backups / one-time download link
  backup auto on|off|status          weekly encrypted backup
  restore FILE [--passphrase-file FILE] [--yes]
  update                             go to the latest published version
  apply                              apply the saved configuration again
  language en|fr                     language of the messages
  version | help

Options
  -c, --config FILE      settings read from a file (see examples/seedtunnel.conf)
  -y, --yes              answer yes to the confirmations
  --staging              Let's Encrypt test servers (no limit, untrusted certificate)
EOF
}

text_en_vpn_client_help() {
    cat <<EOF
Phone    : WireGuard app → « + » → « Scan from QR code ».
Computer : WireGuard app → « Import tunnel(s) from file », with the file
           $VPN_CLIENTS_DIR/$name.conf
           To get it onto the computer:  seedtunnel vpn share $name

Open port for this client: ${C_BOLD}$port${C_RESET} (TCP and UDP)
  Incoming connections on $VPN_PUBLIC_ADDRESS:$port reach this client while
  it is connected: set this port in your torrent program.
EOF
}

text_en_share_steps_vpn() {
    cat <<'EOF'
<li>Computer: WireGuard app → import a tunnel from a file → choose this file.</li>
<li>Phone: WireGuard app → « + » → import from a file.</li>
EOF
}

text_en_seedbox_domain_help() {
    cat <<'EOF'
Domain name of the seedbox. Without a domain of your own, the provider often
gives one (e.g. vps-1234abcd.vps.ovh.net). Otherwise, type the IP address:
a self-signed certificate will be used (browser warning to accept).
EOF
}

text_en_letsencrypt_failed_help() {
    cat <<EOF
  Common causes: port 80 blocked by the firewall of the provider, DNS not
  propagated yet, or more than 5 certificates requested this week for this
  name (for your tests, use --staging). Details in $APP_LOG.
  To try again:  seedtunnel seedbox domain $SEEDBOX_DOMAIN
EOF
}

text_en_seedbox_summary() {
    cat <<EOF
${C_BOLD}Web interface${C_RESET} : https://$SEEDBOX_DOMAIN/   (certificate $(seedbox_certificate_label))
${C_BOLD}SFTP${C_RESET}          : $SEEDBOX_DOMAIN, port $port (WinSCP, FileZilla, Cyberduck: SFTP protocol)
                settings ready to import:  seedtunnel seedbox sftp-config
${C_BOLD}User${C_RESET}          : $SEEDBOX_USER
EOF
    if [[ -n $SEEDBOX_NEW_PASSWORD ]]; then
        printf '%sPassword%s      : %s\n' "$C_BOLD" "$C_RESET" "$SEEDBOX_NEW_PASSWORD"
    fi
    cat <<'EOF'

Folders (seen in SFTP):
  watch/       drop a .torrent here, the download starts by itself
  incomplete/  downloads in progress
  complete/    finished downloads
  documents/   personal space

EOF
    if [[ $SEEDBOX_CERTIFICATE == selfsigned ]]; then
        echo "Self-signed certificate: the browser will show a warning to accept once."
        echo
    fi
    if [[ -n $SEEDBOX_NEW_PASSWORD ]]; then
        echo "Write this down: the password is not saved anywhere in clear."
    fi
}

text_en_sftp_config_help() {
    cat <<EOF
${C_BOLD}WinSCP${C_RESET}: in the login window, « New Site », paste this address into
« Host name », then « Save »:

$url

The fingerprint of the server is inside the address: WinSCP checks by itself
that it is really your server, without a question at the first connection.
EOF
}

text_en_share_steps_filezilla() {
    cat <<EOF
<li>FileZilla: « File » → « Import… » → choose this file.</li>
<li>The site « Seedbox $SEEDBOX_DOMAIN » shows in the Site Manager. The password is asked when connecting.</li>
<li>At the first connection, the fingerprint of the server must be: <code>$fingerprint</code></li>
EOF
}

text_en_share_steps_sftp_key() {
    cat <<'EOF'
<li>Keep this file on your computer, in a folder you keep (not in Downloads).</li>
<li>WinSCP: in the login window, on your site (for a saved site, edit it first): « Advanced… » → « SSH » → « Authentication » → « Private key file »: choose this file → « OK » → « Save ».</li>
<li>FileZilla: « Site Manager » → your site → « Logon Type »: « Key file » → choose this file.</li>
EOF
}

text_en_seedbox_uninstall_help() {
    cat <<EOF
Will be removed: Transmission, nginx, certbot, fail2ban, the user $SEEDBOX_USER
and the certificate. The data in $SEEDBOX_DATA_DIR is kept, unless --purge-data
is given (or you ask for it below).
EOF
}

text_en_backup_contents() {
    cat <<'EOF'
Content: keys and clients of the VPN, settings and password hashes of the
seedbox, firewall, certificates, list of torrents. Downloaded files are not
included.
EOF
}

text_en_backup_after() {
    cat <<'EOF'
  Get it onto your computer, outside this server:  seedtunnel backup share
  Without the passphrase, it cannot be recovered.
EOF
}

text_en_share_steps_backup() {
    cat <<'EOF'
<li>Keep this file on your computer, or on a USB drive.</li>
<li>To restore it on a new server: install seedtunnel, copy the file onto it, then run <code>seedtunnel restore FILE</code>.</li>
EOF
}

text_en_backup_auto_help() {
    cat <<EOF
Every week, an encrypted backup is made by itself in $BACKUP_DIR; the
last $BACKUP_KEEP are kept. Its passphrase is saved on the server (root only)
so that it can run alone: also write it down somewhere else.
EOF
}

text_en_restore_after() {
    cat <<EOF
  Copy the downloaded files back into $SEEDBOX_DATA_DIR, for example:
    rsync -a --info=progress2 old-server:$SEEDBOX_DATA_DIR/ $SEEDBOX_DATA_DIR/
  then:  seedtunnel seedbox restart   (Transmission finds its torrents again)
EOF
}
