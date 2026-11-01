#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — textes longs en français
#  Mêmes fonctions que lang/en.sh, nommées text_fr_<nom>.
#  Les messages courts sont dans lang/fr.txt.
# =============================================================================

text_fr_usage() {
    cat <<EOF
seedtunnel $APP_VERSION — VPN WireGuard + seedbox pour Debian 12/13

Utilisation : seedtunnel [commande] [options]      (sans commande : menu interactif)

VPN
  vpn install [--config FICHIER]     installer (ou remettre en ordre avec --config)
  vpn add NOM [--qr]                 ajouter un client
  vpn remove NOM [--yes]             révoquer un client
  vpn list                           clients et connexions
  vpn show NOM                       QR code et fichier d'un client
  vpn share NOM                      lien de téléchargement du fichier (usage unique)
  vpn restart | uninstall [--yes]

Seedbox
  seedbox install [--config FICHIER] [--staging]
  seedbox password [--user NOM]      changer le mot de passe (et le nom)
                                     (lu sur l'entrée standard hors terminal)
  seedbox domain NOM [--staging]     changer de domaine / redemander le certificat
  seedbox sftp-config [filezilla]    réglages SFTP : adresse pour WinSCP, fichier FileZilla
  seedbox sftp-key add FICHIER.pub | list | remove N
  seedbox sftp-key new               clé pour WinSCP / FileZilla (lien de téléchargement unique)
  seedbox sftp-password on|off       autoriser le mot de passe en SFTP
  seedbox bans | unban IP            adresses bannies par fail2ban
  seedbox restart | uninstall [--yes] [--purge-data]

Serveur
  firewall enable|disable|status     pare-feu (tout refusé sauf le nécessaire)
  doctor                             diagnostic complet (code 1 si problème)
  backup [--output FICHIER] [--passphrase-file FICHIER]
  backup list | share                liste des sauvegardes / lien de téléchargement
  backup auto on|off|status          sauvegarde chiffrée chaque semaine
  restore FICHIER [--passphrase-file FICHIER] [--yes]
  update                             passer à la dernière version publiée
  apply                              réappliquer la configuration enregistrée
  language en|fr                     langue des messages
  version | help

Options
  -c, --config FICHIER   réglages lus dans un fichier (voir examples/seedtunnel.conf)
  -y, --yes              répondre oui aux confirmations
  --staging              serveurs de test de Let's Encrypt (limites plus hautes, certificat non reconnu)
EOF
}

text_fr_vpn_client_help() {
    cat <<EOF
Téléphone  : application WireGuard → « + » → « Scanner un code QR ».
Ordinateur : application WireGuard → « Importer un tunnel depuis un fichier »,
             avec le fichier $VPN_CLIENTS_DIR/$name.conf
             Pour le récupérer sur l'ordinateur :  seedtunnel vpn share $name

Port ouvert pour ce client : ${C_BOLD}$port${C_RESET} (TCP et UDP)
  Les connexions entrantes sur $VPN_PUBLIC_ADDRESS:$port arrivent chez ce
  client quand il est connecté : mettez ce port dans votre logiciel torrent.

Si le tunnel tombe, l'appareil sort sans lui, avec sa vraie adresse.
Pour bloquer tout ce qui passe hors du tunnel (kill switch) :
  Windows     : application WireGuard → Modifier le tunnel → cochez la case « kill-switch ».
  Android     : Paramètres → VPN → WireGuard (roue dentée) → « VPN permanent » et « Bloquer les connexions sans VPN ».
  qBittorrent : Options → Avancé → Interface réseau → le tunnel WireGuard.
EOF
}

text_fr_share_steps_vpn() {
    cat <<'EOF'
<li>Ordinateur : application WireGuard → importer un tunnel depuis un fichier → choisissez ce fichier.</li>
<li>Téléphone : application WireGuard → « + » → importer depuis un fichier.</li>
<li>Si le tunnel tombe, l'appareil sort sans lui. Pour bloquer tout ce qui passe hors du tunnel (kill switch) : sous Windows, modifiez le tunnel et cochez la case « kill-switch » ; sous Android, Paramètres → VPN → WireGuard → « VPN permanent » et « Bloquer les connexions sans VPN » ; dans qBittorrent, Options → Avancé → Interface réseau → le tunnel WireGuard.</li>
EOF
}

text_fr_seedbox_domain_help() {
    cat <<'EOF'
Nom de domaine de la seedbox. Sans domaine à vous, l'hébergeur en fournit
souvent un (ex. vps-1234abcd.vps.ovh.net). À défaut, entrez l'adresse IP :
un certificat auto-signé sera utilisé (alerte du navigateur à accepter).
EOF
}

text_fr_letsencrypt_failed_help() {
    cat <<EOF
  Causes fréquentes : port 80 bloqué par le pare-feu de l'hébergeur, DNS pas
  encore propagé, ou plus de 5 certificats demandés cette semaine pour ce nom
  (pour vos essais, utilisez --staging). Détails dans $APP_LOG.
  Pour réessayer :  seedtunnel seedbox domain $SEEDBOX_DOMAIN
EOF
}

text_fr_seedbox_summary() {
    cat <<EOF
${C_BOLD}Interface web${C_RESET} : https://$SEEDBOX_DOMAIN/   (certificat $(seedbox_certificate_label))
${C_BOLD}SFTP${C_RESET}          : $SEEDBOX_DOMAIN, port $port (WinSCP, FileZilla, Cyberduck : protocole SFTP)
                réglages prêts à importer :  seedtunnel seedbox sftp-config
${C_BOLD}Utilisateur${C_RESET}   : $SEEDBOX_USER
EOF
    if [[ -n $SEEDBOX_NEW_PASSWORD ]]; then
        printf '%sMot de passe%s  : %s\n' "$C_BOLD" "$C_RESET" "$SEEDBOX_NEW_PASSWORD"
    fi
    cat <<'EOF'

Dossiers (vus en SFTP) :
  watch/       déposez un .torrent ici, le téléchargement démarre tout seul
  incomplete/  téléchargements en cours
  complete/    téléchargements terminés
  documents/   espace personnel

EOF
    if [[ $SEEDBOX_CERTIFICATE == selfsigned ]]; then
        echo "Certificat auto-signé : le navigateur affichera une alerte à accepter une fois."
        echo
    fi
    if [[ -n $SEEDBOX_NEW_PASSWORD ]]; then
        echo "Notez ces informations : le mot de passe n'est enregistré nulle part en clair."
    fi
}

text_fr_sftp_config_help() {
    cat <<EOF
${C_BOLD}WinSCP${C_RESET} : dans la fenêtre de connexion, « Nouveau site », collez cette adresse
dans « Nom d'hôte », puis « Enregistrer » :

$url

L'empreinte du serveur est dans l'adresse : WinSCP vérifie tout seul que c'est
bien votre serveur, sans question à la première connexion.
EOF
}

text_fr_share_steps_filezilla() {
    cat <<EOF
<li>FileZilla : « Fichier » → « Importer… » → choisissez ce fichier.</li>
<li>Le site « Seedbox $SEEDBOX_DOMAIN » apparaît dans le gestionnaire de sites. Le mot de passe est demandé à la connexion.</li>
<li>À la première connexion, l'empreinte du serveur doit être : <code>$fingerprint</code></li>
EOF
}

text_fr_share_steps_sftp_key() {
    cat <<'EOF'
<li>Gardez ce fichier sur votre ordinateur, dans un dossier que vous conservez (pas dans Téléchargements).</li>
<li>WinSCP : dans la fenêtre de connexion, sur votre site (pour un site déjà enregistré, passez-le d'abord en modification) : « Avancé… » → « SSH » → « Authentification » → « Fichier de clé privée » : choisissez ce fichier → « OK » → « Enregistrer ».</li>
<li>FileZilla : « Gestionnaire de sites » → votre site → « Type d'authentification » : « Fichier de clé » → choisissez ce fichier.</li>
EOF
}

text_fr_seedbox_uninstall_help() {
    cat <<EOF
Seront supprimés : Transmission, nginx, certbot, fail2ban, l'utilisateur $SEEDBOX_USER
et le certificat. Les données dans $SEEDBOX_DATA_DIR sont conservées, sauf avec
--purge-data (ou si vous le demandez ci-dessous).
EOF
}

text_fr_backup_contents() {
    cat <<'EOF'
Contenu : clés et clients du VPN, réglages et hash des mots de passe de la
seedbox, pare-feu, certificats, liste des torrents. Les fichiers téléchargés ne
sont pas inclus.
EOF
}

text_fr_backup_after() {
    cat <<'EOF'
  Récupérez-la sur votre ordinateur, hors de ce serveur :  seedtunnel backup share
  Sans la passphrase, elle est irrécupérable.
EOF
}

text_fr_share_steps_backup() {
    cat <<EOF
<li>Gardez ce fichier sur votre ordinateur, ou sur une clé USB.</li>
<li>Sa taille doit être de <b>$size</b>. Si le téléchargement s'est arrêté avant la fin, le lien est quand même consommé : créez-en un autre avec <code>seedtunnel backup share</code>.</li>
<li>Pour le restaurer sur un nouveau serveur : installez seedtunnel, copiez-y le fichier, puis lancez <code>seedtunnel restore FICHIER</code>.</li>
EOF
}

text_fr_backup_auto_help() {
    cat <<EOF
Chaque semaine, une sauvegarde chiffrée se fait toute seule dans $BACKUP_DIR ;
les $BACKUP_KEEP dernières sont gardées. Sa passphrase est enregistrée sur le
serveur (root uniquement) pour qu'elle puisse tourner seule : notez-la aussi ailleurs.
EOF
}

text_fr_restore_after() {
    cat <<EOF
  Recopiez les fichiers téléchargés dans $SEEDBOX_DATA_DIR, par exemple :
    rsync -a --info=progress2 ancien-serveur:$SEEDBOX_DATA_DIR/ $SEEDBOX_DATA_DIR/
  puis :  seedtunnel seedbox restart   (Transmission retrouve ses torrents)
EOF
}
