#!/bin/bash
# script auto install seedbox (transmission-daemon + nginx + vsftpd + fail2ban + let's encrypt)

# prochaine maj :
# - ajouter interface gestion des jails de fail2ban
# - plus de commentaires
# - ameliorer les retours d'erreur
# - éventuellement creer ou adatper le script pour du multi-users avec mise en place d'une politique de quota (pas grand chose à modifier, faut juste abandonner les users virtuels)

# compatible :
# - debian 7 wheezy / debian 8 jessie

source variables.sh
source functions.sh

#function motd(){
#	cat "$MOTD".bak > "$MOTD"
#	sed -i '/Accès/,$d' /etc/motd
#	echo "
#Accès Seedbox et FTP : $MON_DOMAINE
#
#Lancer gestion VPN: vpn.sh
#Lancer gestion Seedbox: seedbox.sh
#" >> /etc/motd
#}



####################################################
# début du script
####################################################
prerequis_seedbox
OS_DESC=$(lsb_release -ds)
clear && titre
if [[ -e "$TRANSMISSION" ]]; then
	OPTIONS="0"
	while [[ "$OPTIONS" != "Q" ]]; do
		clear && titre
		REP="0"
		read -p "LA SEEDBOX EST INSTALLEE SUR CE SERVEUR :
		
Accès seedbox et ftp: $MON_DOMAINE
Les données upload et download du FTP sont toujours conservées

1 ) Réinitialiser la configuration de la seedbox (renouveler certificat let's encrypt)
2 ) Supprimer installation

3 ) Redémarrer les services seedbox
4 ) Redémarrer le serveur

Q ) Taper Q pour quitter

Que voulez vous faire ? [1-6]: " -r OPTIONS
		case "$OPTIONS" in
			1)
			while [[ "$REP" != "Q" ]]; do
				clear && titre
				echo "REINITIALISER CONFIGURATION SEEDBOX"
				echo ""
				echo "Taper Q pour quitter"
				read -p "Voulez vous vraiment réinitialiser la configuration de vos services ? [Y/Q] " -r REP
				if [[ "$REP" = "Y" ]]; then
					echo ""
					stop_seedbox
					clear && titre
					echo "REINITIALISER CONFIGURATION SEEDBOX"
					echo "$OS_DESC"
					echo ""
					set_infos_seedbox
					installation_seedbox
					seedbox
					letsencrypt
					nginx
					vsftpd
					fail2ban
					start_seedbox
					clear && titre
					status_seedbox
					echo ""
					recap_install_seedbox
					echo ""
					echo "Réinitialisation seedbox terminée sauvegardez vos informations"
					read -p "Appuyez sur [Enter] pour revenir au menu précedent  ... " -r
					REP="Q"
				fi
			done
			;;
			2)
			while [[ "$REP" != "Q" ]]; do
				clear && titre
				echo "SUPPRIMER INSTALLATION SEEDBOX"
				echo ""
				echo "Taper Q pour quitter"
				read -p "Voulez vous vraiment supprimer vos services ? [Y/Q] " -r REP
				if [[ "$REP" = "Y" ]]; then
					echo ""
					stop_seedbox
					echo ""
					gpasswd -d debian-transmission ftp 
					cat "$TRANSMISSION".bak > "$TRANSMISSION"
					cat "$VSFTPD".bak > "$VSFTPD"
					cat "$NGINX".bak > "$NGINX"
					rm {"$TRANSMISSION".bak,"$NGINX".bak,"$VSFTPD".bak,"$VSFTPD_LOG","$JAIL_LOCAL","$HTPASSWD","$REGEX_RECID","$REGEX_NGINX","$REGEX_FTP","$DHPARAMS","$MON_CERT_KEY","$MON_CERT","$INFO"}
					rm /var/www/html/index.nginx-debian.html &>/dev/null
					sed -i '/Accès/,$d' /etc/motd
					apt-get purge -y minissdpd transmission-cli transmission-common transmission-daemon nginx-common nginx vsftpd fail2ban
					rm -rf /etc/vsftpd
					apt-get autoremove -y
					apt-get update -y
					clear && titre
					read -p "Désinstallation seedbox terminée appuyez sur [Enter] pour quitter... " -r
					echo ""
					echo "A bientôt"
					echo ""
					exit 0
				fi
			done
			;;
			3)
			echo ""
			stop_seedbox
			echo ""
			start_seedbox
			echo ""
			status_services
			echo ""
			read -p "Appuyez sur [Enter] " -r
			;;
			4)
			shutdown -r now
			echo ""
			echo "A bientôt"
			echo ""
			exit 0
			;;
			Q)
			echo ""
			echo "A bientôt"
			echo ""
			exit 0
		esac
	done
else
	clear && titre
	echo "INSTALLATION SERVEUR SEEDBOX"
	echo "$OS_DESC"
	echo ""
	set_infos_seedbox
	installation_seedbox
	echo ""
	stop_seedbox
	backup_seedbox
	seedbox
	clear && titre
	echo "Requete pour obtenir un certificat SSL delivré par let's encrypt"
	echo "patientez quelques minutes"
	echo ""
	letsencrypt
	clear && titre
	nginx
	vsftpd
	fail2ban
	start_seedbox
	clear && titre
	status_seedbox
	echo ""
	echo "RECAPITULATIF INSTALLATION SEEDBOX :"
	echo ""
	recap_install_seedbox
	echo ""
	echo "Installation terminée sauvegardez vos informations"
	read -p "Appuyez sur [Enter] pour redemarrer le serveur... " -r 
	shutdown -r now
	echo ""
	echo "A bientôt"
	echo ""
	exit 0
fi
