#!/bin/bash
# script auto install seedbox (transmission-daemon + nginx + vsftpd + fail2ban + let's encrypt)

# prochaine maj :
# - plus de visilbilté dans les jails
# - plus de commentaires
# - ameliorer les retours d'erreur
# - éventuellement creer ou adatper le script pour du multi-users avec mise en place d'une politique de quota (pas grand chose à modifier, faut juste abandonner les users virtuels)

# compatible :
# - debian 7 wheezy / debian 8 jessie

source variables.sh
source functions.sh

if [[ "$EUID" -ne 0 ]]; then
	_titre
	printf "%s\n" "Seul l'utilisateur root peut executer ce script"
	read -p "Appuyez sur [Enter] pour quitter " -r
	exit
fi

while [[ "$OPTIONS" != "Q" ]]; do
	_titre
	if [[ -e "$OPENVPN" ]]; then printf "%s\n" "1 ) Gestion de votre VPN"; else printf "%s\n" "1 ) Installation de votre VPN"; fi
	if [[ -e "$TRANSMISSION" ]]; then printf "%s\n" "2 ) Gestion de votre Seedbox"; else printf "%s\n" "2 ) Installation de votre Seedbox"; fi
	printf "%s\n" "" "3 ) Redémarrer le serveur" "" "Q ) Taper Q pour quitter"
	read -p "Que voulez vous faire ? [1-3]: " -r OPTIONS
		case "$OPTIONS" in
			1) $SCRIPT_VPN
			;;
			2) $SCRIPT_SEEDBOX
			;;
			3)
			shutdown -r now
			printf "%s\n" "" "A bientôt" ""
			exit 0
			;;
			Q)
			printf "%s\n" "" "A bientôt" ""
			exit 0
		esac
done
