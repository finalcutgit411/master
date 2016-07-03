#!/bin/bash
#!/bin/bash
# script auto install seedbox (transmission-daemon + nginx + vsftpd + fail2ban + let's encrypt)

# prochaine maj :
# - plus de visilbilté dans les jails
# - plus de commentaires
# - ameliorer les retours d'erreur
# - éventuellement creer ou adatper le script pour du multi-users avec mise en place d'une politique de quota (pas grand chose à modifier, faut juste abandonner les users virtuels)

# compatible :
# - debian 7 wheezy / debian 8 jessie

INCLUDES="includes"
. "$INCLUDES"/variables.sh
. "$INCLUDES"/functions.sh

if [[ "$EUID" -ne 0 ]]; then
	echo "Seul l'utilisateur root peut executer ce script"
	read -p "Appuyez sur [Enter] pour quitter " -r
	exit
else
	cd ~/ || exit
	mkdir -p /usr/local/bin/includes
	wget https://raw.githubusercontent.com/finalcutgit411/master/master/scripts/vpn.sh --no-check-certificate
	chmod 700 vpn.sh
	rm -f /usr/local/bin/vpn.sh
	mv vpn.sh /usr/local/bin/

	wget https://raw.githubusercontent.com/finalcutgit411/master/master/scripts/seedbox.sh --no-check-certificate
	chmod 700 seedbox.sh
	rm -f /usr/local/bin/seedbox.sh
	mv seedbox.sh /usr/local/bin/

	wget https://raw.githubusercontent.com/finalcutgit411/master/master/includes/functions.sh --no-check-certificate
	chmod 700 functions.sh
	rm -f /usr/local/bin/includes/functions.sh
	mv functions.sh /usr/local/bin/includes/

	wget https://raw.githubusercontent.com/finalcutgit411/master/master/includes/variables.sh --no-check-certificate
	chmod 700 variables.sh
	rm -f /usr/local/bin/includes/variables.sh
	mv variables.sh /usr/local/bin/includes/
fi

while [[ "$OPTIONS" != "Q" ]]; do
	clear
	titre
	echo "
1 ) Installation et gestion de votre VPN
2 ) Installation et gestion de votre Seedbox

Q ) Taper Q pour quitter"

		read -p "Que voulez vous faire ? [1-2]: " -r OPTIONS
		case "$OPTIONS" in
			1) $SCRIPT_VPN
			;;
			2) $SCRIPT_SEEDBOX
			;;
			Q)
			echo ""
			echo "A bientôt"
			echo ""
			exit 0
		esac
done
