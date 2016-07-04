#!/bin/bash
# shellcheck source=/dev/null
# script auto install VPN

# prochaine maj :
# - porter compatibilté chroot vpn + pid
# - si netfilter actif ajouter règles iptables 

# compatible :
# - debian 7 wheezy / debian 8 jessie

source variables.sh
source functions.sh

prerequis_vpn
OS_DESC=$(lsb_release -ds)
clear
titre
if [[ -e "$OPENVPN" ]]; then
	OPTIONS="0"
	while [[ "$OPTIONS" != "Q" ]]; do
		clear
		REP="0" && ADD_VPN="5"
		read -p "LE VPN EST INSTALLE SUR CE SERVEUR :

1 ) Ajouter des clients
2 ) Revoquer des clients
3 ) Renvoyer les clients dans le dossier /tmp/clients

4 ) Réinitialiser la configuration du vpn
5 ) Supprimer l'installation du vpn

6 ) Voir les clients connectés au vpn

7 ) Redémarrer le vpn
8 ) Redémarrer le serveur

Q ) Taper Q pour quitter

Que voulez vous faire ? [1-8]: " -r OPTIONS
		case "$OPTIONS" in
			1)
			while [[ "$REP" != "Q" ]]; do
				LIST_VPN=$(grep -c 'client' "$INDEX")
				VALID=$(grep 'V' "$INDEX" | grep -c 'client')
				REVOK=$(grep 'R' "$INDEX" | grep -c 'client')
				DISPO=$((62-LIST_VPN))
				clear
				read -p "AJOUTER DES CLIENTS VPN

Vous avez $LIST_VPN client(s) VPN installé(s) sur votre serveur.
Vous pouvez avec cette configuration installer un total maximun
de 62 clients.

Recapitulatif :
$VALID client(s) vpn autorisé(s)
$REVOK client(s) vpn revoqué(s)
$DISPO client(s) vpn disponible(s)
		
Taper Q pour quitter

Combien de client(s) voulez-vous ajouter ? " -r REP
				ADD_VPN="$REP"
				if [[ "$REP" -gt "0" ]] && [[ "$REP" -le "$DISPO" ]]; then
					create_cert_clients
					create_rep_clients
					nat
					clear
					echo "Liste client(s) VPN actif(s) :"
					grep 'V' $INDEX | grep -o 'client[0-9]*' | awk -F "client" '{print "client : " $2}'
					echo ""	
					echo "Vous devez redémarrer le serveur pour activer les règles NAT des clients VPN"
					read -p "Appuyez sur [Enter] pour revenir au menu précedent ... " -r
					REP="Q"
				fi
			done
			;;

			2)
			while [[ "$REP" != "Q" ]]; do
				VALID=$(grep 'V' "$INDEX" | grep -c 'client')
				VERIF=$(grep 'V' $INDEX | grep -o 'client[0-9]*' | awk -F 'client' '{print $2}')
				clear
				echo "$VALID client(s) vpn actif(s) sur le serveur"
				echo "Liste client(s) VPN actif(s) :"
				grep 'V' $INDEX | grep -o 'client[0-9]*' | awk -F "client" '{print "client : " $2}'
				echo ""
				echo "Taper Q pour quitter"
				read -p "Taper le numéro du client à révoquer : " -r REP
				if [[ "$REP" != "Q" ]]; then
					for i in $VERIF; do
						if [[ "$REP" = "$i" ]]; then
							echo ""
							read -p "Vous avez selectionné le client $REP, merci de confirmer [Y/N] " -r CONF
							if [[ "$CONF" = "Y" ]]; then
								DEL_VPN="$REP"
								revoke_cert_client
								create_rep_clients
								echo ""
								read -p "Appuyez sur [Enter] pour revenir au menu précedent " -r
								REP="Q" && CONF="0"
							fi
						fi
					done
				fi
			done
			;;

			3)
			clear
			create_rep_clients
			tree -vd /tmp/clients
			echo ""
			echo "Vos dossiers de clients VPN sont dans /tmp/clients/"
			echo ""
			echo "Infos :"
			echo "Si vous etes sur Windows, utilisez winscp (voir video)"
			echo "Si vous etes sur Linux ou Mac copier dans votre terminal la commande scp suivante :"
			echo "scp -P 22 -r root@$IP:/tmp/clients ./"
			echo ""
			read -p "Appuyez sur [Enter] pour revenir au menu précedent " -r 
			;;

			4)
			while [[ "$REP" != "Q" ]]; do
			clear
				read -p "REINITIALISER CERTIFICATS SERVEUR VPN

Taper Q pour quitter
Voulez vous vraiment réinitialiser les certificats du serveur ? [Y/Q] " -r REP
				if [[ "$REP" = "Y" ]]; then
					clear
					echo "EXEMPLE INFORMATIONS A SAISIR :"
					show_infos_vpn
					echo ""
					set_infos_vpn
					clear
					echo "INSTALLATION SERVEUR VPN"
					echo "$OS_DESC"
					echo ""
					installation_vpn
					if [[ "$PORT_VPN" = "443" ]]; then stop_seedbox && sed -i "s/127.0.0.1:9090/443/" "$NGINX"; else stop_seedbox && sed -i "s/127.0.0.1:9090/443/" "$NGINX"; fi
					stop_openvpn
					vpn
					clear
					echo "Création des certificats VPN"
					echo "Info : Sur un serveur dédié cette étape peut-etre très longue"
					create_cert_serveur
					create_cert_clients
					conf_serveur
					conf_client
					create_rep_clients
					nat
					clear
					titre
					echo "INSTALLATION VPN TERMINEE"
					recap_install_vpn
					echo ""
					read -p "Appuyez sur [Enter] pour redemarrer le serveur... " -r 
					shutdown -r now
					exit 0
				fi
			done
			;;

			5)
			while [[ "$REP" != "Q" ]]; do
			clear
				echo "SUPPRIMER INSTALLATION VPN"
				echo ""
				echo "Taper Q pour quitter"
				read -p "Voulez vous vraiment supprimer vos services ? [Y/Q] " -r REP
				if [[ "$REP" = "Y" ]]; then
					if [[ "$PORT_VPN" = "443" ]]; then stop_seedbox && sed -i "s/127.0.0.1:9090/443/" "$NGINX" &>/dev/null; fi
					stop_openvpn
					cat "$SYSCTL".bak > "$SYSCTL"
					cat "$RC".bak > "$RC"
					rm {"$SYSCTL".bak,"$RC".bak}
					rm -rf /etc/openvpn/*
					apt-get purge -y openvpn
					apt-get autoremove -y
					apt-get update -y
					read -p "Appuyez sur [Enter] pour redemarrer le serveur... " -r
					shutdown -r now
					exit 0
				fi
			done
			;;

			6)
			clear
			echo "Les clients connectés au vpn"
			echo ""
			cat $STATUS
			echo ""
			read -p "Appuyez sur [Enter] pour revenir au menu précedent " -r 
			;;

			7)
			echo ""
			stop_openvpn
			start_openvpn
			status_openvpn
			echo ""
			read -p "Appuyez sur [Enter] " -r
			;;
			
			8)
			shutdown -r now
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
	clear
	titre
	echo "EXEMPLE INFORMATIONS A SAISIR :"
	show_infos_vpn
	echo ""
	set_infos_vpn
	clear
	echo "INSTALLATION SERVEUR VPN"
	echo "$OS_DESC"
	echo ""
	installation_vpn
	stop_openvpn
	backup_vpn
	vpn
	clear
	echo "Création des certificats VPN"
	echo "Info : Sur un serveur dédié cette étape peut-etre très longue"
	create_cert_serveur
	create_cert_clients
	conf_serveur
	conf_client
	create_rep_clients
	nat
	clear
	titre
	echo "INSTALLATION VPN TERMINEE"
	echo ""
	echo "Installation terminée sauvegardez vos informations"
	read -p "Appuyez sur [Enter] pour redemarrer le serveur... " -r 
	shutdown -r now
	exit 0
fi
