#!/bin/bash

# script auto install VPN
# prochaine maj :
# - porter compatibilté chroot vpn + pid
# - si netfilter actif ajouter règles iptables 

# compatible :
# - debian 7 wheezy / debian 8 jessie

source variables.sh
source functions.sh
_prerequis_vpn
OS_DESC=$(lsb_release -ds)
_titre
if [[ -e "$OPENVPN" ]]; then
	OPTIONS="0"
	while [[ "$OPTIONS" != "Q" ]]; do
		_titre
		REP="0" && ADD_VPN="5"
		printf "%s\n" "1 ) Ajouter des clients" "2 ) Revoquer des clients" "3 ) Renvoyer les clients dans le dossier /tmp/clients" "" "4 ) Réinitialiser la configuration du vpn" "5 ) Supprimer l'installation du vpn" "" "6 ) Voir les clients connectés au vpn" "" "7 ) Redémarrer le vpn" "8 ) Redémarrer le serveur" "" "Q ) Taper Q pour quitter " ""
		read -p "Que voulez vous faire ? [1-8]: " -r OPTIONS
		case "$OPTIONS" in
			1)
			while [[ "$REP" != "Q" ]]; do
				LIST_VPN=$(grep -c 'client' "$INDEX")
				VALID=$(grep 'V' "$INDEX" | grep -c 'client')
				REVOK=$(grep 'R' "$INDEX" | grep -c 'client')
				DISPO=$((62-LIST_VPN))
				_titre
				printf "%s\n" "AJOUTER DES CLIENTS VPN" "" "Vous avez $LIST_VPN client(s) VPN installé(s) sur votre serveur." "Vous pouvez avec cette configuration installer un total maximun" "de 62 clients." "" "Recapitulatif :" "$VALID client(s) vpn autorisé(s)" "$REVOK client(s) vpn revoqué(s)" "$DISPO client(s) vpn disponible(s)" "" "Taper Q pour quitter"
				read -p "Combien de client(s) voulez-vous ajouter ? " -r REP
				ADD_VPN="$REP"
				if [[ "$REP" -gt "0" ]] && [[ "$REP" -le "$DISPO" ]]; then
					_create_cert_clients
					_create_rep_clients
					_nat
					_titre
					printf "%s\n" "LISTE CLIENTS VPN ACTIFS :"
					grep 'V' "$INDEX" | grep -o 'client[0-9]*' | awk -F "client" '{print "client : " $2}'
					printf "%s\n" "" "${int}Infos : " "Vous devez redémarrer le serveur pour activer les règles NAT des clients VPN${end}" ""	
					read -p "Appuyez sur [Enter] pour revenir au menu précedent ... " -r
					REP="Q"
				fi
			done
			;;
			2)
			while [[ "$REP" != "Q" ]]; do
				VALID=$(grep 'V' "$INDEX" | grep -c 'client')
				VERIF=$(grep 'V' "$INDEX" | grep -o 'client[0-9]*' | awk -F 'client' '{print $2}')
				_titre
				printf "%s\n" "REVOQUER DES CLIENTS VPN" "" "$VALID clients VPN actifs sur le serveur" "" "Liste clients VPN actifs :"
				grep 'V' "$INDEX" | grep -o 'client[0-9]*' | awk -F "client" '{print "client : " $2}'
				printf "%s\n" "" "Taper Q pour quitter"
				read -p "Taper le numéro du client à révoquer : " -r REP
				if [[ "$REP" != "Q" ]]; then
					for i in $VERIF; do
						if [[ "$REP" = "$i" ]]; then
							printf "\n"
							read -p "Vous avez selectionné le client $REP, merci de confirmer [Y/N] " -r CONF
							if [[ "$CONF" = "Y" ]]; then
								DEL_VPN="$REP"
								_revoke_cert_client
								_create_rep_clients
								printf "\n"
								read -p "Appuyez sur [Enter] pour revenir au menu précedent " -r
								REP="Q" && CONF="0"
							fi
						fi
					done
				fi
			done
			;;

			3)
			_titre
			_create_rep_clients
			tree -vd /tmp/clients
			printf "%s\n" "" "Vos dossiers de clients VPN sont dans /tmp/clients/" "" "${int}Infos :" "Si vous etes sur Windows, utilisez winscp (voir video)" "Si vous etes sur Linux ou Mac copier dans votre terminal la commande scp suivante :" "" "scp -P 22 -r root@$IP:/tmp/clients ./${end}" ""
			read -p "Appuyez sur [Enter] pour revenir au menu précedent " -r 
			;;
			4)
			while [[ "$REP" != "Q" ]]; do
				_titre
				printf "%s\n" "REINITIALISER CERTIFICATS SERVEUR VPN" "" "Taper Q pour quitter"
				read -p "Voulez vous vraiment réinitialiser les certificats du serveur ? [Y/Q] " -r REP
				if [[ "$REP" = "Y" ]]; then
					_titre
					printf "%s\n" "EXEMPLE INFORMATIONS A SAISIR :"
					_show_infos_vpn
					printf "\n"
					_set_infos_vpn
					clear && _titre
					printf "%s\n" "INSTALLATION SERVEUR VPN"
					printf "%s\n\n" "$OS_DESC"
					_installation_vpn
					#if [[ "$PORT_VPN" = "443" ]]; then _stop_seedbox && sed -i "s/127.0.0.1:9090/443/" "$NGINX"; else _stop_seedbox && sed -i "s/127.0.0.1:9090/443/" "$NGINX"; fi
					_stop_openvpn
					_vpn
					_titre
					printf "%s\n" "Création des certificats VPN" "${int}Info : Sur un serveur dédié cette étape peut-etre très longue${end}" ""
					_create_cert_serveur
					_create_cert_clients
					_conf_serveur
					_conf_client
					_create_rep_clients
					_nat
					_titre
					printf "%s\n" "INSTALLATION VPN TERMINEE"
					_recap_install_vpn
					printf "\n"
					read -p "Appuyez sur [Enter] pour redemarrer le serveur... " -r 
					shutdown -r now
					exit 0
				fi
			done
			;;

			5)
			while [[ "$REP" != "Q" ]]; do
				_titre
				printf "%s\n" "SUPPRIMER INSTALLATION VPN" "" "Taper Q pour quitter"
				read -p "Voulez vous vraiment supprimer vos services ? [Y/Q] " -r REP
				if [[ "$REP" = "Y" ]]; then
					#if [[ "$PORT_VPN" = "443" ]]; then _stop_seedbox && sed -i "s/127.0.0.1:9090/443/" "$NGINX" &>/dev/null; fi
					_stop_openvpn
					cat "$SYSCTL".bak > "$SYSCTL"
					cat "$RC".bak > "$RC"
					rm {"$SYSCTL".bak,"$RC".bak}
					rm -rf /etc/openvpn/*
					apt-get purge -y openvpn
					apt-get autoremove -y
					apt-get update -y
					_titre
					read -p "Appuyez sur [Enter] pour redemarrer le serveur... " -r
					shutdown -r now
					exit 0
				fi
			done
			;;

			6)
			_titre
			printf "%s\n" "CLIENTS ACTUELLEMENT CONNECTES" ""
			cat "$STATUS"
			printf "\n"
			read -p "Appuyez sur [Enter] pour revenir au menu précedent " -r 
			;;

			7)
			printf "\n"
			_stop_openvpn
			_start_openvpn
			_status_openvpn
			printf "\n"
			read -p "Appuyez sur [Enter] " -r
			;;
			
			8)
			shutdown -r now
			exit 0
			;;

			Q)
			printf "%s\n" "" "A bientôt" ""
			exit 0
		esac
	done
else
	_titre
	printf "%s\n" "EXEMPLE INFORMATIONS A SAISIR :"
	_show_infos_vpn
	printf "\n"
	_set_infos_vpn
	_titre
	printf "%s\n" "INSTALLATION SERVEUR VPN" "$OS_DESC" ""
	_installation_vpn
	_stop_openvpn
	_backup_vpn
	_vpn
	_titre
	printf "%s\n" "Création des certificats VPN" "${int}Info : Sur un serveur dédié cette étape peut-etre très longue${end}" ""
	_create_cert_serveur
	_create_cert_clients
	_conf_serveur
	_conf_client
	_create_rep_clients
	_nat
	_titre
	printf "%s\n" "INSTALLATION VPN TERMINEE"
	_recap_install_vpn
	printf "\n"
	read -p "Appuyez sur [Enter] pour redemarrer le serveur... " -r 
	shutdown -r now
	exit 0
fi
