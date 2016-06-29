#!/bin/bash
# shellcheck source=/dev/null
# script auto install VPN

# prochaine maj :
# - porter compatibilté chroot vpn + pid
# - si netfilter actif ajouter règles iptables 

# compatible :
# - debian 7 wheezy / debian 8 jessie

# repertoires openvpn
REP_OPENVPN="/etc/openvpn"
REP_RSA="$REP_OPENVPN/easy-rsa"
REP_KEY="$REP_RSA/keys"

# config openvpn
OPENVPN="$REP_OPENVPN/vpn.conf"
STATUS="$REP_OPENVPN/status.log"
LOG="$REP_OPENVPN/openvpn.log"

# exemple informations openvpn
CERT_PAYS="Fr"
CERT_PROV="French"
CERT_VILLE="Paris"
CERT_DESC="Prive"
CERT_NAME=$(uname -n)
CERT_MAIL="admin@$(hostname --fqdn)"
ADD_VPN="5"
PORT_VPN="1194"
if [[ -e "$OPENVPN" ]]; then PORT_VPN=$(awk 'NR==1{print $2}' "$OPENVPN"); fi
if [[ "$PORT_VPN" = "443" ]]; then PROTO_VPN="tcp"; else PROTO_VPN="udp"; fi

# infos ip
IP=$(wget -qO- ipv4.icanhazip.com)
if [[ -z "$IP" ]]; then IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1); fi

# config
SYSCTL="/etc/sysctl.conf"
RC="/etc/rc.local"
TRANSMISSION="/etc/transmission-daemon/settings.json"
NGINX="/etc/nginx/sites-available/default"

# scripts openvpn
VARS="$REP_RSA/vars"
CLEAN="$REP_RSA/clean-all"
BUILD="$REP_RSA/build-dh"
PKITOOL="$REP_RSA/pkitool"
REVOKE="$REP_RSA/revoke-full"
INDEX="$REP_KEY/index.txt"

WARN=$(tput setaf 1)
NC=$(tput sgr0)

function verification(){
        if [[ "$EUID" -ne 0 ]]; then
                MESSAGE="Seul l'utilisateur root peut executer ce script"
                quitter
        elif [[ ! -e /dev/net/tun ]]; then
                MESSAGE="Votre carte reseau TUN/TAP n'est pas active.
contacter votre service technique et demander l'activation du module TUN/TAP"
                quitter
        elif [[ -e /etc/os-release ]] || [[ -e /etc/debian_version ]]; then 
                OS=$(lsb_release -cs 2>/dev/null)
                if [[ ${?} -ne 0 ]]; then
			apt-get update -y && apt-get upgrade -y
			apt-get install -y lsb-release
			OS_DESC=$(lsb_release -ds 2>/dev/null)
			OS=$(lsb_release -cs 2>/dev/null)
                		if [[ ${?} -ne 0 ]]; then
					OPTIONS="0"
                        		while [[ -z "$OS" ]]; do
					clear
                        		read -p "Je n'ai pas reussi à récuperer la version de votre distibution.
Est ce bien un des systèmes d'exploitation ci-dessous ?
1 ) Debian 8  Jessie
2 ) Debian 7  Wheezy

Q ) Taper Q pour quitter

Si oui merci de me l'indiquer [1-2]: " -r OPTIONS
                                		case "$OPTIONS" in
                                        		1) OS="jessie" ;;
                                        		2) OS="wheezy" ;;
                                        		Q) MESSAGE="Si votre systeme d'exploitation n'est pas référencé, si vous etes bien 
sur un serveur basé sur Debian vous pouvez forcer l'installation à vos risques et
périls en choisissant l'option Jessie (systemd) ou Wheezy (init)" && quitter
                                		esac
                        		done
				fi
                fi
        else
                MESSAGE="Votre system d'exploitation n'est ni un Debian ni un Ubuntu "
                quitter
fi
}

function show_infos(){
	echo "Pays: $CERT_PAYS
Province: $CERT_PROV
Ville: $CERT_VILLE
Description: $CERT_DESC
Port VPN: $PORT_VPN
Protocol VPN: $PROTO_VPN
Nombre de client VPN: $ADD_VPN
IP serveur: $IP"
}

function set_infos(){
	REP="0"
	while [[ "$REP" != "Y" ]]; do
		echo "PERSONNALISATION (ou laisser par defaut) :"
		read -p "Pays : " -e -i "$CERT_PAYS" -r CERT_PAYS
		read -p "Province : " -e -i "$CERT_PROV" -r CERT_PROV
		read -p "Ville : " -e -i "$CERT_VILLE" -r CERT_VILLE
		read -p "Description : " -e -i "$CERT_DESC" -r CERT_DESC
		read -p "Port VPN : " -e -i "$PORT_VPN" -r PORT_VPN
			if [[ "$PORT_VPN" = "443" ]]; then PROTO_VPN="tcp"; else PROTO_VPN="udp"; fi
		read -p "Protocol VPN (udp/tcp) : " -e -i "$PROTO_VPN" -r PROTO_VPN
		read -p "Nombre de client VPN : " -e -i "$ADD_VPN" -r ADD_VPN
		read -p "IP serveur : " -e -i "$IP" -r IP
		clear
		echo "VERIFICATION :"
		show_infos
		echo ""
		read -p "Etes-vous satisfait ? Press [Y/N] " -r REP
		clear
	done
}

function quitter(){
        clear
        echo "$MESSAGE"
        read -p "Le script ne peut pas continuer, [Enter] pour quitter ..." -r
        exit
}

function installation(){
	apt-get update -y
	apt-get install -y openvpn openssl iptables tree nano dnsutils
	echo "Europe/Paris" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata
	if [[ -d "$REP_OPENVPN" ]]; then rm -rf "${REP_OPENVPN:?}/"*; fi
	if [[ "$OS" = "wheezy" ]]; then cp -r /usr/share/doc/openvpn/examples/easy-rsa/2.0 "$REP_RSA"; else apt-get install -y easy-rsa && cp -r /usr/share/easy-rsa "$REP_OPENVPN"; fi
}

function backup(){
        if [[ ! -e "$SYSCTL".bak ]]; then cp "$SYSCTL" "$SYSCTL".bak; fi
        if [[ ! -e "$RC".bak ]]; then cp "$RC" "$RC".bak; fi
}

function vpn(){
	sed -i '/^$\|#\|COUNTRY\|SIZE\|PROVINCE\|CITY\|ORG\|EMAI\|OU\|NAME\|EASY_RSA=/d' "$VARS"
	sed -i '1iexport EASY_RSA="'$REP_RSA'"' "$VARS"
	echo "export KEY_SIZE=2048
export KEY_COUNTRY=$CERT_PAYS 
export KEY_PROVINCE=$CERT_PROV 
export KEY_CITY=$CERT_VILLE 
export KEY_ORG=$CERT_NAME 
export KEY_EMAIL=$CERT_MAIL 
export KEY_OU=$CERT_DESC 
export KEY_NAME=$CERT_NAME" >> "$VARS"
}

function create_cert_serveur(){
	source "$VARS" &>/dev/null
	"$CLEAN" && "$BUILD" && "$PKITOOL" --initca && "$PKITOOL" --server openvpn
	"$REVOKE" revoke &>/dev/null
	openvpn --genkey --secret "$REP_KEY"/ta.key
	rm "$REP_KEY"/revoke-test.pem && rm -rf "$REP_SEEDBOX"/vpn
	cp "$REP_KEY"/{ca.crt,ta.key,dh*.pem,crl.pem,openvpn.crt,openvpn.key} "$REP_OPENVPN"
}

function create_cert_clients(){
        i=$(grep -c "client" "$INDEX")
        n=$((ADD_VPN+i))
        source "$VARS" &>/dev/null
        while [[ "$i" -lt "$n" ]] && [[ "$i" -lt 62 ]]; do
                i=$((i+1))
                if [[ "$OS" = "wheezy" ]]; then KEY_CN=client"$i" "$PKITOOL" client"$i"; else "$PKITOOL" client"$i"; fi
        done
}

function revoke_cert_client(){
	source "$VARS" &>/dev/null
	"$REVOKE" client"$DEL_VPN" &>/dev/null
	rm "$REP_KEY"/revoke-test.pem &>/dev/null
	cp "$REP_KEY"/crl.pem "$REP_OPENVPN"
	rm "$REP_KEY"/client"$DEL_VPN".* &>/dev/null
	if [[ ${?} -eq 0 ]]; then echo "[ SUCCES ] Revoking certificat client $DEL_VPN"; else echo "${WARN}[ ECHEC ]${NC} Revoking certificat client $DEL_VPN"; fi
	if [[ "$OS" = "wheezy" ]] || [[ "$OS" = "trusty" ]]; then service openvpn reload &>/dev/null; else systemctl reload openvpn.service &>/dev/null; fi
}

function conf_serveur(){
	echo "port $PORT_VPN
proto $PROTO_VPN
dev tun
ca ca.crt
cert openvpn.crt
key openvpn.key
tls-auth ta.key 0
dh dh2048.pem
crl-verify crl.pem
server 10.8.0.0 255.255.255.0
push 'redirect-gateway'
push 'dhcp-option DNS 208.67.222.222'
push 'dhcp-option DNS 208.67.220.220'
client-config-dir ccd
keepalive 10 120
cipher AES-128-CBC
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
verb 3
log-append $LOG
status $STATUS" > "$OPENVPN"
	if [[ "$PORT_VPN" = "443" ]]; then
		sed -i 's/udp/tcp/' "$OPENVPN"
			if [[ -e "$NGINX" ]]; then
				sed -i "s/443/127.0.0.1:9090/" "$NGINX" && reload_nginx
				sed -i '/port-share/d' "$OPENVPN" && echo "port-share 127.0.0.1 9090" >> "$OPENVPN"	
			fi
	fi
	sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' "$SYSCTL"
}

function conf_client(){
	echo "client
proto $PROTO_VPN
dev tun
remote $IP $PORT_VPN
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert mon_client.crt
key mon_client.key
tls-auth ta.key 1
cipher AES-128-CBC
comp-lzo
verb 3" > "$REP_OPENVPN"/client_model
	# force proto TCP pour https 
	if [[ "$PORT_VPN" = "443" ]]; then sed -i "s/udp/tcp/" "$REP_OPENVPN"/client_model; fi
}

function create_rep_clients(){
	rm -rf "$REP_OPENVPN"/clients
	rm -rf /tmp/clients
	rm -rf "$REP_OPENVPN"/ccd
	mkdir "$REP_OPENVPN"/{clients,ccd}
        n=$(grep -c "client" "$INDEX")
        a=1 && b=2
        for (( i=1 ; i<="$n" ; i++ )); do
                a=$((a+4)) && b=$((b+4))
		if [[ -e "$REP_KEY"/client"$i".crt ]]; then
			mkdir "$REP_OPENVPN"/clients/client"$i"
		        cp "$REP_OPENVPN"/client_model "$REP_OPENVPN"/clients/client"$i".ovpn
		        {
		        echo "<ca>"
		        cat "$REP_KEY"/ca.crt 
		        echo "</ca>"
		        echo "<cert>"
		        cat "$REP_KEY"/client$i.crt
		        echo "</cert>"
		        echo "<key>"
		        cat "$REP_KEY"/client$i.key
		        echo "</key>"
		        echo "<tls-auth>"
		        cat "$REP_KEY"/ta.key
		        echo "</tls-auth>"
		        } >> "$REP_OPENVPN"/clients/client"$i".ovpn
			cp "$REP_KEY"/{ca.crt,client$i.crt,client$i.key,ta.key} "$REP_OPENVPN"/clients/client"$i"/
			cp "$REP_OPENVPN"/clients/client"$i".ovpn "$REP_OPENVPN"/clients/client"$i"/
                        sed -i "s/mon_client/client$i/" "$REP_OPENVPN"/clients/client"$i"/client"$i".ovpn
                        echo "ifconfig-push 10.8.0.$a 10.8.0.$b" > "$REP_OPENVPN"/ccd/client"$i"
                fi
        done
	cp -r "$REP_OPENVPN"/clients /tmp/
	chmod -R 777 /tmp/clients
}

function nat(){
        sed -i '/^exit\|^$\|Client\|# ouvert\|10.8.0./d' "$RC"
        a=1 && b=60000
        n=$(grep -c "client" "$INDEX")
        for (( i=1 ; i<="$n" ; i++ )); do
                a=$((a+4)) && b=$((b+1))
                echo "
# ouverture port $b pour le client$i 
iptables -t nat -A PREROUTING -p tcp --dport $b -j DNAT --to-destination 10.8.0.$a:$b
iptables -t nat -A PREROUTING -p udp --dport $b -j DNAT --to-destination 10.8.0.$a:$b" >> "$RC"
        done
        echo "
# ouverture acces internet aux clients vpn 
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
exit 0" >> "$RC"
}

function recap_install(){
	status_openvpn
	echo ""
	echo "Ouverture automatique d'un port pour chaque client VPN"
	echo ""
	a=1 && b=60000
        n=$(grep -c "client" "$INDEX")
        for (( i=1 ; i<="$n" ; i++ )); do
                a=$((a+4)) && b=$((b+1))
                echo "Client vpn $i \"10.8.0.$a\" ouverture du port $b"
	done
	echo ""
	tree -vd /tmp/clients
	echo ""
	echo "Vos dossiers de clients VPN sont dans /tmp/clients/"
	echo "Récupérez-les puis rédemarrez votre serveur pour activer les règles NAT"
	echo ""
	echo "Infos :"
	echo "Si vous etes sur Windows, utilisez winscp (voir video)"
	echo "Si vous etes sur Linux ou Mac copier dans votre terminal la commande scp suivante :"
	echo "scp -P 22 -r root@$IP:/tmp/clients ./"
}

function stop_openvpn(){
        if [[ "$OS" = "wheezy" ]]; then service openvpn stop &>/dev/null;
                if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn Stopping"; fi
        else systemctl stop openvpn.service &>/dev/null;
                if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn Stopping"; fi
        fi
}

function start_openvpn(){
        if [[ "$OS" = "wheezy" ]]; then service openvpn start &>/dev/null;
                if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn Starting"; else echo "${WARN}[ FAIL ]${NC} openvpn is not Starting"; fi
        else systemctl start openvpn.service &>/dev/null;
                if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn Starting"; else echo "${WARN}[ FAIL ]${NC} openvpn is not Starting"; fi
        fi
}

function status_openvpn(){
	if [[ "$OS" = "wheezy" ]]; then service openvpn status &>/dev/null;
		if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn is running"; else echo "${WARN}[ FAIL ]${NC} openvpn is not running"; fi
	else systemctl status openvpn.service &>/dev/null;
		if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn is running"; else echo "${WARN}[ FAIL ]${NC} openvpn is not running"; fi
	fi
}

function reload_nginx(){
                if [[ "$OS" = "wheezy" ]]; then service nginx reload &>/dev/null; else systemctl reload nginx.service &>/dev/null; fi
}


####################################################
# début du script
####################################################
verification
OS_DESC=$(lsb_release -ds)
clear
if [[ -e "$OPENVPN" ]]; then
	OPTIONS="0"
	while [[ "$OPTIONS" != "Q" ]]; do
		clear
		REP="0" && ADD_VPN="5"
		read -p "LE VPN EST DEJA INSTALLE SUR CE SERVEUR :

1 ) Ajouter des clients
2 ) Revoquer des clients
3 ) Renvoyer les clients dans le dossier /tmp/clients

4 ) Réinitialiser tous les certificats vpn
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
					show_infos
					echo ""
					set_infos
					clear
					echo "INSTALLATION SERVEUR VPN"
					echo "$OS_DESC"
					echo ""
					installation
					stop_openvpn
					vpn
					clear
					echo "Création des certificats VPN"
					echo "cette étape peut-etre longue"
					create_cert_serveur
					create_cert_clients
					conf_serveur
					conf_client
					create_rep_clients
					nat
					start_openvpn
					clear
					echo "INSTALLATION VPN TERMINEE"
					recap_install
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
	echo "EXEMPLE INFORMATIONS A SAISIR :"
	show_infos
	echo ""
	set_infos
	clear
	echo "INSTALLATION SERVEUR VPN"
	echo "$OS_DESC"
	echo ""
	installation
	stop_openvpn
	backup
	vpn
	clear
	echo "Création des certificats VPN"
	echo "cette étape peut-etre longue"
	create_cert_serveur
	create_cert_clients
	conf_serveur
	conf_client
	create_rep_clients
	nat
	start_openvpn
	clear
	echo "INSTALLATION VPN TERMINEE"
	recap_install
	echo ""
	read -p "Appuyez sur [Enter] pour continuer ... " -r 
	if [[ ! -e "$TRANSMISSION" ]]; then
		while [[ "$REP" != "N" ]]; do
			clear
			read -p "Voulez vous installer votre seedbox ? [Y/N] " -r REP
			if [[ "$REP" = "Y" ]]; then
				wget https://raw.githubusercontent.com/finalcutgit411/master/master/seedbox.sh --no-check-certificate
				chmod +x seedbox.sh
				mv seedbox.sh /usr/local/bin/seedbox.sh
				seedbox.sh
				REP="N"
			fi
		done
	fi
	clear
	echo "INSTALLATION VPN TERMINEE"
	recap_install
	echo ""
	read -p "Appuyez sur [Enter] pour redemarrer le serveur... " -r 
	shutdown -r now
fi
exit 0
