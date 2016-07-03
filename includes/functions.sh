#!/bin/bash
function prerequis_vpn(){
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
			apt-get update -y
			apt-get install -y lsb-release
			OS_DESC=$(lsb_release -ds 2>/dev/null)
			OS=$(lsb_release -cs 2>/dev/null)
                fi
        else
                MESSAGE="Votre system d'exploitation n'est pas un Debian"
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
	echo ""
	if [[ "$PORT_VPN" = "443" ]]; then stop_seedbox && stop_openvpn && start_openvpn && start_seedbox; else stop_openvpn && start_openvpn; fi
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
status $STATUS" > "$OPENVPN" && chmod 600 "$OPENVPN"
	if [[ "$PORT_VPN" = "443" ]]; then
		# force protocole TCP pour https
		sed -i 's/udp/tcp/' "$OPENVPN"
			if [[ -e "$NGINX" ]]; then
				sed -i "s/443/127.0.0.1:9090/" "$NGINX" && reload_nginx
				sed -i '/port-share/d' "$OPENVPN" && echo "port-share 127.0.0.1 9090" >> "$OPENVPN"	
			fi
	fi
	sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' "$SYSCTL"
	start_openvpn
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
	# force protocole TCP pour https 
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
		if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn:$PORT_VPN is running"; else echo "${WARN}[ FAIL ]${NC} openvpn is not running"; fi
	else systemctl status openvpn.service &>/dev/null;
		if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn:$PORT_VPN is running $PORT_VPN"; else echo "${WARN}[ FAIL ]${NC} openvpn is not running"; fi
	fi
}

function stop_seedbox(){
        for i in "transmission-daemon" "vsftpd" "nginx" "fail2ban"; do
                if [[ "$OS" = "wheezy" ]]; then service $i stop &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i Stopping"; fi
                else systemctl stop $i.service &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i Stopping"; fi
                fi
        done
}

function start_seedbox(){
        for i in "transmission-daemon" "vsftpd" "nginx" "fail2ban"; do
                if [[ "$OS" = "wheezy" ]]; then service $i start &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i Starting"; else echo "${WARN}[ FAIL ]${NC} $i is not Starting"; fi
                else systemctl start $i.service &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i Starting"; else echo "${WARN}[ FAIL ]${NC} $i is not Starting"; fi
                fi
        done
}

function reload_nginx(){
                if [[ "$OS" = "wheezy" ]]; then service nginx reload &>/dev/null; else systemctl reload nginx.service &>/dev/null; fi
}

function titre(){
	echo "	
___________ .___   _______       _____    .____      _________    ____ ___  ___________
\_   _____/ |   |  \      \     /  _  \   |    |     \_   ___ \  |    |   \ \__    ___/
 |    __)   |   |  /   |   \   /  /_\  \  |    |     /    \  \/  |    |   /   |    |   
 |     \    |   | /    |    \ /    |    \ |    |___  \     \____ |    |  /    |    |   
 \___  /    |___| \____|__  / \____|__  / |_______ \  \______  / |______/     |____|   
     \/                   \/          \/          \/         \/   		
"
}
