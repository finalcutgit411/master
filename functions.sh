#!/bin/bash
# fonctions

_prerequis_vpn(){
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

function prerequis_seedbox(){
        if [[ "$EUID" -ne 0 ]]; then
                MESSAGE="Seul l'utilisateur root peut executer ce script"
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

function show_infos_vpn(){
	echo "Pays: $CERT_PAYS
Province: $CERT_PROV
Ville: $CERT_VILLE
Description: $CERT_DESC
Port VPN: $PORT_VPN
Protocol VPN: $PROTO_VPN
Nombre de client VPN: $ADD_VPN
IP serveur: $IP"
}

function set_infos_vpn(){
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
		clear && titre
		echo "VERIFICATION :"
		show_infos_vpn
		echo ""
		read -p "Etes-vous satisfait ? Press [Y/N] " -r REP
		clear && titre
	done
}

function set_infos_seedbox(){
	REP="0"
	apt-get update -y && apt-get install -y dnsutils
	clear && titre
	while [[ "$REP" != "Y" ]]; do
		echo "CREATION UTILISATEUR VIRTUEL SEEDBOX"
		echo ""
		echo "Personnalisation"
		read -p "Utilisateur: " -e -i "$NOM_USER" -r NOM_USER
		read -p "Mot de passe: " -e -i "$MDP_USER" -r MDP_USER
		echo ""
		echo "Possédez-vous un nom de domaine et souhaitez-vous l'utiliser ? "
		read -p "Si oui saisissez-le ou bien utilisez par défaut $(hostname --fqdn): " -e -i "$MON_DOMAINE" -r MON_DOMAINE
		MON_DOMAINE="${MON_DOMAINE//www./}"
		echo ""
		echo "Vérification"
		echo "Utilisateur: $NOM_USER = $MDP_USER"
		echo "domaine: $MON_DOMAINE"
		echo ""
		VERIF=$(nslookup "$MON_DOMAINE" | awk '/^Address: / { print $2 }')
		nslookup "$MON_DOMAINE" &>/dev/null
			if [[ ${?} -ne 0 ]]; then
				echo ""
				echo "${WARN}[Erreur : $MON_DOMAINE]${NC} Le nom de domaine n'est pas valide"
				read -p "Press [enter] pour recommencer" -r
				MON_DOMAINE=$(hostname --fqdn) && REP="N"
			elif [[ "$VERIF" != "$IP" ]]; then
				echo ""
				echo "${WARN}[Erreur : $VERIF]${NC} Le nom de domaine: $MON_DOMAINE ne redirige pas vers l'IP $IP de ce serveur"
				read -p "Press [enter] pour recommencer" -r
				MON_DOMAINE=$(hostname --fqdn) && REP="N"
			else 
				read -p "Etes-vous satisfait ? Press [Y/N] " -r REP
			fi
		clear && titre
	done
}

function set_password(){
	LIVE="/etc/letsencrypt/live/$MON_DOMAINE"
	FULLCHAIN="$LIVE/fullchain.pem"
	PRIVKEY="$LIVE/privkey.pem"
	stop_seedbox
	REP="0"
	clear && titre
	while [[ "$REP" != "Y" ]]; do
		echo "MODIFICATION PASSWORD UTILISATEUR SEEDBOX"
		echo ""
		echo "Personnalisation"
		read -p "Utilisateur: " -e -i "$NOM_USER" -r NOM_USER
		read -p "Mot de passe: " -e -i "$MDP_USER" -r MDP_USER
		echo ""
		echo "Vérification"
		echo "Utilisateur: $NOM_USER = $MDP_USER"
		echo ""
		read -p "Etes-vous satisfait ? Press [Y/N] " -r REP
	done
	printf "%s" "$NOM_USER:$(openssl passwd -apr1 "$MDP_USER")" > "$HTPASSWD"
	vsftpd
	echo ""
	start_seedbox
	echo ""
	status_seedbox
}

function quitter(){
        clear && titre
        echo "$MESSAGE"
        read -p "Le script ne peut pas continuer, [Enter] pour quitter ..." -r
        exit
}

function installation_vpn(){
	apt-get update -y
	apt-get install -y openvpn openssl iptables tree nano dnsutils
	echo "Europe/Paris" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata
	if [[ -d "$REP_OPENVPN" ]]; then rm -rf "${REP_OPENVPN:?}/"*; fi
	if [[ "$OS" = "wheezy" ]]; then cp -r /usr/share/doc/openvpn/examples/easy-rsa/2.0 "$REP_RSA"; else apt-get install -y easy-rsa && cp -r /usr/share/easy-rsa "$REP_OPENVPN"; fi
}

function installation_seedbox(){
	apt-get update -y
	echo "Europe/Paris" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata
	apt-get install -y transmission-daemon nginx vsftpd fail2ban iptables db-util tree nano git
	clear && titre
	echo "Info : Sur un serveur dédié cette étape peut-etre très longue"
	if [[ ! -e "$DHPARAMS" ]]; then openssl dhparam 2048 > "$DHPARAMS";
	elif [[ -e "$DHPARAMS" ]]; then openssl dhparam -in "$DHPARAMS" &>/dev/null;
		if [[ ${?} -ne 0 ]]; then openssl dhparam 2048 > "$DHPARAMS"; fi
	fi
	# si vous depassez la limite de let's encrypt; (voir explication vidéo)
	# création certificat auto signé 
	openssl genrsa 4096 > "$MON_CERT_KEY"
	openssl req -subj "/O=mon serveur/OU=personnel/CN=$MON_DOMAINE" -new -x509 -days 365 -key "$MON_CERT_KEY" -out "$MON_CERT"
}

function backup_vpn(){
        if [[ ! -e "$SYSCTL".bak ]]; then cp "$SYSCTL" "$SYSCTL".bak; fi
        if [[ ! -e "$RC".bak ]]; then cp "$RC" "$RC".bak; fi
}

function backup_seedbox(){
        if [[ ! -e "$SSHD".bak ]]; then cp "$SSHD" "$SSHD".bak; fi
        if [[ ! -e "$MOTD".bak ]]; then cp "$MOTD" "$MOTD".bak; fi
        if [[ ! -e "$TRANSMISSION".bak ]]; then cp "$TRANSMISSION" "$TRANSMISSION".bak; fi
        if [[ ! -e "$VSFTPD".bak ]]; then cp "$VSFTPD" "$VSFTPD".bak; fi
        if [[ ! -e "$NGINX".bak ]]; then cp "$NGINX" "$NGINX".bak; fi
        if [[ ! -e "$JAIL_CONF".bak ]]; then cp "$JAIL_CONF" "$JAIL_CONF".bak; fi
}

function vpn(){
	sed -i '/^$\|#\|COUNTRY\|SIZE\|PROVINCE\|CITY\|ORG\|EMAI\|OU\|NAME\|EASY_RSA=/d' "$VARS"
	#sed -i '1iexport EASY_RSA="'$REP_RSA'"' "$VARS"
	sed -i "1iexport EASY_RSA='$REP_RSA'" "$VARS"
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
	if [[ "$PORT_VPN" = "443" ]] && [[ -e "$TRANSMISSION" ]]; then stop_seedbox && stop_openvpn && start_openvpn && start_seedbox; else stop_openvpn && start_openvpn; fi
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

function seedbox(){
	usermod -aG ftp debian-transmission 
	mkdir -p "$REP_SEEDBOX"/documents
	chmod 700 -R "$REP_SEEDBOX"/documents
	chown -R ftp:ftp "$REP_SEEDBOX"/documents
	mkdir -p "$REP_SEEDBOX"/{leech,seed,torrents} && chmod 770 -R "$REP_SEEDBOX"/{leech,seed,torrents} && chown -R ftp:ftp "$REP_SEEDBOX"/{leech,seed,torrents}
	printf "%s" "$NOM_USER:$(openssl passwd -apr1 "$MDP_USER")" > "$HTPASSWD"
	# ajouter eventuellment une option "recharger tous les .torrents"
	# rename 's/\.added$//' "$REP_SEEDBOX"/torrents
	cat "$TRANSMISSION".bak > "$TRANSMISSION"
	sed -i 's/ //g; /dht-enabled\|incomplete\|download-dir\|peer-port"\|pex-enabled\|rpc-password\|rpc-username\|umask\|utp-enabled\|}/d' "$TRANSMISSION"
	echo "\"dht-enabled\":false,
\"download-dir\":\"$REP_SEEDBOX/seed\",
\"incomplete-dir\":\"$REP_SEEDBOX/leech\",
\"incomplete-dir-enabled\":true,
\"peer-port\":60000,
\"pex-enabled\":false,
\"rpc-authentication-required\":false,
\"umask\":0,
\"utp-enabled\":false,
\"watch-dir-enabled\":true,
\"watch-dir\":\"$REP_SEEDBOX/torrents\"
}" >> "$TRANSMISSION"
}

function letsencrypt(){
	LIVE="/etc/letsencrypt/live/$MON_DOMAINE"
	FULLCHAIN="$LIVE/fullchain.pem"
	PRIVKEY="$LIVE/privkey.pem"
	if [[ "$PORT_VPN" = "443" ]]; then stop_openvpn; fi
	echo ""
	rm -rf "$LETS_ENCRYTP" && git clone https://github.com/letsencrypt/letsencrypt "$LETS_ENCRYTP"
	if [[ "$MON_DOMAINE" = "$(hostname --fqdn)" ]]; then 
		"$LETS_ENCRYTP"/certbot-auto certonly --rsa-key-size 4096 --non-interactive --standalone --email admin@"$MON_DOMAINE" --domains "$MON_DOMAINE" --agree-tos
	else 
		"$LETS_ENCRYTP"/certbot-auto certonly --rsa-key-size 4096 --non-interactive --standalone --email admin@"$MON_DOMAINE" --domains "$MON_DOMAINE" --domains www."$MON_DOMAINE" --agree-tos
	fi
	if [[ ${?} -ne 0 ]]; then
		rm "$INFO" &>/dev/null
		echo ""
		echo "${WARN}[Erreur]${NC} Let's Encrypt ne vous a pas delivré de certificat (voir video)"
		echo "Votre certificat auto signé est installé; Il est utilisé actuellement sur votre serveur"
		echo "Vous pouvez copier coller le message d'erreur ci-dessus et le poster sur le forum pour obtenir de l'aide"
		read -p "Appuyez sur [Enter] pour continuer " -r
	else
		# les certificats letsencrypt sont valables 90 jours
		# planification automatique dans le cron de la demande de renouvellement
		echo "$MON_DOMAINE" > "$INFO" && chmod 600 "$INFO"
		( crontab -l | grep -v "$CRON_CMD" ; echo "$CRON_JOB" ) | crontab -
		echo ""
		echo "Let's Encrypt a validé votre domaine : $MON_DOMAINE"
		echo "Vous possedez un authentique certificat SSL; il est installé et utilisé sur ce serveur "
		read -p "Appuyez sur [Enter] pour continuer " -r
	fi
	if [[ "$PORT_VPN" = "443" ]]; then start_openvpn; fi
}

function nginx(){
	echo 'server_tokens off;
add_header X-Frame-Options SAMEORIGIN;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection '"'1; mode=block'"';

server {
	listen 80;
	server_name '"$MON_DOMAINE"';
	return 301 https://$host$request_uri;
}

server {
	listen 443 ssl;
	server_name '"$MON_DOMAINE"';

	add_header Strict-Transport-Security '"'max-age=31622400; includeSubDomains; preload'"';

	auth_basic '"'Restricted Content'"';
	auth_basic_user_file '$HTPASSWD';

	#ssl_certificate '$MON_CERT';
	#ssl_certificate_key '$MON_CERT_KEY';
	ssl_certificate '$FULLCHAIN';
	ssl_certificate_key '$PRIVKEY';
	ssl_dhparam '$DHPARAMS';
	ssl_prefer_server_ciphers on;
	ssl_protocols TLSv1.2;
	ssl_ecdh_curve secp384r1;
	ssl_ciphers EECDH+AESGCM:EECDH+AES;
	ssl_session_cache shared:SSL:10m;
	ssl_session_timeout 10m;
	
	location / {
		proxy_pass http://127.0.0.1:9091/;
	}
}' > "$NGINX"
	if [[ "$PORT_VPN" = "443" ]]; then 
		sed -i "s/443/127.0.0.1:9090/" "$NGINX"
		stop_openvpn
		sed -i '/port-share/d' "$OPENVPN"
		echo "port-share 127.0.0.1 9090" >> "$OPENVPN"
		start_openvpn
	fi
	# si vous avez réinstallé plus de 5 fois votre serveur dans la semaine 
	# on bascule sur le certificat auto signé (voir vidéo pour explications)
	if [[ ! -e "$INFO" ]]; then sed -i 's/^#//g; /fullchain\|privkey/d' "$NGINX"; else sed -i '/^#/d' "$NGINX";fi
}

function nginxsave(){
	echo "server_tokens off;
add_header X-Frame-Options SAMEORIGIN;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection '1; mode=block';
server {
listen 80;
server_name $MON_DOMAINE;
return 301 https://\$host\$request_uri;
}
server {
listen 443 ssl;
server_name $MON_DOMAINE;
add_header Strict-Transport-Security 'max-age=31622400; includeSubDomains; preload';
auth_basic 'Restricted Content';
auth_basic_user_file $HTPASSWD;
#ssl_certificate $MON_CERT;
#ssl_certificate_key $MON_CERT_KEY;
ssl_certificate $FULLCHAIN;
ssl_certificate_key $PRIVKEY;
ssl_dhparam $DHPARAMS;
ssl_prefer_server_ciphers on;
ssl_protocols TLSv1.2;
ssl_ecdh_curve secp384r1;
ssl_ciphers EECDH+AESGCM:EECDH+AES;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
location / {
proxy_pass http://127.0.0.1:9091/;
}
}" > "$NGINX"
	if [[ "$PORT_VPN" = "443" ]]; then 
		sed -i "s/443/127.0.0.1:9090/" "$NGINX"
		stop_openvpn
		sed -i '/port-share/d' "$OPENVPN"
		echo "port-share 127.0.0.1 9090" >> "$OPENVPN"
		start_openvpn
	fi
	# si vous avez réinstallé plus de 5 fois votre serveur dans la semaine 
	# on bascule sur le certificat auto signé (voir vidéo pour explications)
	if [[ ! -e "$INFO" ]]; then sed -i 's/#//g; /fullchain\|privkey/d' "$NGINX"; else sed -i '/#/d' "$NGINX";fi
}

function fail2ban(){
	echo "
[DEFAULT]
# ban 30 min
bantime = 1800
findtime = 1800
ignoreip = 127.0.0.1/8 10.8.0.0/24
[ssh]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 4
[ssh-ddos]
enabled  = true
port     = ssh
filter   = sshd-ddos
logpath  = /var/log/auth.log
maxretry = 4
[vsftpd-virtuel]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
filter   = vsftpd-virtuel
logpath  = $VSFTPD_LOG
maxretry = 6
[nginx-http-auth]
enabled = true
filter  = nginx-http-auth
port    = http,https
logpath = /var/log/nginx/error.log
maxretry = 4
[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = iptables-allports[name=recidive]
# Si 3 recidives en 24H alors ban 1 semaine
bantime  = 604800
findtime = 86400
maxretry = 3" > "$JAIL_LOCAL"
	if [[ ! -e "$REGEX_RECID" ]]; then echo '[INCLUDES]
before = common.conf
[Definition]
_daemon = fail2ban\.actions
_jailname = recidive
failregex = ^(%(__prefix_line)s|,\d{3} fail2ban.actions%(__pid_re)s?:\s+)WARNING\s+\[(?!%(_jailname)s\])(?:.*)\]\s+Ban\s+<HOST>\s*$
ignoreregex =' > "$REGEX_RECID"
	fi
	if [[ ! -e "$REGEX_NGINX" ]]; then echo '[Definition]
failregex = ^ \[error\] \d+#\d+: \*\d+ user "\S+":? (password mismatch|was not found in ".*"), client: <HOST>, server: \S+, request: "\S+ \S+ HTTP/\d+\.\d+", host: "\S+"\s*$
ignoreregex =' > "$REGEX_NGINX"
	fi
	echo '[Definition]
failregex = .*Client "<HOST>",."530 Permission denied."$
            .*Client "<HOST>",."530 Login incorrect."$          
ignoreregex =' > "$REGEX_FTP"
}

function vsftpd(){
	mkdir -p /etc/vsftpd/vsftpd_user_conf
	rm -f /etc/vsftpd/vsftpd_user_conf/*
	echo "$NOM_USER" > "$USER_LIST" && chmod 600 "$USER_LIST"
	echo "$NOM_USER" > /etc/vsftpd/login
	echo "$MDP_USER" >> /etc/vsftpd/login
	db_load -T -t hash -f /etc/vsftpd/login /etc/vsftpd/login.db
	chmod 400 /etc/vsftpd/login.db && rm /etc/vsftpd/login
	echo "seccomp_sandbox=NO
anonymous_enable=NO
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO
listen=YES
local_enable=YES
chroot_local_user=YES
write_enable=NO
hide_file={.*}
user_config_dir=/etc/vsftpd/vsftpd_user_conf
pam_service_name=vsftpd
chmod_enable=NO
chown_uploads=NO
guest_enable=YES
guest_username=nobody
userlist_deny=NO
userlist_enable=YES
userlist_file=$USER_LIST
use_localtime=YES
ssl_enable=YES
allow_anon_ssl=YES
force_local_data_ssl=YES
force_anon_data_ssl=YES
force_local_logins_ssl=YES
force_anon_logins_ssl=YES
#rsa_cert_file=$MON_CERT
#rsa_private_key_file=$MON_CERT_KEY
rsa_cert_file=$FULLCHAIN
rsa_private_key_file=$PRIVKEY
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
strict_ssl_read_eof=YES
strict_ssl_write_shutdown=YES
ascii_download_enable=YES
ascii_upload_enable=YES
max_clients=10
max_per_ip=10
require_ssl_reuse=NO
log_ftp_protocol=YES
xferlog_enable=YES
ssl_ciphers=HIGH" > "$VSFTPD"
	if [[ ! -e "$VSFTPD_LOG" ]]; then touch "$VSFTPD_LOG" && chmod 600 "$VSFTPD_LOG"; fi
	if [[ "$OS" = "wheezy" ]]; then sed -i '/seccomp_sandbox=NO/d' "$VSFTPD"; fi
	# si vous avez réinstallé plus de 5 fois votre serveur dans la semaine 
	# on bascule sur le certificat auto signé (voir vidéo pour explications)
	if [[ ! -e "$INFO" ]]; then sed -i 's/^#//g; /fullchain\|privkey/d' "$VSFTPD"; fi
	echo "anon_world_readable_only=NO
write_enable=YES
download_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
virtual_use_local_privs=YES
local_umask=007
local_root=$REP_SEEDBOX
guest_username=ftp" > /etc/vsftpd/vsftpd_user_conf/"$NOM_USER"
	if [[ "$OS" = "wheezy" ]] || [[ "$ARCH" = "32" ]]; then
		echo "auth required pam_userdb.so db=/etc/vsftpd/login
account required pam_userdb.so db=/etc/vsftpd/login" > /etc/pam.d/vsftpd
	else 
		echo "auth required /lib/x86_64-linux-gnu/security/pam_userdb.so db=/etc/vsftpd/login
account required /lib/x86_64-linux-gnu/security/pam_userdb.so db=/etc/vsftpd/login" > /etc/pam.d/vsftpd
	fi
}

function recap_install_vpn(){
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

function recap_install_seedbox(){
	echo "Accès Seedbox et FTP : $MON_DOMAINE"
	echo ""
	echo "utilisateur: $NOM_USER"
	echo "password: $MDP_USER"
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
        else systemctl start openvpn@vpn.service &>/dev/null;
                if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn Starting"; else echo "${WARN}[ FAIL ]${NC} openvpn is not Starting"; fi
        fi
}

function status_openvpn(){
	if [[ "$OS" = "wheezy" ]]; then service openvpn status &>/dev/null;
		if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn:$PORT_VPN is running"; else echo "${WARN}[ FAIL ]${NC} openvpn is not running"; fi
	else systemctl status openvpn@vpn.service &>/dev/null;
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

function status_seedbox(){
        for i in "transmission-daemon" "vsftpd" "nginx" "fail2ban"; do
                if [[ "$OS" = "wheezy" ]]; then service $i status &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i is running"; else echo "${WARN}[ FAIL ]${NC} $i is not running"; fi
                else systemctl status $i.service &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i is running"; else echo "${WARN}[ FAIL ]${NC} $i is not running"; fi
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
"
}

