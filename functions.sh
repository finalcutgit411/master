#!/bin/bash
# shellcheck source=/dev/null
source variables.sh
_prerequis_vpn(){
        if [[ "$EUID" -ne 0 ]]; then 
		_titre
                printf "%s\n" "${red}Seul l'utilisateur root peut executer ce script"
		read -p "[Enter] pour quitter ...${end} " -r
                exit
        elif [[ ! -e /dev/net/tun ]]; then
		_titre
                printf "%s\n" "${red}Votre carte reseau TUN/TAP n'est pas active." "contacter votre service technique et demander l'activation du module TUN/TAP"
		read -p "[Enter] pour quitter ...${end} " -r
                exit
        elif [[ -e /etc/os-release ]] || [[ -e /etc/debian_version ]]; then 
                OS=$(grep "VERSION=" /etc/os-release 2>/dev/null | tr '[:upper:]' '[:lower:]')
                	if [[ ${?} -ne 0 ]]; then apt-get update -y && apt-get install -y lsb-release; fi
		OS=$(grep "VERSION=" /etc/os-release | tr '[:upper:]' '[:lower:]')
		OS=${OS##*\(} && OS=${OS%%\)*}
			if [[ "$OS" != "wheezy" ]] && [[ "$OS" != "jessie" ]]; then
				_titre
				printf "%s\n" "${red}Le script est uniquement comptatible avec Debian 7 ou 8"
				read -p "[Enter] pour quitter ...${end} " -r
				exit
			fi
        else
		_titre
                printf "%s\n" "${red}Votre system d'exploitation n'est pas un Debian"
		read -p "Le script ne peut pas continuer, [Enter] pour quitter ...${end} " -r
                exit
	fi
}

_prerequis_seedbox(){
        if [[ "$EUID" -ne 0 ]]; then
		_titre
                printf "%s\n" "${red}Seul l'utilisateur root peut executer ce script"
		read -p "[Enter] pour quitter ...${end} " -r
                exit
        elif [[ -e /etc/os-release ]] || [[ -e /etc/debian_version ]]; then 
                OS=$(grep "VERSION=" /etc/*release 2>/dev/null | tr '[:upper:]' '[:lower:]')
                	if [[ ${?} -ne 0 ]]; then apt-get update -y && apt-get install -y lsb-release; fi
		OS=$(grep "VERSION=" /etc/*release | tr '[:upper:]' '[:lower:]')
		OS=${OS##*\(} && OS=${OS%%\)*}
			if [[ "$OS" != "wheezy" ]] && [[ "$OS" != "wheezy" ]]; then 
				_titre
				printf "%s\n" "${red}Le script est uniquement comptatible avec Debian 7 ou 8"
				read -p "[Enter] pour quitter ...${end} " -r
				exit
			fi
        else
		_titre
                printf "%s\n" "${red}Votre system d'exploitation n'est pas un Debian"
		read -p "Le script ne peut pas continuer, [Enter] pour quitter ...${end} " -r
                exit
	fi
}

_show_infos_vpn(){
printf "%s\n" \
"Pays: $CERT_PAYS
Province: $CERT_PROV
Ville: $CERT_VILLE
Description: $CERT_DESC
Port VPN: $PORT_VPN
Protocol VPN: $PROTO_VPN
Nombre de client VPN: $ADD_VPN
IP serveur: $IP"
}

_set_infos_vpn(){
	REP="0"
	while [[ "$REP" != "Y" ]]; do
		printf "%s\n" "PERSONNALISATION (ou laisser par defaut) :"
		read -p "Pays : " -e -i "$CERT_PAYS" -r CERT_PAYS
		read -p "Province : " -e -i "$CERT_PROV" -r CERT_PROV
		read -p "Ville : " -e -i "$CERT_VILLE" -r CERT_VILLE
		read -p "Description : " -e -i "$CERT_DESC" -r CERT_DESC
		read -p "Port VPN : " -e -i "$PORT_VPN" -r PORT_VPN
			if [[ "$PORT_VPN" = "443" ]] || [[ "$PORT_VPN" = "4432" ]]; then PROTO_VPN="tcp" && PORT_VPN="443"; else PROTO_VPN="udp"; fi
		read -p "Protocol VPN (udp/tcp) : " -e -i "$PROTO_VPN" -r PROTO_VPN
			if [[ "$PORT_VPN" = "443" ]]; then PROTO_VPN="tcp"; fi
		read -p "Nombre de client VPN : " -e -i "$ADD_VPN" -r ADD_VPN
		read -p "IP serveur : " -e -i "$IP" -r IP
		_titre
		printf "%s\n" "VERIFICATION :"
		_show_infos_vpn
		printf "\n"
		read -p "Etes-vous satisfait ? Press [Y/N] " -r REP
		_titre
	done
}

_set_infos_seedbox(){
	REP="0"
	apt-get update -y && apt-get install -y dnsutils
	_titre
	while [[ "$REP" != "Y" ]]; do
		printf "%s\n" "CREATION UTILISATEUR VIRTUEL SEEDBOX" "" "Personnalisation"
		read -p "Utilisateur: " -e -i "$NOM_USER" -r NOM_USER
		read -p "Mot de passe: " -e -i "$MDP_USER" -r MDP_USER
		printf "%s\n" "" "Possédez-vous un nom de domaine et souhaitez-vous l'utiliser ? "
		read -p "Si oui saisissez-le ou bien utilisez par défaut $(hostname --fqdn): " -e -i "$MON_DOMAINE" -r MON_DOMAINE
		MON_DOMAINE="${MON_DOMAINE//www./}"
		printf "%s\n"  "" "Vérification" "Utilisateur: $NOM_USER = $MDP_USER" "domaine: $MON_DOMAINE" ""
		VERIF=$(nslookup "$MON_DOMAINE" | awk '/^Address: / { print $2 }')
		nslookup "$MON_DOMAINE" &>/dev/null
			if [[ ${?} -ne 0 ]]; then
				printf "%s\n" "" "${red}[Erreur : $MON_DOMAINE] Le nom de domaine n'est pas valide${end}"
				read -p "Press [enter] pour recommencer" -r
				MON_DOMAINE=$(hostname --fqdn) && REP="N"
			elif [[ "$VERIF" != "$IP" ]]; then
				printf "%s\n" "" "${red}[Erreur : $VERIF] Le nom de domaine: $MON_DOMAINE ne redirige pas vers l'IP $IP de ce serveur${end}"
				read -p "Press [enter] pour recommencer" -r
				MON_DOMAINE=$(hostname --fqdn) && REP="N"
			else 
				read -p "Etes-vous satisfait ? Press [Y/N] " -r REP
			fi
		_titre
	done
}

_set_password(){
	LIVE="/etc/letsencrypt/live/$MON_DOMAINE" && FULLCHAIN="$LIVE/fullchain.pem" && PRIVKEY="$LIVE/privkey.pem"
	_stop_seedbox
	REP="0"
	_titre
	while [[ "$REP" != "Y" ]]; do
		printf "%s\n" "MODIFICATION PASSWORD UTILISATEUR SEEDBOX" "" "Personnalisation"
		read -p "Utilisateur: " -e -i "$NOM_USER" -r NOM_USER
		read -p "Mot de passe: " -e -i "$MDP_USER" -r MDP_USER
		printf "%s\n" "" "Vérification" "Utilisateur: $NOM_USER = $MDP_USER" ""
		read -p "Etes-vous satisfait ? Press [Y/N] " -r REP
	done
	printf "%s" "$NOM_USER:$(openssl passwd -apr1 "$MDP_USER")" > "$HTPASSWD"
	_vsftpd
	_start_seedbox
	_status_seedbox
}

_installation_vpn(){
	apt-get update -y
	apt-get install -y openvpn openssl iptables tree nano dnsutils
	printf "%s\n" "Europe/Paris" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata
	rm -rf "${REP_OPENVPN:?}/"*
	if [[ "$OS" = "wheezy" ]]; then cp -r /usr/share/doc/openvpn/examples/easy-rsa/2.0 "$REP_RSA"; else apt-get install -y easy-rsa && cp -r /usr/share/easy-rsa "$REP_OPENVPN"; fi
}

_installation_seedbox(){
	apt-get update -y
	echo "Europe/Paris" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata
	apt-get install -y transmission-daemon nginx vsftpd fail2ban iptables db-util tree nano git
	_titre
	printf "%s\n" "Info : Sur un serveur dédié cette étape peut-etre très longue" ""
	if [[ ! -e "$DHPARAMS" ]]; then openssl dhparam 2048 > "$DHPARAMS"; else openssl dhparam -in "$DHPARAMS" &>/dev/null; fi
		if [[ ${?} -ne 0 ]]; then openssl dhparam 2048 > "$DHPARAMS"; fi
	# si vous depassez la limite de let's encrypt; (voir explication vidéo)
	# création certificat auto signé 
	openssl genrsa 4096 > "$MON_CERT_KEY"
	openssl req -subj "/O=mon serveur/OU=personnel/CN=$MON_DOMAINE" -new -x509 -days 365 -key "$MON_CERT_KEY" -out "$MON_CERT"
}

_backup_vpn(){
        if [[ ! -e "$SYSCTL".bak ]]; then cp "$SYSCTL" "$SYSCTL".bak; fi
        if [[ ! -e "$RC".bak ]]; then cp "$RC" "$RC".bak; fi
}

_backup_seedbox(){
        if [[ ! -e "$SSHD".bak ]]; then cp "$SSHD" "$SSHD".bak; fi
        if [[ ! -e "$MOTD".bak ]]; then cp "$MOTD" "$MOTD".bak; fi
        if [[ ! -e "$TRANSMISSION".bak ]]; then cp "$TRANSMISSION" "$TRANSMISSION".bak; fi
        if [[ ! -e "$VSFTPD".bak ]]; then cp "$VSFTPD" "$VSFTPD".bak; fi
        if [[ ! -e "$NGINX".bak ]]; then cp "$NGINX" "$NGINX".bak; fi
        if [[ ! -e "$JAIL_CONF".bak ]]; then cp "$JAIL_CONF" "$JAIL_CONF".bak; fi
}

_vpn(){
	sed -i '/^$\|#\|EASY_RSA=\|KEY/d' "$VARS"
	printf "%s\n" \
'export EASY_RSA='"$REP_RSA"'
export KEY_CONFIG=`$EASY_RSA/whichopensslcnf $EASY_RSA`
export KEY_DIR="$EASY_RSA/keys"
export KEY_SIZE=2048
export KEY_EXPIRE=3650
export KEY_COUNTRY='"$CERT_PAYS"'
export KEY_PROVINCE='"$CERT_PROV"'
export KEY_CITY='"$CERT_VILLE"'
export KEY_ORG='"$CERT_NAME"'
export KEY_EMAIL='"$CERT_MAIL"'
export KEY_OU='"$CERT_DESC"'
export KEY_NAME='"$CERT_NAME"'' >> "$VARS"
}

_create_cert_serveur(){
	source "$VARS"
	"$CLEAN" && "$BUILD" && "$PKITOOL" --initca && "$PKITOOL" --server openvpn
	"$REVOKE" revoke &>/dev/null
	openvpn --genkey --secret "$REP_KEY"/ta.key
	rm "$REP_KEY"/revoke-test.pem
	cp "$REP_KEY"/{ca.crt,ta.key,dh*.pem,crl.pem,openvpn.crt,openvpn.key} "$REP_OPENVPN"
}

_create_cert_clients(){
        i=$(grep -c "client" "$INDEX")
        n=$((ADD_VPN+i))
        source "$VARS"
        while [[ "$i" -lt "$n" ]] && [[ "$i" -lt 62 ]]; do
                i=$((i+1))
                if [[ "$OS" = "wheezy" ]]; then KEY_CN=client"$i" "$PKITOOL" client"$i"; else "$PKITOOL" client"$i"; fi
        done
}

_revoke_cert_client(){
	source "$VARS"
	"$REVOKE" client"$DEL_VPN" &>/dev/null
	rm "$REP_KEY"/revoke-test.pem &>/dev/null
	cp "$REP_KEY"/crl.pem "$REP_OPENVPN"
	rm "$REP_KEY"/client"$DEL_VPN".* &>/dev/null
		if [[ ${?} -eq 0 ]]; then printf "%s\n\n" "[ SUCCES ] Revoking certificat client $DEL_VPN"; else printf "%s\n\n" "${red}[ ECHEC ] Revoking certificat client $DEL_VPN${end}"; fi
	_stop_openvpn
	_start_openvpn
}

_conf_serveur(){
	printf "%s\n" \
"port $PORT_VPN
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
cipher AES-256-CBC
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
verb 3
log-append $LOG
status $STATUS" > "$OPENVPN"
	sed -i '/net.ipv4.ip_for/d' "$SYSCTL" && printf "%s\n" "net.ipv4.ip_forward=1" >> "$SYSCTL"
	if [[ "$PORT_VPN" = "443" ]]; then _sslh; fi
#############################
	systemctl enable openvpn@vpn.service
}

_sslh(){
	DEBIAN_FRONTEND='noninteractive' command apt-get install -y sslh 
	if [[ ! -e "$SSLH".bak ]]; then cp "$SSLH" "$SSLH".bak; fi
	cat "$SSLH".bak > "$SSLH"
	sed -i 's/RUN=.*$/RUN=yes/; /DAEMON_OPTS/d' "$SSLH"
	printf "%s\n" "DAEMON_OPTS=\"--user sslh --transparent --on-timeout ssl --listen $IP:443 --ssh $IP:4431 --openvpn $IP:4432 --ssl $IP:4433 --pidfile /var/run/sslh/sslh.pid\"" >> "$SSLH"
	sed -i 's/Port .*$/Port 4431/' "$SSHD"
	sed -i 's/port .*$/port 4432/; s/proto .*$/proto tcp/' "$OPENVPN"
	sed -i '/^exit/d; /^# création table/,+8d' "$RC"
	printf "%s\n" \
"# création table sslh -- tag paquets
iptables -t mangle -N SSLH
iptables -t mangle -A OUTPUT --protocol tcp --out-interface $NIC --sport 4431 --jump SSLH
iptables -t mangle -A OUTPUT --protocol tcp --out-interface $NIC --sport 4432 --jump SSLH
iptables -t mangle -A OUTPUT --protocol tcp --out-interface $NIC --sport 4433 --jump SSLH
iptables -t mangle -A SSLH --jump MARK --set-mark 0x1
iptables -t mangle -A SSLH --jump ACCEPT
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
exit 0" >> "$RC"
}

_conf_client(){
	printf "%s\n" \
"client
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
cipher AES-256-CBC
comp-lzo
verb 3" > "$REP_OPENVPN"/client_model
}

_create_rep_clients(){
	rm -rf "$REP_OPENVPN"/{clients,ccd}
	mkdir -p "$REP_OPENVPN"/{clients,ccd}
        n=$(grep -c "client" "$INDEX") && a=1 && b=2
        for (( i=1 ; i<="$n" ; i++ )); do
                a=$((a+4)) && b=$((b+4))
		if [[ -e "$REP_KEY"/client"$i".crt ]]; then
			mkdir -p "$REP_OPENVPN"/clients/client"$i"
		        cp "$REP_OPENVPN"/client_model "$REP_OPENVPN"/clients/client"$i".ovpn
			printf "%s\n" "<ca>" "$(cat "$REP_KEY"/ca.crt)" "</ca>" "<cert>" "$(cat "$REP_KEY"/client$i.key)" "</cert>" "<key>" "$(cat "$REP_KEY"/client$i.key)" "</key>" "<tls-auth>" "$(cat "$REP_KEY"/ta.key)" "</tls-auth>" >> "$REP_OPENVPN"/clients/client"$i".ovpn
			cp "$REP_KEY"/{ca.crt,client$i.crt,client$i.key,ta.key} "$REP_OPENVPN"/clients/client"$i"/
			cp "$REP_OPENVPN"/clients/client"$i".ovpn "$REP_OPENVPN"/clients/client"$i"/
                        sed -i "s/mon_client/client$i/" "$REP_OPENVPN"/clients/client"$i"/client"$i".ovpn
                        printf "%s\n" "ifconfig-push 10.8.0.$a 10.8.0.$b" > "$REP_OPENVPN"/ccd/client"$i"
                fi
        done
	rm -rf /tmp/clients && cp -r "$REP_OPENVPN"/clients /tmp/
	chmod -R 777 /tmp/clients
}

_nat(){
        a=1 && b=60000 && n=$(grep -c "client" "$INDEX") && m=$(((n*3)+1))
	sed -i '/^exit/d; /^# ouvert/,+'"$m"'d' "$RC"
        for (( i=1 ; i<="$n" ; i++ )); do
                a=$((a+4)) && b=$((b+1))
		printf "%s\n" \
"# ouverture port $b pour le client $i
iptables -t nat -A PREROUTING -p tcp --dport $b -j DNAT --to-destination 10.8.0.$a:$b
iptables -t nat -A PREROUTING -p udp --dport $b -j DNAT --to-destination 10.8.0.$a:$b" >> "$RC"
	done
        printf "%s\n" \
"# ouverture acces internet aux clients vpn
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
exit 0" >> "$RC"
}

_seedbox(){
# ajouter eventuellment une option "recharger tous les .torrents"
# rename 's/\.added$//' "$REP_SEEDBOX"/torrents
	usermod -aG ftp debian-transmission 
	install -d -m 0700 -o ftp -g ftp "$REP_SEEDBOX"/documents
	install -d -m 0770 -o ftp -g ftp "$REP_SEEDBOX"/{leech,seed,torrents}
	printf "%s" "$NOM_USER:$(openssl passwd -apr1 "$MDP_USER")" > "$HTPASSWD"
	printf "%s\n" \
'{
"dht-enabled":false,
"download-dir":"'"$REP_SEEDBOX"'/seed",
"incomplete-dir":"'"$REP_SEEDBOX"'/leech",
"incomplete-dir-enabled":true,
"peer-port":60000,
"pex-enabled":false,
"rpc-authentication-required":false,
"rpc-bind-address":"127.0.0.1",
"umask":0,
"utp-enabled":false,
"watch-dir-enabled":true,
"watch-dir":"'"$REP_SEEDBOX"'/torrents"
}' > "$TRANSMISSION"
}

_letsencrypt(){
	LIVE="/etc/letsencrypt/live/$MON_DOMAINE" && FULLCHAIN="$LIVE/fullchain.pem" && PRIVKEY="$LIVE/privkey.pem"
	rm -rf "$LETS_ENCRYTP" && git clone https://github.com/letsencrypt/letsencrypt "$LETS_ENCRYTP"
	if [[ "$MON_DOMAINE" = "$(hostname --fqdn)" ]]; then 
		"$LETS_ENCRYTP"/certbot-auto certonly --rsa-key-size 4096 --non-interactive --standalone --email admin@"$MON_DOMAINE" --domains "$MON_DOMAINE" --agree-tos
	else 
		"$LETS_ENCRYTP"/certbot-auto certonly --rsa-key-size 4096 --non-interactive --standalone --email admin@"$MON_DOMAINE" --domains "$MON_DOMAINE" --domains www."$MON_DOMAINE" --agree-tos
	fi
	if [[ ${?} -ne 0 ]]; then
		rm "$INFO" &>/dev/null
		printf "%s\n" "${red}[Erreur] Let's Encrypt ne vous a pas delivré de certificat (voir video)${end}" "Votre certificat auto signé est installé; Il est utilisé actuellement sur votre serveur" "Vous pouvez copier coller le message d'erreur ci-dessus et le poster sur le forum pour obtenir de l'aide" ""
		read -p "Appuyez sur [Enter] pour continuer " -r
	else
# les certificats letsencrypt sont valables 90 jours
# planification automatique dans le cron de la demande de renouvellement
		printf "%s\n" "$MON_DOMAINE" > "$INFO"
		( crontab -l | grep -v "$CRON_CMD" ; echo "$CRON_JOB" ) | crontab -
		printf "%s\n" "" "Let's Encrypt a validé votre domaine : $MON_DOMAINE" "Vous possedez un authentique certificat SSL; il est installé et utilisé sur ce serveur"
		read -p "Appuyez sur [Enter] pour continuer " -r
	fi
}

_nginx(){
	printf "%s\n" \
'server_tokens off;
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
auth_basic '"'Authentification Seedbox'"';
auth_basic_user_file '"$HTPASSWD"';
#ssl_certificate '"$MON_CERT"';
#ssl_certificate_key '"$MON_CERT_KEY"';
ssl_certificate '"$FULLCHAIN"';
ssl_certificate_key '"$PRIVKEY"';
ssl_dhparam '"$DHPARAMS"';
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
	if [[ "$PORT_VPN" = "443" ]]; then _sslh; fi
	# si vous avez réinstallé plus de 5 fois votre serveur dans la semaine 
	# on bascule sur le certificat auto signé (voir vidéo pour explications)
	if [[ ! -e "$INFO" ]]; then sed -i 's/#//g; /fullchain\|privkey/d' "$NGINX"; else sed -i '/#/d' "$NGINX"; fi
}

_fail2ban(){
	printf "%s\n" \
"[DEFAULT]
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
	if [[ ! -e "$REGEX_RECID" ]]; then printf "%s\n" '[INCLUDES]' 'before = common.conf' '[Definition]' '_daemon = fail2ban\.actions' '_jailname = recidive' 'failregex = ^(%(__prefix_line)s|,\d{3} fail2ban.actions%(__pid_re)s?:\s+)WARNING\s+\[(?!%(_jailname)s\])(?:.*)\]\s+Ban\s+<HOST>\s*$' 'ignoreregex =' > "$REGEX_RECID"; fi
	if [[ ! -e "$REGEX_NGINX" ]]; then printf "%s\n" '[Definition]' 'failregex = ^ \[error\] \d+#\d+: \*\d+ user "\S+":? (password mismatch|was not found in ".*"), client: <HOST>, server: \S+, request: "\S+ \S+ HTTP/\d+\.\d+", host: "\S+"\s*$' 'ignoreregex =' > "$REGEX_NGINX"; fi
	printf "%s\n" '[Definition]' 'failregex = .*Client "<HOST>",."530 Permission denied."$' '            .*Client "<HOST>",."530 Login incorrect."$' 'ignoreregex =' > "$REGEX_FTP"
}

_vsftpd(){
	mkdir -p /etc/vsftpd/vsftpd_user_conf
	rm -f /etc/vsftpd/vsftpd_user_conf/*
	printf "%s\n" "$NOM_USER" > "$USER_LIST"
	chmod 600 "$USER_LIST"
	printf "%s\n" "$NOM_USER" "$MDP_USER" > /etc/vsftpd/login
	db_load -T -t hash -f /etc/vsftpd/login /etc/vsftpd/login.db
	chmod 400 /etc/vsftpd/login.db
	rm /etc/vsftpd/login
	printf "%s\n" \
"seccomp_sandbox=NO
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
	printf "%s\n" \
"anon_world_readable_only=NO
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
		printf "%s\n" "auth required pam_userdb.so db=/etc/vsftpd/login" "account required pam_userdb.so db=/etc/vsftpd/login" > /etc/pam.d/vsftpd
	else 
		printf "%s\n" "auth required /lib/x86_64-linux-gnu/security/pam_userdb.so db=/etc/vsftpd/login" "account required /lib/x86_64-linux-gnu/security/pam_userdb.so db=/etc/vsftpd/login" > /etc/pam.d/vsftpd
	fi
}

_recap_install_vpn(){
	printf "%s\n" "" "Ouverture automatique d'un port pour chaque client VPN"
	a=1 && b=60000
        n=$(grep -c "client" "$INDEX")
        for (( i=1 ; i<="$n" ; i++ )); do a=$((a+4)) && b=$((b+1)) && printf "%s\n" "Client vpn $i \"10.8.0.$a\" ouverture du port $b" ""; done
	tree -vd /tmp/clients
	printf "%s\n" "" "Vos dossiers de clients VPN sont dans /tmp/clients/" "Récupérez-les puis rédemarrez votre serveur pour activer les règles NAT" "" "${int}Infos :" "Si vous etes sur Windows, utilisez winscp (voir video)" "Si vous etes sur Linux ou Mac copier dans votre terminal la commande scp suivante :${end}" "" "scp -P 22 -r root@$IP:/tmp/clients ./"
}

_recap_install_seedbox(){
	printf "%s\n" "Accès Seedbox et FTP : $MON_DOMAINE" "" "utilisateur: $NOM_USER" "password: $MDP_USER"
}

_stop_openvpn(){
        if [[ "$OS" = "wheezy" ]]; then service openvpn stop &>/dev/null;
                if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] openvpn Stopping"; fi
        else systemctl stop openvpn.service &>/dev/null;
                if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] openvpn Stopping"; fi
        fi
}

_start_openvpn(){
        if [[ "$OS" = "wheezy" ]]; then service openvpn start &>/dev/null;
                if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] openvpn Starting"; else printf "%s\n" "${red}[ FAIL ] openvpn is not Starting${end}"; fi
        else systemctl start openvpn@vpn.service &>/dev/null;
                if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] openvpn Starting"; else printf "%s\n" "${red}[ FAIL ] openvpn is not Starting${end}"; fi
        fi
}

_reload_openvpn(){
        if [[ "$OS" = "wheezy" ]]; then service openvpn reload &>/dev/null;
                if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] openvpn Starting"; else printf "%s\n" "${red}[ FAIL ] openvpn is not Starting${end}"; fi
        else systemctl reload openvpn@vpn.service &>/dev/null;
                if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] openvpn Starting"; else printf "%s\n" "${red}[ FAIL ] openvpn is not Starting${end}"; fi
        fi
}

_status_openvpn(){
	if [[ "$OS" = "wheezy" ]]; then service openvpn status &>/dev/null;
		if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] openvpn:$PORT_VPN is running"; else printf "%s\n" "${red}[ FAIL ] openvpn is not running${end}"; fi
	else systemctl status openvpn@vpn.service &>/dev/null;
		if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] openvpn:$PORT_VPN is running $PORT_VPN"; else printf "%s\n" "${red}[ FAIL ] openvpn is not running${end}"; fi
	fi
}

_stop_seedbox(){
        for i in "transmission-daemon" "vsftpd" "nginx" "fail2ban"; do
                if [[ "$OS" = "wheezy" ]]; then service $i stop &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] $i Stopping"; fi
                else systemctl stop $i.service &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] $i Stopping"; fi
                fi
        done
}

_start_seedbox(){
        for i in "transmission-daemon" "vsftpd" "nginx" "fail2ban"; do
                if [[ "$OS" = "wheezy" ]]; then service $i start &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then  printf "%s\n" "[ ok ] $i Starting"; else  printf "%s\n" "${red}[ FAIL ] $i is not Starting${end}"; fi
                else systemctl start $i.service &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then  printf "%s\n" "[ ok ] $i Starting"; else  printf "%s\n" "${red}[ FAIL ] $i is not Starting${end}"; fi
                fi
        done
}

_status_seedbox(){
        for i in "transmission-daemon" "vsftpd" "nginx" "fail2ban"; do
                if [[ "$OS" = "wheezy" ]]; then service $i status &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] $i is running"; else printf "%s\n" "${red}[ FAIL ] $i is not running${end}"; fi
                else systemctl status $i.service &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then printf "%s\n" "[ ok ] $i is running"; else printf "%s\n" "${red}[ FAIL ] $i is not running${end}"; fi
                fi
        done
}

_reload_nginx(){
                if [[ "$OS" = "wheezy" ]]; then service nginx reload &>/dev/null; else systemctl reload nginx.service &>/dev/null; fi
}

_titre(){
	clear
	printf "%s\n" \
"
___________ .___   _______       _____    .____      _________    ____ ___  ___________
\_   _____/ |   |  \      \     /  _  \   |    |     \_   ___ \  |    |   \ \__    ___/
 |    __)   |   |  /   |   \   /  /_\  \  |    |     /    \  \/  |    |   /   |    |   
 |     \    |   | /    |    \ /    |    \ |    |___  \     \____ |    |  /    |    |   
 \___  /    |___| \____|__  / \____|__  / |_______ \  \______  / |______/     |____|   
"
}
