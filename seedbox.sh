#!/bin/bash
# shellcheck source=/dev/null
# script auto install VPN et seedbox (openvpn + transmission-daemon + nginx + vsftpd + fail2ban + let's encrypt)

# date : juin 2016
# auteur : finalcut
# infos : https://github.com/finalcutgit411/master/blob/master/README.md
# vidéo : 

# prochaine maj :
# - plus de visilbilté dans les jails
# - améliorer les regex de fail2ban
# - options supplementaires dans transmission
# - chrooter le vpn
# - revoir le nom des variables.
# - plus de commentaires
# - ameliorer les retours d'erreur
# - simplifier les grep awk sed
# - peut etre separer ce script en plusieur fichier variables / fonctions / script
# - éventuellement creer ou adatper le script pour du multi-users avec mise en place d'une politique de quota (pas grand chose à modifier, faut juste abandonner les users virtuels)

# compatible :
# - debian 8 jessie,
# - debian 7 wheezy
# - ubuntu 16 xenial
# - ubuntu 15 vivid
# - ubuntu 15 wily
# - ubuntu 14 trusty
# - (voir pour du centos si il y a des demandes)


# certificats openvpn
CERT_PAYS="Fr"
CERT_PROV="French"
CERT_VILLE="Paris"
CERT_DESC="Prive"
CERT_NAME=$(uname -n)
CERT_MAIL="admin@$(hostname --fqdn)"
ADD_VPN="5"
PORT_VPN="1194"

# infos système
OS_DESC=$(lsb_release -ds)
IP=$(wget -qO- ipv4.icanhazip.com)
if [[ -z "$IP" ]]; then IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1); fi

# repertoires principaux
PARTITION=$(df -l | awk '{print $2 " " $6}' | sort -nr | awk 'NR==1{print $2}' | sed -e '/\/$/ s/.*//')
REP_SEEDBOX="$PARTITION/seedbox"
REP_OPENVPN="/etc/openvpn"
REP_RSA="$REP_OPENVPN/easy-rsa"
REP_KEY="$REP_RSA/keys"

# openvpn scripts
OPENVPN="$REP_OPENVPN/seedbox.conf"
if [[ -e "$OPENVPN" ]]; then PORT_VPN=$(awk 'NR==1{print $2}' "$OPENVPN"); fi
OPENVPNLOG="$REP_OPENVPN/seedbox.log"
VARS="$REP_RSA/vars"
CLEAN="$REP_RSA/clean-all"
BUILD="$REP_RSA/build-dh"
PKITOOL="$REP_RSA/pkitool"
REVOKE="$REP_RSA/revoke-full"
INDEX="$REP_KEY/index.txt"

# logs perso
VPN="$REP_SEEDBOX/vpn.log"
FTP="$REP_SEEDBOX/ftp.log"
SSH="$REP_SEEDBOX/ssh.log"

# fichiers système
SSHD="/etc/ssh/sshd_config"
SYS_CTL="/etc/sysctl.conf"
RC_L="/etc/rc.local"
VSFTPD="/etc/vsftpd.conf"
RSYSLOG="/etc/rsyslog.conf"

FAILJAIL="/etc/fail2ban/jail.conf"
FAILLOCAL="/etc/fail2ban/jail.local"
FAILFTP="/etc/fail2ban/filter.d/vsftpd.conf"
FAILRECID="/etc/fail2ban/filter.d/recidive.conf"

TRANSMISSION="/etc/transmission-daemon/settings.json"
NGINX="/etc/nginx/sites-available/default"

# certificats ssl delivrés par let's encrypt
# attention 5 certificats max distribués par FQDN par semaine
# donc si vous depassez la limite de let's encrypt; (voir explication vidéo) vous basculez sur un certificat auto signé.
SENCRYTP="/opt/letsencrypt"
CERTBOT="$SENCRYTP/certbot-auto certonly --non-interactive --standalone --email admin@$(hostname --fqdn) -d $(hostname --fqdn) --agree-tos"
CRONCMD="$SENCRYTP/letsencrypt-auto renew --non-interactive"
CRONJOB="0 0 * * * $CRONCMD &>/dev/null"

# certificat auto signé
SERVICES_KEY="/etc/ssl/private/services.key"
SERVICES_CRT="/etc/ssl/private/services.crt"

MDP_USER=$(</dev/urandom tr -dc 'a-zA-Z0-9-@!' | fold -w 12 | head -n 1)
USER_LIST="/etc/vsftpd/vsftpd.user_list"
NOM_USER="lancelot"
if [[ -e "$USER_LIST" ]]; then NOM_USER=$(sed q "$USER_LIST"); fi

WARN=$(tput setaf 1)
NC=$(tput sgr0)

# check si utilisateur root, carte tun/tap active, et distribution valide
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
                        		echo "Je n'ai pas reussi à récuperer la version de votre distibution.
Est ce bien un des systèmes d'exploitation ci-dessous ?

1 ) Debian 8  Jessie
2 ) Debian 7  Wheezy
3 ) Ubuntu 16.04 Xenial
4 ) Ubuntu 15.10 Wily
5 ) Ubuntu 15.04 Vivid
6 ) Ubuntu 14.04 Trusty
Q ) Taper Q pour quitter
"
                        		read -p "Si oui merci de me l'indiquer [1-7]: " -r OPTIONS
                                		case "$OPTIONS" in
                                        		1) OS="jessie" ;;
                                        		2) OS="wheezy" ;;
                                        		3) OS="xenial" ;;
                                        		4) OS="wily" ;;
                                        		5) OS="vivid" ;;
                                        		6) OS="trusty" ;;
                                        		Q) MESSAGE="Si votre systeme d'exploitation n'est pas référencé, si vous etes bien 
sur un Debian like vous pouvez forcer l'installation à vos risques et
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
Nombre de client VPN: $ADD_VPN
IP serveur: $IP
Utilisateur: $NOM_USER = $MDP_USER
"
}

function set_infos(){
	REP="0"
	while [[ "$REP" != "Y" ]]; do
		echo "PERSONNALISATION (ou laisser par defaut) :"
		read -p "Pays: " -e -i "$CERT_PAYS" -r CERT_PAYS
		read -p "Province: " -e -i "$CERT_PROV" -r CERT_PROV
		read -p "Ville: " -e -i "$CERT_VILLE" -r CERT_VILLE
		read -p "Description: " -e -i "$CERT_DESC" -r CERT_DESC
		read -p "Port VPN: " -e -i "$PORT_VPN" -r PORT_VPN
		read -p "Nombre de client VPN: " -e -i "$ADD_VPN" -r ADD_VPN
		read -p "IP serveur: " -e -i "$IP" -r IP
		read -p "Utilisateur: " -e -i "$NOM_USER" -r NOM_USER
		read -p "Mot de passe: " -e -i "$MDP_USER" -r MDP_USER
		clear
		echo "VERIFICATION :"
		show_infos
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
	apt-get update -y && apt-get upgrade -y
	# maj timezone pour la date et l'heure des logs
	echo "Europe/Paris" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata
	# supprime les anciennes installations d'openvpn
	if [[ -d "$REP_OPENVPN" ]]; then rm -rf "${REP_OPENVPN:?}/"*; fi
	apt-get install -y openvpn openssl transmission-daemon nginx vsftpd fail2ban iptables db-util tree nano git dnsutils
	if [[ "$OS" = "wheezy" ]]; then cp -r /usr/share/doc/openvpn/examples/easy-rsa/2.0 "$REP_RSA"; else apt-get install -y easy-rsa && cp -r /usr/share/easy-rsa "$REP_OPENVPN"; fi
}

function backup(){
        if [[ ! -e "$SSHD".bak ]]; then cp "$SSHD" "$SSHD".bak; fi
        if [[ ! -e "$RSYSLOG".bak ]]; then cp "$RSYSLOG" "$RSYSLOG".bak; fi
        if [[ ! -e "$TRANSMISSION".bak ]]; then cp "$TRANSMISSION" "$TRANSMISSION".bak; fi
        if [[ ! -e "$SYS_CTL".bak ]]; then cp "$SYS_CTL" "$SYS_CTL".bak; fi
        if [[ ! -e "$RC_L".bak ]]; then cp "$RC_L" "$RC_L".bak; fi
        if [[ ! -e "$VSFTPD".bak ]]; then cp "$VSFTPD" "$VSFTPD".bak; fi
        if [[ ! -e "$NGINX".bak ]]; then cp "$NGINX" "$NGINX".bak; fi
        if [[ ! -e "$FAILJAIL".bak ]]; then cp "$FAILJAIL" "$FAILJAIL".bak; fi
        if [[ ! -e "$FAILFTP".bak ]]; then cp "$FAILFTP" "$FAILFTP".bak; fi
        if [[ ! -e "$FAILRECID".bak ]]; then cp "$FAILRECID" "$FAILRECID".bak &>/dev/null; fi
}

function seedbox(){
	usermod -aG ftp debian-transmission
	mkdir -p "$REP_SEEDBOX"/documents
	chmod 700 -R "$REP_SEEDBOX"/documents
	chown -R ftp:ftp "$REP_SEEDBOX"/documents
	touch "$SSH"
	if [[ "$OS" = "jessie" ]] || [[ "$OS" = "wheezy" ]]; then chmod 600 "$SSH" && chown ftp:ftp "$SSH"; else chmod 660 "$SSH" && chown ftp:syslog "$SSH"; fi
	sed -i 's/SyslogFacility AUTH/SyslogFacility local5/; s/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/; s/Forwarding yes/Forwarding no/' "$SSHD"
	echo "local5.* $SSH" >> "$RSYSLOG"
	sed -i '/^$\|#\|COUNTRY\|PROVINCE\|CITY\|ORG\|EMAI\|OU\|NAME\|EASY_RSA=/d' "$VARS"
	sed -i '1iexport EASY_RSA="'$REP_RSA'"' "$VARS"
	# charge vos variables
	echo "export KEY_COUNTRY=$CERT_PAYS 
export KEY_PROVINCE=$CERT_PROV 
export KEY_CITY=$CERT_VILLE 
export KEY_ORG=$CERT_NAME 
export KEY_EMAIL=$CERT_MAIL 
export KEY_OU=$CERT_DESC 
export KEY_NAME=$CERT_NAME" >> "$VARS"
}

function letsencrypt(){
	rm -rf "$SENCRYTP" && git clone https://github.com/letsencrypt/letsencrypt "$SENCRYTP"
	$CERTBOT &>/dev/null && $CRONCMD
	# les certificats letsencrypt sont valables 90 jours
	# planification automatique dans le cron de la demande de renouvellement
	( crontab -l | grep -v "$CRONCMD" ; echo "$CRONJOB" ) | crontab -
	# si vous depassez la limite de let's encrypt; (voir explication vidéo)
	# création certificat de secours auto signé 
	openssl genrsa 2048 > "$SERVICES_KEY"
	openssl req -subj "/C=$CERT_PAYS/ST=$CERT_PROV/L=$CERT_VILLE/O=$CERT_DESC/OU=$CERT_NAME/CN=Seedbox" -new -x509 -days 365 -key "$SERVICES_KEY" -out "$SERVICES_CRT"
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
	if [[ "$OS" = "wheezy" ]] || [[ "$OS" = "trusty" ]]; then service openvpn reload &>/dev/null; else systemctl reload transmission-daemon.service &>/dev/null; fi
}

function conf_serveur(){
	# prochaine maj du script éventuellement chrooter le vpn et verifier les weaks diffie hellman pour les versions oldstables
	echo "port $PORT_VPN
proto udp
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
log-append $OPENVPNLOG
status $VPN" > "$OPENVPN"
	touch "$VPN"
	chmod 600 "$VPN"
	chown ftp:ftp "$VPN"
	if [[ "$PORT_VPN" = "443" ]]; then sed -i 's/udp/tcp\nport-share 127.0.0.1 9090/' "$OPENVPN"; fi
	if [[ "$OS" = "wheezy" ]]; then sed -i "s/dh2048.pem/dh1024.pem/" "$OPENVPN";
	elif [[ "$OS" = "xenial" ]] || [[ "$OS" = "wily" ]]; then chmod 666 "$VPN"; fi
	sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' "$SYS_CTL"
}

function conf_client(){
	echo "client
proto udp
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
	if [[ "$PORT_VPN" = "443" ]]; then sed -i "s/udp/tcp/" "$REP_OPENVPN"/client_model; fi
}

function create_rep_clients(){
        rm -rf "$REP_SEEDBOX"/vpn
	mkdir -p "$REP_SEEDBOX"/vpn && chmod 700 "$REP_SEEDBOX"/vpn
	rm -rf "$REP_OPENVPN"/{clients,ccd} && mkdir "$REP_OPENVPN"/{clients,ccd}
        n=$(grep -c "client" "$INDEX")
        a=1 && b=2
        for (( i=1 ; i<="$n" ; i++ )); do
                a=$((a+4)) && b=$((b+4))
		if [[ -e "$REP_KEY"/client"$i".crt ]]; then
		        cp "$REP_OPENVPN"/client_model "$REP_OPENVPN"/clients/client"$i".ovpn
		        {
		        echo "<ca>"
		        cat "$REP_KEY"/ca.crt 
		        echo "</ca>
<cert>"
		        cat "$REP_KEY"/client$i.crt
		        echo "</cert>
<key>"
		        cat "$REP_KEY"/client$i.key
		        echo "</key>
<tls-auth>"
		        cat "$REP_KEY"/ta.key
		        echo "</tls-auth>"
		        } >> "$REP_OPENVPN"/clients/client"$i".ovpn
                        sed -i "s/mon_client/client$i/" "$REP_OPENVPN"/clients/client"$i".ovpn
                        echo "ifconfig-push 10.8.0.$a 10.8.0.$b" > "$REP_OPENVPN"/ccd/client"$i"
                fi
        done
        cp "$REP_KEY"/ca.crt "$REP_OPENVPN"/clients/
        cp "$REP_OPENVPN"/clients/* "$REP_SEEDBOX"/vpn/
        chmod 600 "$REP_SEEDBOX"/vpn/* && chown -R ftp:ftp "$REP_SEEDBOX"/vpn
}

function nat(){
        sed -i '/^exit\|^$\|Client\|# ouvert\|10.8.0./d' "$RC_L"
        a=1 && b=60000
        n=$(grep -c "client" "$INDEX")
	# je prefere passer par rc.local, jamais vu, mais entendu parler de bug avec iptables-save en fonction des hebergeurs; 
	# alors bon dans le doute ..
        for (( i=1 ; i<="$n" ; i++ )); do
                a=$((a+4)) && b=$((b+1))
                echo "
# ouverture port $b pour le client$i 
iptables -t nat -A PREROUTING -p tcp --dport $b -j DNAT --to-destination 10.8.0.$a:$b
iptables -t nat -A PREROUTING -p udp --dport $b -j DNAT --to-destination 10.8.0.$a:$b" >> "$RC_L"
        done
        echo "
# ouverture acces internet aux clients vpn 
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP

exit 0" >> "$RC_L"
}

function conf_transmission(){
	mkdir -p "$REP_SEEDBOX"/{leech,seed,torrents} && chmod 770 -R "$REP_SEEDBOX"/{leech,seed,torrents} && chown -R ftp:ftp "$REP_SEEDBOX"/{leech,seed,torrents}
	# ajouter eventuellment une option "recharger tous les .torrents" dans une prochaine maj
	# rename 's/\.added$//' "$REP_SEEDBOX"/torrents
	sed -i 's/ //g; /dht-enabled\|incomplete\|download-dir\|peer-port"\|pex-enabled\|rpc-password\|rpc-username\|umask\|utp-enabled\|}/d' "$TRANSMISSION"
	echo "\"dht-enabled\":false,
\"download-dir\":\"$REP_SEEDBOX/seed\",
\"incomplete-dir\":\"$REP_SEEDBOX/leech\",
\"incomplete-dir-enabled\":true,
\"peer-port\":60000,
\"pex-enabled\":false,
\"rpc-password\":\"$MDP_USER\",
\"rpc-username\":\"$NOM_USER\",
\"umask\":7,
\"utp-enabled\":false,
\"watch-dir-enabled\":true,
\"watch-dir\":\"$REP_SEEDBOX/torrents\"
}" >> $TRANSMISSION
}

function conf_nginx(){
	echo "server {
listen 80;
return 301 https://\$host\$request_uri;
}
server {
listen 443;
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers \"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA\";
ssl_prefer_server_ciphers on;
#ssl_certificate $SERVICES_CRT;
#ssl_certificate_key $SERVICES_KEY;
ssl_certificate /etc/letsencrypt/live/$(hostname --fqdn)/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/$(hostname --fqdn)/privkey.pem;
location / {
proxy_pass http://127.0.0.1:9091/;
}
}" > "$NGINX"
	if [[ "$PORT_VPN" = "443" ]]; then sed -i "s/443/127.0.0.1:9090/" "$NGINX"; fi
	# si vous avez réinstallé plus de 5 fois votre serveur dans la semaine 
	# on bascule sur le certificat auto signé (voir vidéo pour explications)
	if [[ ! -d "/etc/letsencrypt/live/$(hostname --fqdn)/" ]]; then sed -i 's/^#//g; /fullchain\|privkey/d' "$NGINX"; fi
}

function conf_fail2ban(){
	cat "$FAILJAIL".bak > "$FAILJAIL"
	sed -i "s/\[ssh\]/\[sshd\]/" "$FAILJAIL"
	echo "
[DEFAULT]
# ban 30 min
bantime = 1800
findtime = 1800
ignoreip = 127.0.0.1/8 10.8.0.0/24
[sshd]
enabled = true
port = ssh,sftp
filter = sshd
logpath = $SSH
maxretry = 4
[vsftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
filter = vsftpd
logpath = $FTP
maxretry = 6
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = iptables-allports[name=recidive]
# ban 1 semaine
bantime = 604800
findtime = 86400
maxretry = 3" > "$FAILLOCAL"

# regex vsftpd basic à ameliorer pour prochaine maj need sleep too
	echo '[Definition]
failregex = .*Client "<HOST>",."530 Permission denied."$
            .*Client "<HOST>",."530 Login incorrect."$          
ignoreregex =' > "$FAILFTP"

# regex recidive basic à ameliorer pour prochaine maj
	echo '[INCLUDES]
before = common.conf
[Definition]
_daemon = fail2ban\.actions\s*
_jailname = recidive
failregex = .*WARNING .* Ban <HOST>
            .*NOTICE .* Ban <HOST>
ignoreregex = .*WARNING \[recidive\] Ban <HOST>
              .*NOTICE \[recidive\] Ban <HOST>' > "$FAILRECID"
}

function conf_vsftpd(){
	mkdir -p /etc/vsftpd/vsftpd_user_conf
	rm -f /etc/vsftpd/vsftpd_user_conf/*
	echo "$NOM_USER" > $USER_LIST
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
#rsa_cert_file=$SERVICES_CRT
#rsa_private_key_file=$SERVICES_KEY
rsa_cert_file=/etc/letsencrypt/live/$(hostname --fqdn)/fullchain.pem
rsa_private_key_file=/etc/letsencrypt/live/$(hostname --fqdn)/privkey.pem
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
strict_ssl_read_eof=YES
strict_ssl_write_shutdown=YES
ascii_download_enable=YES
ascii_upload_enable=YES
max_clients=10
max_per_ip=5
require_ssl_reuse=NO
ssl_ciphers=HIGH
xferlog_enable=YES
log_ftp_protocol=YES
vsftpd_log_file=$FTP" > "$VSFTPD"
	touch "$FTP" && chmod 600 "$FTP" && chown -R ftp:ftp "$FTP"
	# si vous avez réinstallé plus de 5 fois votre serveur dans la semaine 
	# on bascule sur le certificat auto signé (voir vidéo pour explications)
	if [[ ! -d "/etc/letsencrypt/live/$(hostname --fqdn)/" ]]; then sed -i 's/^#//g; /fullchain\|privkey/d' "$VSFTPD"; fi
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
	echo "auth required /lib/x86_64-linux-gnu/security/pam_userdb.so db=/etc/vsftpd/login
account required /lib/x86_64-linux-gnu/security/pam_userdb.so db=/etc/vsftpd/login" > /etc/pam.d/vsftpd
	if [[ "$OS" = "wheezy" ]]; then
		sed -i '/seccomp_sandbox=NO/d' "$VSFTPD"
		echo "auth required pam_userdb.so db=/etc/vsftpd/login
account required pam_userdb.so db=/etc/vsftpd/login" > /etc/pam.d/vsftpd
	fi
}

function stop_seedbox(){
        for i in "transmission-daemon" "vsftpd" "nginx" "fail2ban"; do
                if [[ "$OS" = "wheezy" ]] || [[ "$OS" = "trusty" ]]; then service $i stop &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i Stopping"; fi
                else systemctl stop $i.service &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i Stopping"; fi
                fi
        done
}

function start_seedbox(){
        for i in "transmission-daemon" "vsftpd" "nginx" "fail2ban"; do
                if [[ "$OS" = "wheezy" ]] || [[ "$OS" = "trusty" ]]; then service $i start &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i Starting"; else echo "${WARN}[ FAIL ]${NC} $i is not Starting"; fi
                else systemctl start $i.service &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i Starting"; else echo "${WARN}[ FAIL ]${NC} $i is not Starting"; fi
                fi
        done
}

function status_services(){
        for i in "openvpn" "transmission-daemon" "vsftpd" "nginx" "fail2ban"; do
                if [[ "$OS" = "wheezy" ]] || [[ "$OS" = "trusty" ]]; then service $i status &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i is running"; else echo "${WARN}[ FAIL ]${NC} $i is not running"; fi
                else systemctl status $i.service &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i is running"; else echo "${WARN}[ FAIL ]${NC} $i is not running"; fi
                fi
        done
}

function stop_openvpn(){
        if [[ "$OS" = "wheezy" ]] || [[ "$OS" = "trusty" ]]; then service openvpn stop &>/dev/null;
                if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn Stopping"; fi
        else systemctl stop openvpn.service &>/dev/null;
                if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn Stopping"; fi
        fi
}

function start_openvpn(){
        if [[ "$OS" = "wheezy" ]] || [[ "$OS" = "trusty" ]]; then service openvpn start &>/dev/null;
                if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn Starting"; else echo "${WARN}[ FAIL ]${NC} openvpn is not Starting"; fi
        else systemctl start openvpn.service &>/dev/null;
                if [[ ${?} -eq 0 ]]; then echo "[ ok ] openvpn Starting"; else echo "${WARN}[ FAIL ]${NC} openvpn is not Starting"; fi
        fi
}


function recap_install(){
	echo "RECAPITULATIF INSTALLATION SERVEUR ( $OS_DESC ) :
$(hostname --fqdn) $IP

Accès seedbox 
http://$(hostname --fqdn)

Accès ftps
$(hostname --fqdn) port 21

Utilisateur
$NOM_USER = $MDP_USER

Administrateur
root = (voir dans votre mail)

Clients vpn"  > "$REP_SEEDBOX"/documents/infos.txt
	chmod 600 "$REP_SEEDBOX"/documents/infos.txt && chown -R ftp:ftp "$REP_SEEDBOX"/documents
        a=1 && b=60000
        n=$(grep -c "client" "$INDEX")
        for (( i=1 ; i<="$n" ; i++ )); do
                a=$((a+4)) && b=$((b+1))
                echo "client vpn $i \"client$i\" Ip : 10.8.0.$a ouverture du port $b" >> "$REP_SEEDBOX"/documents/infos.txt
	done
	echo "
Arborescence " >> "$REP_SEEDBOX"/documents/infos.txt
	tree -pagu "$REP_SEEDBOX" >> "$REP_SEEDBOX"/documents/infos.txt
}

####################################################
# début du script
verification
clear
if [[ -e "$OPENVPN" ]]; then
	OPTIONS="0"
	while [[ "$OPTIONS" != "Q" ]]; do
		clear
		REP="0" && ADD_VPN="5"
		read -p "LES SERVICES SEEDBOX SONT DEJA INSTALLES SUR CE SERVEUR ( $OS_DESC ) :
$(hostname --fqdn) $IP

VPN
1 ) Ajouter des clients vpn
2 ) Revoquer des clients vpn
3 ) Renvoyer les clients vpn dans le FTP
4 ) Supprimer et réinitialiser tous les certificats serveur et clients d'openvpn

SEEDBOX
5 ) Modifier le nom et le mot de passe de l'utilisateur seedbox
6 ) Demander ou renouveler un certificat let's encrypt (explication dans la video)

SERVEUR (les données upload et download du FTP sont toujours conservées)
7 ) Réinitialiser la configuration d'openvpn et de la seedbox
8 ) Supprimer installation 
9 ) Redémarrer les services VPN et seedbox
10) Redémarrer le serveur

QUITTER
Q ) Taper Q pour quitter


Que voulez vous faire ? [1-10]: " -r OPTIONS
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
					echo "Liste client(s) VPN :"
					tree -v -I "ca.crt" "$REP_SEEDBOX"/vpn/
					read -p "	
Les règles NAT des clients VPN seront actives au prochain démarrage du serveur

Appuyez sur [Enter] pour revenir au menu précedent " -r
					REP="Q"
				fi
			done
			;;

			2)
			while [[ "$REP" != "Q" ]]; do
				VALID=$(grep 'V' "$INDEX" | grep -c 'client')
				VERIF=$(grep 'V' $INDEX | grep -n 'client[0-9]*' | awk -F ':' '{print $1}')
				clear
				echo "REVOQUER UN CLIENT VPN

$VALID client(s) vpn actif(s) sur le serveur

Liste client(s) VPN actif(s) :"
				grep 'V' $INDEX | grep -o 'client[0-9]*' | awk -F "client" '{print "client : " $2}'
				read -p "
Taper Q pour quitter
Taper le numéro du client à révoquer : " -r REP
				if [[ "$REP" != "Q" ]]; then
					for i in $VERIF; do
						if [[ "$REP" = "$i" ]]; then
							read -p "
Vous avez selectionné le client $REP
Merci de confirmer votre choix [Y/N] " -r CONF
							if [[ "$CONF" = "Y" ]]; then
								DEL_VPN="$REP"
								echo ""
								revoke_cert_client
								create_rep_clients
								read -p "
Appuyez sur [Enter] pour revenir au menu précedent " -r
								REP="Q" && CONF="0"
							fi
						fi
					done
				fi
			done
			;;

			3)
			create_rep_clients
			echo "
Envoi dans le FTP terminé "
			tree -v -I "ca.crt" "$REP_SEEDBOX"/vpn/
			read -p "
Appuyez sur [Enter] " -r 
			;;

			4)
			while [[ "$REP" != "Q" ]]; do
			clear
				read -p "REINITIALISER CERTIFICATS SERVEUR VPN

Taper Q pour quitter
Voulez vous vraiment réinitialiser les certificats du serveur ? [Y/Q] " -r REP
				if [[ "$REP" = "Y" ]]; then
					create_cert_serveur
					read -p "
Vous devez maintenant ajouter des clients VPN
Appuyez sur [Enter] pour revenir au menu précedent " -r
					REP="Q"
				fi
			done
			;;

			5)
			stop_seedbox
			clear
			cat "$TRANSMISSION".bak > "$TRANSMISSION"
			NOM_USER="lancelot"
			MDP_USER=$(</dev/urandom tr -dc 'a-zA-Z0-9-@!' | fold -w 12 | head -n 1)
			while [[ "$REP" != "Y" ]]; do
				read -p "
MODIFIER NOM ET MOT DE PASSE UTILISATEUR SEEDBOX

Personnalisation
Nouvel utilisateur : " -e -i "$NOM_USER" -r NOM_USER
				read -p "Mot de passe: " -e -i "$MDP_USER" -r MDP_USER
				read -p "
Vérification
Nouvel utilisateur : $NOM_USER = $MDP_USER

Etes-vous satisfait ? Press [Y/N] " -r REP
			done
			echo ""
			conf_transmission
			conf_vsftpd
			start_seedbox
			recap_install
			read -p "
Vous pouvez maintenant vous reconnecter au FTP et à la seedbox avec :
utilisateur : $NOM_USER = $MDP_USER
adresse : $(hostname --fqdn)

Appuyez sur [Enter] pour revenir au menu précedent " -r
			;;

			6)
			echo ""
			stop_seedbox
			clear
			echo "
DEMANDE DE CERTIFICAT SSL APRES DE LET'S ENCRYPT
"
			letsencrypt
			conf_nginx
			conf_vsftpd
			echo ""
			start_seedbox
			echo ""
			status_services
			echo ""
			if [[ ! -d "/etc/letsencrypt/live/$(hostname --fqdn)/" ]]; then 
				echo "
Vos certificats ne sont pas disponibles, attendez encore quelques jours,
let's encrypt n'en delivre que 5 par semaine par FQDN
Votre certificat de secours auto signé est installé et utilisé sur votre serveur"
			else 
				echo "
Vos certificats sont disponibles et installés sur votre serveur"
				tree /etc/letsencrypt/live/$(hostname --fqdn)/
			fi
			read -p "
Appuyez sur [Enter] pour revenir au menu précedent " -r 
			;;

			7)
			while [[ "$REP" != "Q" ]]; do
			clear
				read -p "REINITIALISER CONFIGURATION VPN ET SEEDBOX

Taper Q pour quitter
Voulez vous vraiment réinitialiser la configuration de vos services ? [Y/Q] " -r REP
				if [[ "$REP" = "Y" ]]; then
					clear
					stop_openvpn
					stop_seedbox
					clear
					cat "$SSHD".bak > "$SSHD"
					cat "$TRANSMISSION".bak > "$TRANSMISSION"
					cat "$SYS_CTL".bak > "$SYS_CTL"
					cat "$RC_L".bak > "$RC_L"
					cat "$RSYSLOG".bak > "$RSYSLOG"
					echo "EXEMPLE INFORMATIONS A SAISIR :"
					show_infos
					set_infos
					clear
					echo "INSTALLATION SERVEUR VPN ET SEEDBOX
$OS_DESC
"
					installation
					seedbox
					letsencrypt
					clean
					echo "Création des certificats VPN
cette étape est longue"
					create_cert_serveur
					create_cert_clients
					conf_serveur
					conf_client
					create_rep_clients
					nat
					conf_transmission
					conf_nginx
					conf_vsftpd
					conf_fail2ban
					start_openvpn
					start_seedbox
					recap_install
					clear
					status_services
					echo ""
					cat "$REP_SEEDBOX"/documents/infos.txt
					read -p "
Appuyez sur [Enter] pour redemarrer le serveur... " -r 
					shutdown -r now
					exit 0
				fi
			done
			;;

			8)
			while [[ "$REP" != "Q" ]]; do
			clear
				read -p "SUPPRIMER INSTALLATION VPN ET SEEDBOX

Taper Q pour quitter
Voulez vous vraiment supprimer vos services ? [Y/Q] " -r REP
				if [[ "$REP" = "Y" ]]; then
					stop_openvpn
					stop_seedbox
					gpasswd -d debian-transmission ftp
					cat "$SSHD".bak > "$SSHD"
					cat "$TRANSMISSION".bak > "$TRANSMISSION"
					cat "$SYS_CTL".bak > "$SYS_CTL"
					cat "$RC_L".bak > "$RC_L"
					cat "$VSFTPD".bak > "$VSFTPD"
					cat "$NGINX".bak > "$NGINX"
					cat "$RSYSLOG".bak > "$RSYSLOG"
					rm {"$SSHD".bak,"$RSYSLOG".bak,"$TRANSMISSION".bak,"$SYS_CTL".bak,"$RC_L".bak,"$VSFTPD".bak,"$NGINX".bak,"$VPN","$FTP","$SSH","$FAILLOCAL"}
					rm -rf /etc/openvpn/*
					rm /var/www/html/index.nginx-debian.html &>/dev/null
					rm "$REP_SEEDBOX"/documents/infos.txt
					rm -rf "$REP_SEEDBOX"/vpn
					apt-get purge -y openvpn minissdpd transmission-cli transmission-common transmission-daemon nginx-common nginx-light vsftpd fail2ban
					rm -rf /etc/vsftpd
					apt-get autoremove -y
					apt-get update -y && apt-get upgrade -y
					read -p "
Appuyez sur [Enter] pour redemarrer le serveur... " -r
					shutdown -r now
					exit 0
				fi
			done
			;;

			9)
			echo ""
			stop_openvpn
			stop_seedbox
			echo ""
			start_openvpn
			start_seedbox
			echo ""
			status_services
			echo ""
			read -p "Appuyez sur [Enter] " -r
			;;
			
			10)
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
	set_infos
	
	clear
	echo "INSTALLATION SERVEUR VPN ET SEEDBOX 
$OS_DESC
"
	installation
	stop_openvpn
	stop_seedbox
	backup
	seedbox
	clean
	echo "Requete pour obtenir un certificat SSL delivré par let's encrypt
patientez quelques minutes"
	letsencrypt
	clean
	echo "Création des certificats VPN
cette étape est longue"
	create_cert_serveur
	create_cert_clients
	conf_serveur
	conf_client
	create_rep_clients
	nat
	conf_transmission
	conf_nginx
	conf_vsftpd
	conf_fail2ban
	start_openvpn
	start_seedbox
	recap_install
	clear
	status_services
	echo ""
	cat "$REP_SEEDBOX"/documents/infos.txt
	read -p "Appuyez sur [Enter] pour redemarrer le serveur... " -r 
	shutdown -r now
fi
exit 0
