#!/bin/bash
# script auto install seedbox (transmission-daemon + nginx + vsftpd + fail2ban + let's encrypt)

# prochaine maj :
# - interface gestion des jails de fail2ban
# - plus de commentaires
# - ameliorer les retours d'erreur
# - éventuellement creer ou adatper le script pour du multi-users avec mise en place d'une politique de quota (pas grand chose à modifier, faut juste abandonner les users virtuels)

# compatible :
# - debian 7 wheezy / debian 8 jessie

# repertoires principaux
PARTITION=$(df -l | awk '{print $2 " " $6}' | sort -nr | awk 'NR==1{print $2}' | sed -e '/\/$/ s/.*//')
REP_SEEDBOX="$PARTITION/seedbox"

VSFTPD="/etc/vsftpd.conf"
VSFTPD_LOG="/var/log/vsftpd.log"
TRANSMISSION="/etc/transmission-daemon/settings.json"
NGINX="/etc/nginx/sites-available/default"
HTPASSWD="/etc/nginx/.htpasswd"
OPENVPN="/etc/openvpn/vpn.conf"
MOTD="/etc/motd"
DHPARAMS="/etc/ssl/private/dhparams.pem"
MON_CERT_KEY="/etc/ssl/private/services.key"
MON_CERT="/etc/ssl/private/services.crt"
	if [[ -e "$OPENVPN" ]]; then PORT_VPN=$(awk 'NR==1{print $2}' "$OPENVPN"); else PORT_VPN="0"; fi

JAIL_CONF="/etc/fail2ban/jail.conf"
JAIL_LOCAL="/etc/fail2ban/jail.local"
REGEX_FTP="/etc/fail2ban/filter.d/vsftpd-virtuel.conf"
REGEX_RECID="/etc/fail2ban/filter.d/recidive.conf"

# certificats ssl delivrés par let's encrypt
# attention 5 certificats max distribués par semaine pour le même FQDN ou 20 pour le même domaine 
# donc si vous depassez les limites de let's encrypt; (voir explication vidéo) vous basculez sur un certificat auto signé.
LETS_ENCRYTP="/opt/letsencrypt"
INFO="/etc/letsencrypt/info"
CRON_CMD="$LETS_ENCRYTP/letsencrypt-auto renew --non-interactive"
CRON_JOB="00 00 * * * $CRON_CMD &>/dev/null"

# fichiers système
SSHD="/etc/ssh/sshd_config"

# infos serveur
IP=$(wget -qO- ipv4.icanhazip.com)
	if [[ -z "$IP" ]]; then IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1); fi
ARCH=$(getconf LONG_BIT)
MON_DOMAINE=$(hostname --fqdn)
	if [[ -e "$INFO" ]]; then MON_DOMAINE=$(sed q "$INFO"); fi

MDP_USER=$(</dev/urandom tr -dc 'a-zA-Z0-9-@!' | fold -w 12 | head -n 1)
USER_LIST="/etc/vsftpd/vsftpd.user_list"
NOM_USER="lancelot"
	if [[ -e "$USER_LIST" ]]; then NOM_USER=$(sed q "$USER_LIST"); fi

WARN=$(tput setaf 1)
NC=$(tput sgr0)

function verification(){
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

function set_infos(){
	REP="0"
	while [[ "$REP" != "Y" ]]; do
		echo "CREATION UTILISATEUR VIRTUEL SEEDBOX"
		echo ""
		echo "Personnalisation"
		read -p "Utilisateur: " -e -i "$NOM_USER" -r NOM_USER
		read -p "Mot de passe: " -e -i "$MDP_USER" -r MDP_USER
		echo ""
		echo "Possédez-vous un nom de domaine et souhaitez-vous l'utilisez ? "
		read -p "Si oui saisissez-le ou bien laissez par défaut $(hostname --fqdn): " -e -i "$MON_DOMAINE" -r MON_DOMAINE
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
	echo "Europe/Paris" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata
	apt-get install -y transmission-daemon nginx vsftpd fail2ban iptables db-util tree nano git dnsutils
	if [[ ! -e "$DHPARAMS" ]]; then openssl dhparam 2048 > "$DHPARAMS";
	elif [[ -e "$DHPARAMS" ]]; then openssl dhparam -in "$DHPARAMS" &>/dev/null;
		if [[ ${?} -ne 0 ]]; then openssl dhparam 2048 > "$DHPARAMS"; fi
	fi
	# si vous depassez la limite de let's encrypt; (voir explication vidéo)
	# création certificat auto signé 
	openssl genrsa 4096 > "$MON_CERT_KEY"
	openssl req -subj "/O=mon serveur/OU=personnel/CN=$MON_DOMAINE" -new -x509 -days 365 -key "$MON_CERT_KEY" -out "$MON_CERT"
}

function backup(){
        if [[ ! -e "$SSHD".bak ]]; then cp "$SSHD" "$SSHD".bak; fi
        if [[ ! -e "$MOTD".bak ]]; then cp "$MOTD" "$MOTD".bak; fi
        if [[ ! -e "$TRANSMISSION".bak ]]; then cp "$TRANSMISSION" "$TRANSMISSION".bak; fi
        if [[ ! -e "$VSFTPD".bak ]]; then cp "$VSFTPD" "$VSFTPD".bak; fi
        if [[ ! -e "$NGINX".bak ]]; then cp "$NGINX" "$NGINX".bak; fi
        if [[ ! -e "$JAIL_CONF".bak ]]; then cp "$JAIL_CONF" "$JAIL_CONF".bak; fi
        if [[ ! -e "$REGEX_RECID".bak ]]; then cp "$REGEX_RECID" "$REGEX_RECID".bak &>/dev/null; fi
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
}" >> $TRANSMISSION
}

function letsencrypt(){
	LIVE="/etc/letsencrypt/live/$MON_DOMAINE"
	FULLCHAIN="$LIVE/fullchain.pem"
	PRIVKEY="$LIVE/privkey.pem"
	if [[ "$PORT_VPN" = "443" ]]; then stop_openvpn; fi
	rm -rf "$LETS_ENCRYTP" && git clone https://github.com/letsencrypt/letsencrypt "$LETS_ENCRYTP"
	echo ""
	if [[ "$MON_DOMAINE" = "$(hostname --fqdn)" ]]; then 
		"$LETS_ENCRYTP"/certbot-auto certonly --rsa-key-size 4096 --non-interactive --standalone --email admin@"$MON_DOMAINE" --domains "$MON_DOMAINE" --agree-tos
	else 
		"$LETS_ENCRYTP"/certbot-auto certonly --rsa-key-size 4096 --non-interactive --standalone --email admin@"$MON_DOMAINE" --domains "$MON_DOMAINE" --domains www."$MON_DOMAINE" --agree-tos
	fi
	if [[ ${?} -ne 0 ]]; then
		echo ""
		echo "Let's Encrypt ne vous a pas delivré de certificat"
		echo "Votre certificat auto signé est installé; Il est utilisé actuellement sur votre serveur"
		echo "Vous pouvez copier coller le message d'erreur ci-dessus et le poster sur le forum pour obtenir de l'aide"
		read -p "Appuyez sur [Enter] pour continuer " -r
	else
		# les certificats letsencrypt sont valables 90 jours
		# planification automatique dans le cron de la demande de renouvellement
		echo "$MON_DOMAINE" > "$INFO" && chmod 600 "$INFO"
		( crontab -l | grep -v "$CRON_CMD" ; echo "$CRON_JOB" ) | crontab -
		echo ""
		echo "Let's Encrypt a validé votre domaine: $MON_DOMAINE"
		echo "Vous possedez un authentique certificat SSL; il est installé et utilisé sur ce serveur "
		read -p "Appuyez sur [Enter] pour continuer " -r
	fi
	set_infos
	if [[ "$PORT_VPN" = "443" ]]; then start_openvpn; fi
}

function nginx(){
	echo "
server_tokens off;
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
ssl_dhparam $DHPARAMS;
#ssl_certificate $MON_CERT;
#ssl_certificate_key $MON_CERT_KEY;
ssl_certificate $FULLCHAIN;
ssl_certificate_key $PRIVKEY;
ssl_prefer_server_ciphers on;
ssl_protocols TLSv1.2;
ssl_ecdh_curve secp384r1;
ssl_ciphers EECDH+AESGCM:EECDH+AES;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
add_header Strict-Transport-Security 'max-age=31622400; includeSubDomains; preload';
location / {
auth_basic 'Restricted Content';
auth_basic_user_file $HTPASSWD;
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
	if [[ ! -d "$LIVE" ]]; then sed -i 's/^#//g; /fullchain\|privkey/d' "$NGINX"; else sed -i '/^#/d' "$NGINX";fi
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
maxretry = 3
[ssh-ddos]
enabled  = true
port     = ssh
filter   = sshd-ddos
logpath  = /var/log/auth.log
maxretry = 3
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
maxretry = 3
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
xferlog_enable=YES
ssl_ciphers=HIGH" > "$VSFTPD"
	if [[ ! -e "$VSFTPD_LOG" ]]; then touch "$VSFTPD_LOG" && chmod 600 "$VSFTPD_LOG"; fi
	if [[ "$OS" = "wheezy" ]]; then sed -i '/seccomp_sandbox=NO/d' "$VSFTPD"; fi
	# si vous avez réinstallé plus de 5 fois votre serveur dans la semaine 
	# on bascule sur le certificat auto signé (voir vidéo pour explications)
	if [[ ! -d "$LIVE" ]]; then sed -i 's/^#//g; /fullchain\|privkey/d' "$VSFTPD"; fi
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

function infos(){
	cat "$MOTD".bak > "$MOTD"
	sed -i '/Accès/,$d' /etc/motd
	echo "
Accès Seedbox et FTP : $MON_DOMAINE

Lancer gestion VPN: vpn.sh
Lancer gestion Seedbox: seedbox.sh
" >> /etc/motd
}

function recap(){
	echo "Accès Seedbox et FTP : $MON_DOMAINE"
	echo ""
	echo "Utilisateur: $NOM_USER = $MDP_USER"
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

function status_services(){
        for i in "transmission-daemon" "vsftpd" "nginx" "fail2ban"; do
                if [[ "$OS" = "wheezy" ]]; then service $i status &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i is running"; else echo "${WARN}[ FAIL ]${NC} $i is not running"; fi
                else systemctl status $i.service &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i is running"; else echo "${WARN}[ FAIL ]${NC} $i is not running"; fi
                fi
        done
}

####################################################
# début du script
####################################################
verification
infos
OS_DESC=$(lsb_release -ds)
clear
if [[ -e "$TRANSMISSION" ]]; then
	OPTIONS="0"
	while [[ "$OPTIONS" != "Q" ]]; do
		clear
		REP="0"
		read -p "LA SEEDBOX EST DEJA INSTALLEE SUR CE SERVEUR :
		
Accès seedbox et ftp: $MON_DOMAINE

les données upload et download du FTP sont toujours conservées
1 ) Réinitialiser la configuration de la seedbox (renouveler certificat let's encrypt)
2 ) Supprimer installation

3 ) Redémarrer les services seedbox
4 ) Redémarrer le serveur

Q ) Taper Q pour quitter

Que voulez vous faire ? [1-6]: " -r OPTIONS
		case "$OPTIONS" in
			1)
			while [[ "$REP" != "Q" ]]; do
				clear
				echo "REINITIALISER CONFIGURATION SEEDBOX"
				echo ""
				echo "Taper Q pour quitter"
				read -p "Voulez vous vraiment réinitialiser la configuration de vos services ? [Y/Q] " -r REP
				if [[ "$REP" = "Y" ]]; then
					echo ""
					stop_seedbox
					clear
					echo "REINITIALISER CONFIGURATION SEEDBOX"
					echo "$OS_DESC"
					echo ""
					installation
					seedbox
					letsencrypt
					nginx
					vsftpd
					fail2ban
					start_seedbox
					clear
					status_services
					echo ""
					recap
					echo ""
					echo "Réinitialisation seedbox terminée sauvegardez vos informations"
					read -p "Appuyez sur [Enter] pour revenir au menu précedent  ... " -r
					set_infos
					REP="Q"
				fi
			done
			;;
			2)
			while [[ "$REP" != "Q" ]]; do
				clear
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
					rmf() { "$TRANSMISSION".bak,"$NGINX".bak,"$VSFTPD".bak,"$VSFTPD_LOG","$JAIL_LOCAL", "$HTPASSWD","$REGEX_RECID","$REGEX_RECID".bak,"$REGEX_FTP","$DHPARAMS","$MON_CERT_KEY","$MON_CERT"; }
					rm /var/www/html/index.nginx-debian.html &>/dev/null
					sed -i '/Accès/,$d' /etc/motd
					apt-get purge -y minissdpd transmission-cli transmission-common transmission-daemon nginx-common nginx vsftpd fail2ban
					rm -rf /etc/vsftpd
					apt-get autoremove -y
					apt-get update -y
					clear
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
	clear
	clear
	echo "INSTALLATION SERVEUR VPN ET SEEDBOX"
	echo "$OS_DESC"
	echo ""
	installation
	echo ""
	stop_seedbox
	backup
	seedbox
	clear
	echo "Requete pour obtenir un certificat SSL delivré par let's encrypt"
	echo "patientez quelques minutes"
	letsencrypt
	clear
	nginx
	vsftpd
	fail2ban
	start_seedbox
	clear
	status_services
	echo ""
	echo "RECAPITULATIF INSTALLATION SEEDBOX :"
	echo ""
	recap
	echo ""
	read -p "Appuyez sur [Enter] pour continuer ... " -r
	if [[ ! -e "$OPENVPN" ]]; then
		while [[ "$REP" != "N" ]]; do
			clear
			read -p "Voulez vous installer votre VPN ? [Y/N] " -r REP
			if [[ "$REP" = "Y" ]]; then
				wget https://raw.githubusercontent.com/finalcutgit411/master/master/vpn.sh --no-check-certificate
				chmod +x vpn.sh
				rm -f /usr/local/bin/vpn.sh
				mv vpn.sh /usr/local/bin/vpn.sh
				vpn.sh
				REP="N"
			fi
		done
	fi
	clear
	status_services
	echo ""
	echo "RECAPITULATIF INSTALLATION SEEDBOX :"
	echo ""
	recap
	echo ""
	echo "Installation terminée sauvegardez vos informations"
	read -p "Appuyez sur [Enter] pour redemarrer le serveur... " -r 
	shutdown -r now
	echo ""
	echo "A bientôt"
	echo ""
	exit 0
fi
