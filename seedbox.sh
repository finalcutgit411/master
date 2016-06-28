#!/bin/bash
# shellcheck source=/dev/null
# script auto install seedbox (transmission-daemon + nginx + vsftpd + fail2ban + let's encrypt)

# prochaine maj :
# - plus de visilbilté dans les jails
# - améliorer les regex de fail2ban
# - options supplementaires dans transmission
# - plus de commentaires
# - ameliorer les retours d'erreur
# - simplifier les grep awk sed
# - éventuellement creer ou adatper le script pour du multi-users avec mise en place d'une politique de quota (pas grand chose à modifier, faut juste abandonner les users virtuels)

# compatible :
# - debian 8 jessie,
# - debian 7 wheezy
# - ubuntu 16 xenial
# - ubuntu 15 vivid
# - ubuntu 15 wily
# - ubuntu 14 trusty
# - (voir pour du centos si il y a des demandes)

# repertoires principaux
PARTITION=$(df -l | awk '{print $2 " " $6}' | sort -nr | awk 'NR==1{print $2}' | sed -e '/\/$/ s/.*//')
REP_SEEDBOX="$PARTITION/seedbox"

LOG="$REP_SEEDBOX/ftp.log"
VSFTPD="/etc/vsftpd.conf"
TRANSMISSION="/etc/transmission-daemon/settings.json"
NGINX="/etc/nginx/sites-available/default"
OPENVPN="/etc/openvpn/vpn.conf"
if [[ -e "$OPENVPN" ]]; then PORT_VPN=$(awk 'NR==1{print $2}' "$OPENVPN"); else PORT_VPN="0"; fi

FAILJAIL="/etc/fail2ban/jail.conf"
FAILLOCAL="/etc/fail2ban/jail.local"
FAILFTP="/etc/fail2ban/filter.d/vsftpd.conf"
FAILRECID="/etc/fail2ban/filter.d/recidive.conf"

# certificats ssl delivrés par let's encrypt
# attention 5 certificats max distribués par FQDN par semaine
# donc si vous depassez la limite de let's encrypt; (voir explication vidéo) vous basculez sur un certificat auto signé.
SENCRYTP="/opt/letsencrypt"
CERTBOT="$SENCRYTP/certbot-auto certonly --non-interactive --standalone --email admin@$(hostname --fqdn) -d $(hostname --fqdn) --agree-tos"
CRONCMD="$SENCRYTP/letsencrypt-auto renew --non-interactive"
CRONJOB="00 00 * * * $CRONCMD &>/dev/null"

# certificat auto signé
SERVICES_KEY="/etc/ssl/private/services.key"
SERVICES_CRT="/etc/ssl/private/services.crt"

# fichiers système
SSHD="/etc/ssh/sshd_config"

# infos ip
IP=$(wget -qO- ipv4.icanhazip.com)
if [[ -z "$IP" ]]; then IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1); fi

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
			apt-get update -y && apt-get upgrade -y
			apt-get install -y lsb-release
			OS_DESC=$(lsb_release -ds 2>/dev/null)
			OS=$(lsb_release -cs 2>/dev/null)
                		if [[ ${?} -ne 0 ]]; then
					OPTIONS="0"
                        		while [[ -z "$OS" ]]; do
					clear
                        		read -p " Je n'ai pas reussi à récuperer la version de votre distibution
Est ce bien un des systèmes d'exploitation ci-dessous ?
1 ) Debian 8  Jessie
2 ) Debian 7  Wheezy
3 ) Ubuntu 16.04 Xenial
4 ) Ubuntu 15.10 Wily
5 ) Ubuntu 15.04 Vivid
6 ) Ubuntu 14.04 Trusty
Q ) Taper Q pour quitter

Si oui merci de me l'indiquer [1-7]: " -r OPTIONS
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

function set_infos(){
	REP="0"
	while [[ "$REP" != "Y" ]]; do
		echo "CREATION UTILISATEUR VIRTUEL SEEDBOX"
		echo ""
		echo "Personnalisation"
		read -p "Utilisateur: " -e -i "$NOM_USER" -r NOM_USER
		read -p "Mot de passe: " -e -i "$MDP_USER" -r MDP_USER
		echo ""
		echo "Vérification"
		echo "Utilisateur: $NOM_USER = $MDP_USER"
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
	echo "Europe/Paris" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata
	apt-get install -y transmission-daemon nginx vsftpd fail2ban iptables db-util tree nano git dnsutils
	##test!!!!!!!!!!!!!!!!!!!!!
	openssl genrsa 2048 > "$SERVICES_KEY"
	openssl req -subj "/OU=$(uname -n)/CN=Seedbox" -new -x509 -days 365 -key "$SERVICES_KEY" -out "$SERVICES_CRT"

}

function backup(){
        if [[ ! -e "$SSHD".bak ]]; then cp "$SSHD" "$SSHD".bak; fi
        if [[ ! -e "$TRANSMISSION".bak ]]; then cp "$TRANSMISSION" "$TRANSMISSION".bak; fi
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
\"umask\":0,
\"utp-enabled\":false,
\"watch-dir-enabled\":true,
\"watch-dir\":\"$REP_SEEDBOX/torrents\"
}" >> $TRANSMISSION
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

function nginx(){
	echo "server {
listen 80;
return 301 https://\$host\$request_uri;
}
server {
listen 443;
ssl on;
#ssl_certificate $SERVICES_CRT;
#ssl_certificate_key $SERVICES_KEY;
ssl_certificate /etc/letsencrypt/live/$(hostname --fqdn)/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/$(hostname --fqdn)/privkey.pem;
location / {
proxy_pass http://127.0.0.1:9091/;
}
}" > "$NGINX"
	if [[ "$PORT_VPN" = "443" ]]; then 
		sed -i "s/443/127.0.0.1:9090/" "$NGINX"
		stop_openvpn
		echo "port-share 127.0.0.1 9090" >> "$OPENVPN"
		start_openvpn
	fi
	# si vous avez réinstallé plus de 5 fois votre serveur dans la semaine 
	# on bascule sur le certificat auto signé (voir vidéo pour explications)
	if [[ ! -d "/etc/letsencrypt/live/$(hostname --fqdn)/" ]]; then sed -i 's/^#//g; /fullchain\|privkey/d' "$NGINX"; fi
}

function fail2ban(){
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
logpath = /var/log/auth.log
maxretry = 4
[vsftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
filter = vsftpd
logpath = $LOG
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
              
# peut-etre ajouter une regex anti-dos pour transmission 
# failregex = ^<HOST> -.*"(GET|POST).*HTTP.*"$
}

function vsftpd(){
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
vsftpd_log_file=$LOG" > "$VSFTPD"
	touch "$LOG" && chmod 600 "$LOG" && chown -R ftp:ftp "$LOG"
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

function motd(){
	sed -i '/Acc/,$d' /etc/motd
	echo "Accès seedbox :
http://$(hostname --fqdn)

Accès ftps :
$(hostname --fqdn) port 21

Administrer votre VPN :
vpn

Administrer votre Seedbox :
seedbox" >> /etc/motd
}

function recap(){
	echo "Accès seedbox : http://$(hostname --fqdn)"
	echo "Accès ftps : $(hostname --fqdn) port 21"
	echo ""
	echo "Utilisateur : $NOM_USER = $MDP_USER"
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
        for i in "transmission-daemon" "vsftpd" "nginx" "fail2ban"; do
                if [[ "$OS" = "wheezy" ]] || [[ "$OS" = "trusty" ]]; then service $i status &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i is running"; else echo "${WARN}[ FAIL ]${NC} $i is not running"; fi
                else systemctl status $i.service &>/dev/null;
                        if [[ ${?} -eq 0 ]]; then echo "[ ok ] $i is running"; else echo "${WARN}[ FAIL ]${NC} $i is not running"; fi
                fi
        done
}



####################################################
# début du script
verification
OS_DESC=$(lsb_release -ds)
clear
if [[ -e "$TRANSMISSION" ]]; then
	OPTIONS="0"
	while [[ "$OPTIONS" != "Q" ]]; do
		clear
		REP="0"
		read -p "LA SEEDBOX EST DEJA INSTALLEE SUR CE SERVEUR :
		
Accès seedbox : http://$(hostname --fqdn)
Accès ftps : $(hostname --fqdn) port 21

1 ) Modifier le nom et le mot de passe de l'utilisateur seedbox
2 ) Demander ou renouveler un certificat let's encrypt (explication dans la video)

les données upload et download du FTP sont toujours conservées
3 ) Réinitialiser la configuration de la seedbox
4 ) Supprimer installation

5 ) Redémarrer les services seedbox
6 ) Redémarrer le serveur

Q ) Taper Q pour quitter

Que voulez vous faire ? [1-6]: " -r OPTIONS
		case "$OPTIONS" in
			1)
			echo ""
			stop_seedbox
			clear
			cat "$TRANSMISSION".bak > "$TRANSMISSION"
			NOM_USER="lancelot"
			MDP_USER=$(</dev/urandom tr -dc 'a-zA-Z0-9-@!' | fold -w 12 | head -n 1)
			while [[ "$REP" != "Y" ]]; do
				echo "MODIFIER NOM ET MOT DE PASSE UTILISATEUR SEEDBOX"
				echo ""
				echo "Personnalisation"
				read -p "Nouvel utilisateur : " -e -i "$NOM_USER" -r NOM_USER
				read -p "Mot de passe: " -e -i "$MDP_USER" -r MDP_USER
				echo ""
				echo "Vérification"
				echo "Nouvel utilisateur : $NOM_USER = $MDP_USER"
				echo ""
				read -p "Etes-vous satisfait ? Press [Y/N] " -r REP
			done
			seedbox
			vsftpd
			echo ""
			start_seedbox
			echo ""
			recap
			echo ""
			read -p "Appuyez sur [Enter] pour revenir au menu précedent " -r
			;;

			2)
			echo ""
			stop_seedbox
			clear
			echo "DEMANDE DE CERTIFICAT SSL AUPRES DE LET'S ENCRYPT"
			echo ""
			#letsencrypt
			nginx
			vsftpd
			echo ""
			start_seedbox
			echo ""
			status_services
			echo ""
			if [[ ! -d "/etc/letsencrypt/live/$(hostname --fqdn)/" ]]; then 
				echo "Vos certificats ne sont pas disponibles, attendez encore quelques jours,"
				echo "let's encrypt n'en delivre que 5 par semaine par FQDN"
				echo "Votre certificat de secours auto signé est installé et utilisé sur votre serveur"
			else 
				echo "Vos certificats sont disponibles et installés sur votre serveur"
				echo ""
				tree /etc/letsencrypt/live/$(hostname --fqdn)/
			fi
			echo ""
			read -p "Appuyez sur [Enter] pour revenir au menu précedent " -r 
			;;

			3)
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
					cat "$TRANSMISSION".bak > "$TRANSMISSION"
					set_infos
					clear
					echo "REINITIALISER CONFIGURATION SEEDBOX"
					echo "$OS_DESC"
					echo ""
					installation
					seedbox
					#letsencrypt
					nginx
					vsftpd
					fail2ban
					start_seedbox
					clear
					status_services
					echo ""
					motd
					recap
					echo""
					read -p "Réinitialisation seedbox terminée sauvegardez et appuyez sur [Enter] pour quitter ... " -r 
				fi
			done
			;;

			4)
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
					rm {"$TRANSMISSION".bak,"$VSFTPD".bak,"$NGINX".bak,"$LOG","$FAILLOCAL"}
					rm /var/www/html/index.nginx-debian.html &>/dev/null
					apt-get purge -y minissdpd transmission-cli transmission-common transmission-daemon nginx-common nginx vsftpd fail2ban
					rm -rf /etc/vsftpd
					apt-get autoremove -y
					apt-get update -y
					echo ""
					read -p "Désinstallation seedbox terminée appuyez sur [Enter] pour quitter... " -r
					exit 0
				fi
			done
			;;

			5)
			echo ""
			stop_seedbox
			echo ""
			start_seedbox
			echo ""
			status_services
			echo ""
			read -p "Appuyez sur [Enter] " -r
			;;
			
			6)
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
	set_infos
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
	#letsencrypt
	clear
	nginx
	vsftpd
	fail2ban
	start_seedbox
	clear
	status_services
	motd
	echo "RECAPITULATIF INSTALLATION SEEDBOX :"
	recap
	read -p "Installation seedbox terminée sauvegardez et appuyez sur [Enter] pour quitter ... " -r 
fi
exit 0
