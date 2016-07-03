#!/bin/bash

# Scripts
SCRIPT_VPN="/usr/local/bin/vpn.sh"
SCRIPT_SEEDBOX="/usr/local/bin/seedbox.sh"

# Seedbox
PARTITION=$(df -l | awk '{print $2 " " $6}' | sort -nr | awk 'NR==1{print $2}' | sed -e '/\/$/ s/.*//')
REP_SEEDBOX="$PARTITION/seedbox"

# System
SYSCTL="/etc/sysctl.conf"
RC="/etc/rc.local"
SSHD="/etc/ssh/sshd_config"
MOTD="/etc/motd"

# Certificats
DHPARAMS="/etc/ssl/private/dhparams.pem"
MON_CERT_KEY="/etc/ssl/private/services.key"
MON_CERT="/etc/ssl/private/services.crt"

# Openvpn
REP_OPENVPN="/etc/openvpn"
REP_RSA="$REP_OPENVPN/easy-rsa"
REP_KEY="$REP_RSA/keys"
VARS="$REP_RSA/vars"
CLEAN="$REP_RSA/clean-all"
BUILD="$REP_RSA/build-dh"
PKITOOL="$REP_RSA/pkitool"
REVOKE="$REP_RSA/revoke-full"
INDEX="$REP_KEY/index.txt"
OPENVPN="$REP_OPENVPN/vpn.conf"
STATUS="$REP_OPENVPN/status.log"
LOG="$REP_OPENVPN/openvpn.log"
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

# Transimsion
TRANSMISSION="/etc/transmission-daemon/settings.json"

# Vsftpd
VSFTPD="/etc/vsftpd.conf"
VSFTPD_LOG="/var/log/vsftpd.log"
USER_LIST="/etc/vsftpd/vsftpd.user_list"

# Nginx
MDP_USER=$(</dev/urandom tr -dc 'a-zA-Z0-9-@!' | fold -w 12 | head -n 1)
NOM_USER="lancelot"
	if [[ -e "$USER_LIST" ]]; then NOM_USER=$(sed q "$USER_LIST"); fi
NGINX="/etc/nginx/sites-available/default"
HTPASSWD="/etc/nginx/.htpasswd"
JAIL_CONF="/etc/fail2ban/jail.conf"
JAIL_LOCAL="/etc/fail2ban/jail.local"
REGEX_FTP="/etc/fail2ban/filter.d/vsftpd-virtuel.conf"
REGEX_RECID="/etc/fail2ban/filter.d/recidive.conf"
REGEX_NGINX="/etc/fail2ban/filter.d/nginx-http-auth.conf"

# Let's Encrypt
# certificats ssl delivrés par let's encrypt
# attention 5 certificats max distribués par semaine pour le même FQDN ou 20 pour le même domaine 
# donc si vous depassez les limites de let's encrypt; (voir explication vidéo) vous basculez sur un certificat auto signé.
LETS_ENCRYTP="/opt/letsencrypt"
INFO="/etc/letsencrypt/info"
CRON_CMD="$LETS_ENCRYTP/letsencrypt-auto renew --non-interactive"
CRON_JOB="00 00 * * * $CRON_CMD &>/dev/null"

# Serveur
IP=$(wget -qO- ipv4.icanhazip.com)
if [[ -z "$IP" ]]; then IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1); fi
ARCH=$(getconf LONG_BIT)
MON_DOMAINE=$(hostname --fqdn)
	if [[ -e "$INFO" ]]; then MON_DOMAINE=$(sed q "$INFO"); fi
	
# Warning
WARN=$(tput setaf 1)
NC=$(tput sgr0)
