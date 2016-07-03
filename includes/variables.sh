#!/bin/bash

#scripts
SCRIPT_VPN="/usr/local/bin/vpn.sh"
SCRIPT_SEEDBOX="/usr/local/bin/seedbox.sh"

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
