ATTENTION EN COURS DE MODIF NE PAS UTILISER ....
Lundi 27 juin 11h00


## Script installation VPN et seedbox sécurisée (mono utilisateur)
###### A executer suite à une clean install de votre serveur
```
apt-get update -y && apt-get upgrade -y
```
```
wget -P /usr/local/bin/ -N https://raw.githubusercontent.com/finalcutgit411/master/master/{vpn.sh,seedbox.sh,finalcut.sh,functions.sh,variables.sh} --no-check-certificate
chmod 700 /usr/local/bin/{finalcut.sh,vpn.sh,seedbox.sh} && finalcut.sh
```







#### Tuto Youtube


#### Compatibilité serveur Debian 32 ou 64 bits (recommandé debian 8 jessie 64)
 * debian 8  jessie 
 * debian 7  wheezy
