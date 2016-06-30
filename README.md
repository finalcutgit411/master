EN COURS DE MODIF NE PAS UTILISER ....
Lundi 27 juin 11h00


## Script installation VPN et seedbox sécurisée (mono utilisateur)
###### A executer suite à une clean install de votre serveur
<code>apt-get update -y && apt-get upgrade -y && shutdown -r now</code>
#### Installation VPN
<code>wget https://raw.githubusercontent.com/finalcutgit411/master/master/vpn.sh --no-check-certificate</code>
<code>chmod +x vpn.sh</code>
<code>mv -f vpn.sh /usr/local/bin/vpn.sh</code>
<code>vpn.sh</code>

#### Installation Seedbox
<code>
wget https://raw.githubusercontent.com/finalcutgit411/master/master/seedbox.sh --no-check-certificate && chmod +x seedbox.sh && mv -f seedbox.sh /usr/local/bin/seedbox.sh && seedbox.sh
</code>





#### Tuto Youtube
[![Video youtube](http://img11.hostingpics.net/pics/552319seedbox.jpg)](https://youtu.be/CRw4nTvR8ng "Video youtube")

#### Compatibilité serveur Debian 32 ou 64 bits (recommandé debian 8 jessie 64)
 * debian 8  jessie 
 * debian 7  wheezy

#### Support
<code>https://www.t411.ch/forum.php#/discussion/69408/tuto-video-debutant-script-installation-vpn-et-seedbox</code>
###### (penser à activer adblock avant d'aller sur le tracker t411.ch)
