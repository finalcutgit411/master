# finalcut — VPN WireGuard + seedbox sécurisée

Script en bash, lisible de haut en bas, qui transforme un serveur Debian fraîchement installé en :

- **VPN WireGuard** : un QR code par client pour les téléphones, un port ouvert par client (pratique pour un logiciel torrent à la maison derrière le VPN) ;
- **seedbox** : Transmission derrière nginx en HTTPS (Let's Encrypt renouvelé automatiquement), fichiers en SFTP (mot de passe ou clés SSH), fail2ban.

On l'utilise par un **menu** pour débuter, ou par des **commandes** et un **fichier de configuration** pour automatiser. Les deux parties sont indépendantes.

[![CI](https://github.com/finalcutgit411/finalcut/actions/workflows/ci.yml/badge.svg)](https://github.com/finalcutgit411/finalcut/actions/workflows/ci.yml)

## Compatibilité

- Debian **12 (bookworm)** et **13 (trixie)** — testées automatiquement à chaque modification ;
- VPS KVM ou serveur dédié. Les VPS en conteneur (OpenVZ, LXC) n'ont souvent pas WireGuard : le script le détecte et le signale.

## Installation

Sur une Debian fraîchement installée, en root.

### Version publiée (recommandé)

On télécharge une version publiée et on vérifie son empreinte avant de la lancer. Les commandes sont enchaînées par `&&` : à la moindre erreur, tout s'arrête avec un message clair.

```bash
apt update && apt full-upgrade -y
V=2.2.2
cd "$(mktemp -d)"
curl -fLO https://github.com/finalcutgit411/finalcut/releases/download/v$V/finalcut-$V.tar.gz \
  && curl -fLO https://github.com/finalcutgit411/finalcut/releases/download/v$V/SHA256SUMS \
  && sha256sum -c SHA256SUMS \
  && tar -xzf finalcut-$V.tar.gz \
  && mv finalcut-$V /opt/finalcut \
  && /opt/finalcut/finalcut.sh
```

Les versions disponibles sont listées sur la page [Releases](https://github.com/finalcutgit411/finalcut/releases).

### Avec git

Pour suivre le développement, ou si vous préférez git :

```bash
apt update && apt full-upgrade -y && apt install -y git
git clone https://github.com/finalcutgit411/finalcut.git /opt/finalcut
/opt/finalcut/finalcut.sh
```

Dans ce cas, `finalcut update` passe à la dernière version publiée (étiquette `vX.Y.Z`).

Le code est fait pour être lu : n'hésitez pas à parcourir `finalcut.sh` et `lib/` avant de le lancer.

Ensuite, la commande `finalcut` relance le menu. `finalcut update` passe à la version suivante en vérifiant son empreinte, puis réapplique la configuration pour que ses corrections prennent effet.

## Utilisation

### Menu

`finalcut` sans argument donne accès à tout : VPN, seedbox, pare-feu, diagnostic, sauvegarde, mise à jour.

### Commandes

```text
finalcut vpn install [--config FICHIER]     finalcut seedbox install [--config FICHIER] [--staging]
finalcut vpn add telephone [--qr]           finalcut seedbox password [--user NOM]
finalcut vpn remove telephone --yes         finalcut seedbox domain mon.domaine.fr [--staging]
finalcut vpn list                           finalcut seedbox sftp-config [filezilla]
finalcut vpn show telephone                 finalcut seedbox sftp-key add ma-cle.pub
finalcut vpn share pc-bureau                finalcut seedbox sftp-password off
                                            finalcut seedbox bans | unban IP
finalcut firewall enable|disable|status     finalcut doctor
finalcut backup [--output F] [--passphrase-file F]
finalcut restore FICHIER [--passphrase-file F]
finalcut update                             finalcut apply
```

`finalcut help` donne le détail.

Hors terminal (dans un script), les actions destructrices demandent `--yes`. Le mot de passe se passe alors sur l'entrée standard :

```bash
printf '%s\n' "$NOUVEAU_MDP" | finalcut seedbox password
```

### Fichier de configuration

Tout ce que le menu demande peut être écrit dans un fichier. Le modèle commenté est dans `examples/finalcut.conf`.

```bash
cp /opt/finalcut/examples/finalcut.conf /root/serveur.conf && chmod 600 /root/serveur.conf
nano /root/serveur.conf
finalcut vpn install --config /root/serveur.conf
finalcut seedbox install --config /root/serveur.conf
```

L'installation est **idempotente** : relancée avec le même fichier, elle ne change rien et ne redémarre aucun service. Si quelque chose a été modifié à la main, elle remet tout en ordre.

Le fichier n'est jamais exécuté : il est seulement lu ligne par ligne, et les clés inconnues sont refusées.

## Ce que fait le script

### VPN

| | |
|---|---|
| Réseau | 10.8.0.0/24, serveur en 10.8.0.1 |
| Port | 51820/UDP par défaut |
| Clients | jusqu'à 253, nommés, révocables, appliqués à chaud |
| Port ouvert | le client n°N reçoit le port 60000+N en TCP et UDP |
| Fuites | tout le trafic IPv4 et IPv6 du client passe par le tunnel |
| Récupération | QR code pour les téléphones, ou lien de téléchargement à usage unique pour les ordinateurs |

### Seedbox

| | |
|---|---|
| Interface web | `https://votre-domaine/` (identifiant + mot de passe) |
| Fichiers | SFTP (FileZilla, WinSCP, Cyberduck), mot de passe et/ou clés SSH ; réglages prêts à importer avec `finalcut seedbox sftp-config` |
| Certificat | Let's Encrypt, ou auto-signé si aucun nom de domaine ne pointe sur le serveur |
| Dossiers | `watch/` (déposez un .torrent), `incomplete/`, `complete/`, `documents/` |
| Protection | fail2ban sur SSH/SFTP, le mot de passe web et les récidivistes |

Pas de nom de domaine ? La plupart des hébergeurs en fournissent un (par exemple `vps-1234abcd.vps.ovh.net`). Le script le propose s'il pointe bien sur le serveur.

Pour vos essais, `--staging` utilise les serveurs de test de Let's Encrypt. Ils n'ont pas de limite, mais leur certificat n'est pas reconnu par les navigateurs.

### Liens de téléchargement

Plus besoin de `scp` pour récupérer un fichier sur son ordinateur :

- `finalcut vpn share pc-bureau` donne un lien vers la configuration WireGuard du client ;
- `finalcut seedbox sftp-config` donne une adresse à coller dans WinSCP, qui contient l'empreinte du serveur : WinSCP vérifie tout seul que c'est le bon serveur, sans question à la première connexion. Avec `filezilla`, elle crée en plus un lien vers un fichier à importer dans FileZilla.

Le lien passe par le site HTTPS de la seedbox. Il contient un jeton aléatoire impossible à deviner, ne fonctionne **qu'une fois** et expire au bout de **10 minutes**. Ouvrir la page ne compte pas : seul le téléchargement du fichier « consomme » le lien. Un aperçu automatique dans une messagerie ne le gâche donc pas.

### Pare-feu

`finalcut firewall enable` refuse tout ce qui arrive sur le serveur, sauf :
- SSH, sur le port réellement utilisé ;
- le VPN et la seedbox s'ils sont installés ;
- l'ICMP indispensable à IPv6.

Dans un terminal, l'activation est **provisoire** : sans confirmation depuis une nouvelle connexion SSH, tout est annulé au bout de 2 minutes. Impossible de se retrouver enfermé dehors.

### Diagnostic

`finalcut doctor` vérifie, avec pour chaque problème la commande qui le corrige :
- les services ;
- le DNS ;
- l'expiration du certificat et son renouvellement ;
- les ports et le pare-feu, dont le port SSH : un port changé sans mettre le pare-feu à jour vous enfermerait dehors ;
- l'espace disque et l'horloge.

Il renvoie le code 1 s'il trouve un problème : il peut tourner dans une tâche planifiée.

### Sauvegarde et restauration

`finalcut backup` crée une archive chiffrée (AES-256) contenant :
- les clés et clients du VPN ;
- les réglages et empreintes des mots de passe de la seedbox ;
- les certificats ;
- les clés SSH du SFTP ;
- le pare-feu.

Sur un serveur neuf, `finalcut restore` remet tout en place. Les clients VPN se reconnectent sans rien changer si `VPN_ENDPOINT` est un nom de domaine qui pointe vers le nouveau serveur.

Les fichiers téléchargés ne sont pas dans la sauvegarde : copiez-les avec `rsync`.

## Sécurité

- Transmission n'écoute que sur `127.0.0.1`. Seul nginx est exposé, et le mot de passe est vérifié deux fois : par nginx, puis par Transmission.
- Transmission est **enfermé par systemd** (`ProtectSystem=strict`…) : il ne peut écrire que dans ses dossiers.
- Les mots de passe ne sont **jamais écrits en clair**, ni passés en argument d'une commande. Seules leurs empreintes sont gardées.
- L'utilisateur SFTP est enfermé dans le dossier des données : pas de shell, pas de tunnel.
- fail2ban bannit les attaquants de SSH de **tous les ports**, quel que soit le port de SSH.
- Réglages réseau du noyau durcis (`/etc/sysctl.d/90-finalcut-reseau.conf`) : redirections ICMP ignorées, routage par la source refusé.
- La configuration SSH est vérifiée (`sshd -t`) avant d'être rechargée. En cas d'erreur, la version précédente est remise.
- TLS 1.2/1.3 uniquement. HSTS n'est activé qu'avec un vrai certificat.
- Mises à jour de sécurité Debian automatiques (`unattended-upgrades`).
- `/etc/finalcut` est lisible par root uniquement.

## Développement

### Organisation

| Fichier | Rôle |
|---|---|
| `finalcut.sh` | point d'entrée : options, commandes, menu principal |
| `lib/common.sh` | affichage, saisie, journal, fichier de configuration, apt |
| `lib/vpn.sh` | WireGuard |
| `lib/seedbox.sh` | Transmission, nginx, Let's Encrypt, SFTP, fail2ban |
| `lib/firewall.sh` | pare-feu nftables |
| `lib/doctor.sh` | diagnostic |
| `lib/maintenance.sh` | sauvegarde, restauration, mise à jour, réapplication |
| `lib/share.sh` | liens de téléchargement à usage unique |
| `tests/` | image Debian de test et tests d'intégration |

Chaque module suit le même principe :
1. lire l'état voulu dans `/etc/finalcut` ;
2. générer les fichiers de configuration ;
3. ne remplacer que ceux qui ont changé (`write_if_changed`) ;
4. ne redémarrer que les services concernés.

`finalcut apply` refait ces étapes pour tout ce qui est installé. `finalcut update` le lance après chaque mise à jour.

### Tests automatiques

À chaque envoi sur GitHub, `.github/workflows/ci.yml` :

1. analyse le code avec **shellcheck** et vérifie la mise en forme avec **shfmt** ;
2. lance une Debian 12 et une Debian 13 vierges (conteneurs avec systemd), puis y exécute `tests/integration.sh`, qui :
   - installe le VPN et la seedbox pour de vrai ;
   - ouvre un **vrai tunnel WireGuard** ;
   - se connecte en **SFTP** par mot de passe puis par clé, et vérifie l'enfermement ;
   - teste l'interface web et vérifie l'**idempotence** ;
   - vérifie qu'un **lien de téléchargement** ne sert qu'une fois ;
   - teste le **pare-feu depuis l'extérieur** ;
   - fait une **sauvegarde**, désinstalle tout, **restaure** et vérifie que l'ancien client VPN se reconnecte.

En local : `make check` (il faut `shellcheck` et `shfmt`), `make fmt` pour remettre le code en forme.

### Publier une version

1. Mettez à jour `FC_VERSION` dans `lib/common.sh`, par exemple `2.3.0`.
2. Ajoutez une section `## [2.3.0]` dans `CHANGELOG.md`.
3. Envoyez sur `master`.

`.github/workflows/release.yml` voit qu'une nouvelle version n'est pas encore publiée. Il relance tous les tests, puis crée l'étiquette `v2.3.0` et publie sur GitHub l'archive et `SHA256SUMS`. C'est là que `finalcut update` va chercher les nouvelles versions. Envoyer soi-même une étiquette `v2.3.0` fonctionne aussi.

Le dépôt interrogé par `finalcut update` est défini par `FC_REPO` dans `lib/common.sh`. En cas de renommage du dépôt ou de copie (fork), adaptez-le, ainsi que les liens de ce README.

## Limites connues

- **WireGuard ne fonctionne qu'en UDP.** Sur un réseau qui bloque l'UDP, essayez le port 443 en UDP : il est souvent ouvert, car HTTP/3 l'utilise.
- **Le VPN est en IPv4 uniquement.** L'IPv6 des clients est bloqué dans le tunnel plutôt que de fuiter.
- **La seedbox est mono-utilisateur.**

## Désinstallation

`finalcut seedbox uninstall`, `finalcut vpn uninstall`, `finalcut firewall disable`, ou les options du menu.

Les données téléchargées sont conservées, sauf avec `--purge-data`.

## Licence

[MIT](LICENSE) : vous pouvez utiliser, modifier et redistribuer ce script librement, à condition de conserver la mention de l'auteur. Il est fourni sans aucune garantie.
