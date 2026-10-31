# seedtunnel — VPN WireGuard + seedbox sécurisée

*[English version](README.md)*

Script en bash, lisible de haut en bas, qui transforme un serveur Debian fraîchement installé en :

- **VPN WireGuard** : un QR code par client pour les téléphones, un port ouvert par client (pratique pour un logiciel torrent à la maison derrière le VPN) ;
- **seedbox** : Transmission derrière nginx en HTTPS (Let's Encrypt renouvelé automatiquement), fichiers en SFTP (mot de passe ou clés SSH), fail2ban.

On l'utilise par un **menu** pour débuter, ou par des **commandes** et un **fichier de configuration** pour automatiser. Les deux parties sont indépendantes. Les messages sont en **français ou en anglais**.

[![CI](https://github.com/finalcutgit411/seedtunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/finalcutgit411/seedtunnel/actions/workflows/ci.yml)

## Compatibilité

- Debian **12 (bookworm)** et **13 (trixie)**, testées automatiquement à chaque modification ;
- VPS KVM ou serveur dédié. Les VPS en conteneur (OpenVZ, LXC) n'ont souvent pas WireGuard : le script le détecte et le signale.

## Installation

Sur une Debian fraîchement installée, en root.

### Version publiée (recommandé)

On télécharge une version publiée et on vérifie son empreinte avant de la lancer. Les commandes sont enchaînées par `&&` : à la moindre erreur, tout s'arrête avec un message clair.

```bash
apt update && apt full-upgrade -y
V=1.1.1
cd "$(mktemp -d)"
curl -fLO https://github.com/finalcutgit411/seedtunnel/releases/download/v$V/seedtunnel-$V.tar.gz \
  && curl -fLO https://github.com/finalcutgit411/seedtunnel/releases/download/v$V/SHA256SUMS \
  && sha256sum -c SHA256SUMS \
  && tar -xzf seedtunnel-$V.tar.gz \
  && mv seedtunnel-$V /opt/seedtunnel \
  && /opt/seedtunnel/seedtunnel.sh
```

Les versions disponibles sont listées sur la page [Releases](https://github.com/finalcutgit411/seedtunnel/releases).

### Avec git

Pour suivre le développement, ou si vous préférez git :

```bash
apt update && apt full-upgrade -y && apt install -y git
git clone https://github.com/finalcutgit411/seedtunnel.git /opt/seedtunnel
/opt/seedtunnel/seedtunnel.sh
```

Dans ce cas, `seedtunnel update` passe à la dernière version publiée (étiquette `vX.Y.Z`).

Le code est fait pour être lu : n'hésitez pas à parcourir `seedtunnel.sh` et `lib/` avant de le lancer.

Ensuite, la commande `seedtunnel` relance le menu. `seedtunnel update` passe à la version suivante en vérifiant son empreinte, puis réapplique la configuration pour que ses corrections prennent effet.

## Utilisation

### Menu

`seedtunnel` sans argument donne accès à tout : VPN, seedbox, pare-feu, diagnostic, sauvegardes, mise à jour. L'état du serveur s'affiche en haut : clients VPN connectés, espace disque libre, services arrêtés.

### Commandes

```text
seedtunnel vpn install [--config FICHIER]   seedtunnel seedbox install [--config FICHIER] [--staging]
seedtunnel vpn add telephone [--qr]         seedtunnel seedbox password [--user NOM]
seedtunnel vpn remove telephone --yes       seedtunnel seedbox domain mon.domaine.fr [--staging]
seedtunnel vpn list                         seedtunnel seedbox sftp-config [filezilla]
seedtunnel vpn show telephone               seedtunnel seedbox sftp-key add ma-cle.pub
seedtunnel vpn share pc-bureau              seedtunnel seedbox sftp-key new
                                            seedtunnel seedbox sftp-password off
                                            seedtunnel seedbox bans | unban IP
seedtunnel firewall enable|disable|status   seedtunnel doctor
seedtunnel backup [--passphrase-file F]     seedtunnel backup list | share
seedtunnel backup auto on|off|status        seedtunnel restore FICHIER [--passphrase-file F]
seedtunnel update                           seedtunnel apply
seedtunnel language en|fr
```

`seedtunnel help` donne le détail.

Hors terminal (dans un script), les actions destructrices demandent `--yes`. Le mot de passe se passe alors sur l'entrée standard :

```bash
printf '%s\n' "$NOUVEAU_MOT_DE_PASSE" | seedtunnel seedbox password
```

### Fichier de configuration

Tout ce que le menu demande peut être écrit dans un fichier. Le modèle commenté est dans `examples/seedtunnel.conf`.

```bash
cp /opt/seedtunnel/examples/seedtunnel.conf /root/serveur.conf && chmod 600 /root/serveur.conf
nano /root/serveur.conf
seedtunnel vpn install --config /root/serveur.conf
seedtunnel seedbox install --config /root/serveur.conf
```

L'installation est **idempotente** : relancée avec le même fichier, elle ne change rien et ne redémarre aucun service. Si quelque chose a été modifié à la main, elle remet tout en ordre.

Le fichier n'est jamais exécuté : il est seulement lu ligne par ligne, et les clés inconnues sont refusées.

### Langue

À la première ouverture, le menu demande la langue : anglais ou français. Pour en changer ensuite : `seedtunnel language fr` (ou `en`), ou `L` dans le menu. La clé `LANGUAGE` du fichier de configuration fait de même, et `SEEDTUNNEL_LANG=fr` dans l'environnement la change pour une seule commande.

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
| Fichiers | SFTP (WinSCP, FileZilla, Cyberduck), mot de passe et/ou clés SSH ; réglages prêts à importer avec `seedtunnel seedbox sftp-config` |
| Certificat | Let's Encrypt, ou auto-signé si aucun nom de domaine ne pointe sur le serveur |
| Dossiers | `watch/` (déposez un .torrent), `incomplete/`, `complete/`, `documents/` |
| Protection | fail2ban sur SSH/SFTP, le mot de passe web et les récidivistes |
| Disque plein | contrôlé toutes les 5 minutes : sous 3 Go libres, Transmission est arrêté proprement ; il redémarre tout seul au-dessus de 5 Go |

Pas de nom de domaine ? La plupart des hébergeurs en fournissent un (par exemple `vps-1234abcd.vps.ovh.net`). Le script le propose s'il pointe bien sur le serveur.

Pour vos essais, `--staging` utilise les serveurs de test de Let's Encrypt. Leurs limites sont bien plus hautes, mais leur certificat n'est pas reconnu par les navigateurs.

### Liens de téléchargement à usage unique

Plus besoin de `scp` pour récupérer un fichier sur son ordinateur :

- `seedtunnel vpn share pc-bureau` donne un lien vers la configuration WireGuard du client ;
- `seedtunnel backup share` donne un lien vers la dernière sauvegarde ;
- `seedtunnel seedbox sftp-config` donne une adresse à coller dans WinSCP, qui contient l'empreinte du serveur : WinSCP vérifie tout seul que c'est le bon serveur, sans question à la première connexion. Avec `filezilla`, elle crée en plus un lien vers un fichier à importer dans FileZilla ;
- `seedtunnel seedbox sftp-key new` crée une clé SSH et donne un lien vers elle au format .ppk, prête pour WinSCP et FileZilla : SFTP sans mot de passe. Aucune copie de la clé privée ne reste sur le serveur.

Le lien passe par le site HTTPS de la seedbox. Il contient un jeton aléatoire impossible à deviner, ne fonctionne **qu'une fois** et expire au bout de **10 minutes**. nginx ne sert le fichier qu'une fois : toute autre requête est refusée, même juste après sur la même connexion ou avec une autre forme de l'adresse, jamais de téléchargement partiel, et le fichier est aussitôt supprimé. Une requête HEAD est refusée sans consommer le lien. Ouvrir la page ne compte pas, seul le téléchargement du fichier compte : l'aperçu automatique d'une messagerie ne gâche donc pas le lien.

### Pare-feu

`seedtunnel firewall enable` refuse tout ce qui arrive sur le serveur, sauf :
- SSH, sur le port réellement utilisé ;
- le VPN et la seedbox s'ils sont installés ;
- l'ICMP indispensable à IPv6.

Dans un terminal, chaque changement est d'abord **à l'essai** : sans confirmation depuis une nouvelle connexion SSH dans les 2 minutes, les règles précédentes reviennent (ou aucune règle, la première fois). Les règles chargées au démarrage ne changent qu'après confirmation.

### Diagnostic

`seedtunnel doctor` vérifie, avec pour chaque problème la commande qui le corrige :
- les services ;
- le DNS ;
- l'expiration du certificat et son renouvellement ;
- les ports et le pare-feu, dont le port SSH : un port changé sans mettre le pare-feu à jour vous enfermerait dehors ;
- l'espace disque, la protection contre le disque plein et l'horloge ;
- les sauvegardes (voir plus bas).

Il renvoie le code 1 s'il trouve un problème : il peut tourner dans une tâche planifiée.

### Sauvegardes

`seedtunnel backup` crée une archive chiffrée (AES-256) dans `/var/backups/seedtunnel`, contenant :
- les clés et clients du VPN ;
- les réglages et empreintes des mots de passe de la seedbox ;
- les certificats et les clés SSH du SFTP ;
- le pare-feu ;
- l'état de Transmission : liste des torrents, progression, réglages.

`seedtunnel backup auto on` fait une sauvegarde chiffrée **chaque semaine** et garde les 4 dernières. Sa phrase de passe est enregistrée sur le serveur (lisible par root uniquement) pour qu'elle tourne seule : notez-la aussi ailleurs.

Une sauvegarde restée sur le serveur disparaît avec lui : `seedtunnel backup share` donne un lien à usage unique pour télécharger la dernière sur votre ordinateur. `seedtunnel doctor` vous le rappelle quand la sauvegarde hebdomadaire est désactivée ou échoue, et quand aucune sauvegarde n'a été téléchargée depuis un mois.

Sur un serveur neuf, `seedtunnel restore FICHIER` remet tout en place. Les clients VPN se reconnectent sans rien changer si `VPN_PUBLIC_ADDRESS` est un nom de domaine qui pointe vers le nouveau serveur.

Les fichiers téléchargés ne sont pas dans la sauvegarde : copiez-les avec `rsync`.

## Sécurité

- Transmission n'écoute que sur `127.0.0.1`. Seul nginx est exposé, et le mot de passe est vérifié deux fois : par nginx, puis par Transmission.
- Transmission est **enfermé par systemd** (`ProtectSystem=strict`…) : il ne peut écrire que dans ses dossiers.
- Les mots de passe ne sont **jamais écrits en clair**, ni passés en argument d'une commande. Seules leurs empreintes sont gardées. Seule exception : la phrase de passe de la sauvegarde hebdomadaire, si vous l'activez, enregistrée lisible par root uniquement pour que la sauvegarde tourne seule.
- L'utilisateur SFTP est enfermé dans le dossier des données : pas de shell, pas de tunnel.
- fail2ban bannit les attaquants de SSH de **tous les ports**, quel que soit le port de SSH.
- Réglages réseau du noyau durcis (`/etc/sysctl.d/90-seedtunnel-network.conf`) : redirections ICMP ignorées, routage par la source refusé.
- La configuration SSH est vérifiée (`sshd -t`) avant d'être rechargée. En cas d'erreur, la version précédente est remise.
- TLS 1.2/1.3 uniquement. HSTS n'est activé qu'avec un vrai certificat.
- Mises à jour de sécurité Debian automatiques (`unattended-upgrades`).
- `/etc/seedtunnel` et les sauvegardes sont lisibles par root uniquement.

## Développement

### Organisation

| Fichier | Rôle |
|---|---|
| `seedtunnel.sh` | point d'entrée : options, commandes, menu principal |
| `lib/common.sh` | affichage, saisie, journal, fichier de configuration, apt |
| `lib/i18n.sh` | traductions |
| `lib/vpn.sh` | WireGuard |
| `lib/seedbox.sh` | Transmission, nginx, Let's Encrypt, SFTP, fail2ban |
| `lib/firewall.sh` | pare-feu nftables |
| `lib/share.sh` | liens de téléchargement à usage unique |
| `lib/diskguard.sh` | protection contre le disque plein |
| `lib/backup.sh` | sauvegardes et restauration |
| `lib/update.sh` | mise à jour, réapplication de la configuration |
| `lib/doctor.sh` | diagnostic |
| `lang/` | messages en français (`fr.txt`) et textes longs (`en.sh`, `fr.sh`) |
| `tests/` | tests unitaires, vérification des traductions, image Debian de test, tests d'intégration |

Chaque module suit le même principe :
1. lire l'état voulu dans `/etc/seedtunnel` ;
2. générer les fichiers de configuration ;
3. ne remplacer que ceux qui ont changé (`write_if_changed`) ;
4. ne redémarrer que les services concernés.

`seedtunnel apply` refait ces étapes pour tout ce qui est installé. `seedtunnel update` le lance après chaque mise à jour.

### Traductions

Les messages sont écrits en anglais, directement dans le code, comme formats `printf` :

```bash
ok 'Client "%s" created.' "$name"
```

En français, chaque format est cherché dans `lang/fr.txt`, un simple fichier texte où chaque ligne anglaise (`en: …`) est suivie de sa traduction (`fr: …`). Une traduction manquante affiche simplement le texte anglais. Les textes longs (aide, récapitulatifs) sont des fonctions dans `lang/en.sh` et `lang/fr.sh`.

`make i18n` vérifie que chaque message a sa traduction, avec les mêmes `%s` ; `python3 tests/i18n_check.py --missing` affiche celles qui manquent, prêtes à remplir.

### Tests automatiques

À chaque envoi sur GitHub, `.github/workflows/ci.yml` :

1. analyse le code avec **shellcheck**, vérifie la mise en forme avec **shfmt** et les traductions, puis lance les **tests unitaires** (`tests/unit.sh` : des bugs trouvés par le passé, pour qu'ils ne reviennent jamais) ;
2. lance une Debian 12 et une Debian 13 vierges (conteneurs avec systemd), puis y exécute `tests/integration.sh`, qui :
   - installe le VPN et la seedbox pour de vrai, et vérifie l'**idempotence** ;
   - ouvre un **vrai tunnel WireGuard** ;
   - se connecte en **SFTP** par mot de passe puis par clé, et vérifie l'enfermement ;
   - teste l'interface web, ajoute un **torrent** par le dossier `watch/` ;
   - vérifie qu'un **lien de téléchargement** ne sert qu'une fois, même avec une autre forme de l'adresse ;
   - vérifie que fail2ban bannit de tous les ports, et la **protection contre le disque plein** ;
   - teste le **pare-feu depuis l'extérieur** ;
   - fait des **sauvegardes**, dont hebdomadaires, en télécharge une, désinstalle tout, **restaure** et vérifie que l'ancien client VPN se reconnecte et que les torrents sont revenus.

En local : `make check` (il faut `shellcheck`, `shfmt`, `python3` et `inotify-tools`), et `make fmt` pour remettre le code en forme.

### Publier une version

1. Mettez à jour `APP_VERSION` dans `lib/common.sh`, par exemple `1.1.0`.
2. Ajoutez une section `## [1.1.0]` dans `CHANGELOG.md`.
3. Envoyez sur `master`.

`.github/workflows/release.yml` voit qu'une nouvelle version n'est pas encore publiée. Il relance tous les tests, puis crée l'étiquette `v1.1.0` et publie sur GitHub l'archive et `SHA256SUMS`. C'est là que `seedtunnel update` va chercher les nouvelles versions. Envoyer soi-même une étiquette `v1.1.0` fonctionne aussi. Les versions de développement (avec un tiret, comme `1.1.0-dev`) ne sont jamais publiées.

Le dépôt interrogé par `seedtunnel update` est défini par `APP_REPO` dans `lib/common.sh`. En cas de renommage du dépôt ou de copie (fork), adaptez-le, ainsi que les liens de ce README.

## Limites connues

- **WireGuard ne fonctionne qu'en UDP.** Sur un réseau qui bloque l'UDP, essayez le port 443 en UDP : il est souvent ouvert, car HTTP/3 l'utilise.
- **Le VPN est en IPv4 uniquement.** L'IPv6 des clients est bloqué dans le tunnel plutôt que de fuiter.
- **La seedbox est mono-utilisateur.**

## Désinstallation

`seedtunnel seedbox uninstall`, `seedtunnel vpn uninstall`, `seedtunnel firewall disable`, ou les options du menu.

Les données téléchargées sont conservées, sauf avec `--purge-data`. Les sauvegardes restent dans `/var/backups/seedtunnel`.

## Historique

seedtunnel est né en 2016 sous le nom de **finalcut**, un script en français pour Debian 7/8 (OpenVPN, vsftpd). Il a été réécrit pour Debian 12/13 en 2026, puis renommé seedtunnel et traduit en anglais pour la version 1.0.0. Voir [CHANGELOG.md](CHANGELOG.md).

## Licence

[MIT](LICENSE) : vous pouvez utiliser, modifier et redistribuer ce script librement, à condition de conserver la mention de l'auteur. Il est fourni sans aucune garantie.
