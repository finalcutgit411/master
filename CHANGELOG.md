# Historique des versions

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
numérotation [SemVer](https://semver.org/lang/fr/) : MAJEUR.MINEUR.CORRECTIF.

## [2.1.2] - 2026-10-31

### Corrigé
- Pare-feu activé avant la seedbox : les ports 80/443 n'étaient ouverts qu'à la fin de l'installation, après la demande de certificat, que Let's Encrypt ne pouvait donc pas valider (« Timeout during connect »). Les ports sont maintenant ouverts dès le début, pour la seedbox comme pour le VPN.
- La commande `finalcut` est installée dans `/usr/local/bin`, présent dans le PATH même après un `su` sans tiret.

## [2.1.1] - 2026-10-31

### Corrigé
- `sysctl: command not found` après un `su` sans tiret : sur Debian, le PATH n'inclut alors pas `/usr/sbin`. Le script complète désormais le PATH lui-même, et les tests automatiques tournent dans ces conditions.
- Une installation du VPN interrompue est reprise au lancement suivant, au lieu d'afficher le menu de gestion d'un VPN incomplet.

## [2.1.0] - 2026-10-31

### Ajouté
- **Commandes** utilisables sans menu (`finalcut vpn add`, `finalcut seedbox password`…), voir `finalcut help`.
- **Fichier de configuration** (`--config`, modèle dans `examples/finalcut.conf`) pour installer sans répondre aux questions.
- **Installation idempotente** : relancer avec la même configuration ne redémarre rien et ne change rien.
- **Let's Encrypt en mode test** (`--staging`), sans limite de 5 certificats par semaine.
- **Clés SSH pour le SFTP**, avec possibilité de refuser le mot de passe en SFTP.
- **Pare-feu nftables** « tout refusé sauf le nécessaire », avec annulation automatique au bout de 2 minutes sans confirmation.
- **Transmission enfermé par systemd** : en cas de faille, il ne peut écrire que dans ses dossiers.
- **`finalcut doctor`** : diagnostic complet (services, DNS, certificat, ports, disque, horloge…).
- **`finalcut backup` / `restore`** : sauvegarde chiffrée, restauration sur un serveur neuf sans que les clients VPN aient à se reconfigurer.
- **`finalcut update`** : mise à jour vers la dernière version publiée, empreinte SHA-256 vérifiée.
- **Tests automatiques** sur GitHub Actions : shellcheck, shfmt, et installation réelle sur Debian 12 et 13.
- **Publication automatique** d'une version à l'envoi d'une étiquette `vX.Y.Z`.

### Modifié
- Les mots de passe de la seedbox sont conservés sous forme d'empreintes dans `/etc/finalcut/seedbox.secrets` (jamais en clair). Les installations 2.0 doivent redéfinir le mot de passe une fois : `finalcut seedbox password`.
- Le certificat Let's Encrypt existant est réutilisé tant qu'il est valide ; le renouvellement automatique (`certbot.timer`) est vérifié.

## [2.0.0] - 2026-10-31

### Modifié
- Réécriture complète pour Debian 12/13 :
  - WireGuard remplace OpenVPN ;
  - SFTP remplace vsftpd ;
  - nftables remplace iptables et rc.local ;
  - certbot passe par les paquets Debian ;
  - gestion des erreurs avec journal détaillé ;
  - fail2ban consultable depuis le menu.

## [1.0.0]

- Version d'origine : Debian 7/8, OpenVPN + sslh, Transmission, vsftpd, Let's Encrypt (`certbot-auto`).
