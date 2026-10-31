# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions follow [Semantic Versioning](https://semver.org/): MAJOR.MINOR.PATCH.

## [1.0.0] - 2026-10-31

**seedtunnel is the new name of finalcut** (versions 1.0.0 to 2.2.2 below),
rewritten for an English-speaking audience, with French still available.

### Added
- **Messages in English and French**, chosen for each server: question at the first start of the menu, `seedtunnel language en|fr`, `L` in the menu, `LANGUAGE` key of the configuration file, or `SEEDTUNNEL_LANG` in the environment.
- **Weekly backup**: `seedtunnel backup auto on` makes an encrypted backup every week and keeps the last 4. `seedtunnel backup auto off|status`.
- **`seedtunnel backup share`**: one-time link to download the latest backup onto your computer.
- **The backup includes the state of Transmission**: list of torrents, progress and settings, put back by `seedtunnel restore`.
- **`seedtunnel doctor` watches the backups**: warning when the weekly backup is off, when the last automatic backup is more than 8 days old, and when no backup was downloaded for 30 days.
- **Full disk protection**: every 5 minutes, under 3 GB free in the data folder, Transmission is stopped cleanly; it starts again by itself above 5 GB. The menu and `seedtunnel doctor` show it.
- **Unit tests** (`make unit`) and a translation check (`make i18n`), run at every push.

### Changed
- New name everywhere: the `seedtunnel` command, `/opt/seedtunnel`, `/etc/seedtunnel`, `/var/log/seedtunnel.log`. Backups go to `/var/backups/seedtunnel`. Download links are served under `/share/`.
- Full words instead of abbreviations in the configuration file:

  | finalcut | seedtunnel |
  |---|---|
  | `VPN_ENDPOINT` | `VPN_PUBLIC_ADDRESS` |
  | `SB_USER` | `SEEDBOX_USER` |
  | `SB_PASSWORD`, `SB_PASSWORD_FILE` | `SEEDBOX_PASSWORD`, `SEEDBOX_PASSWORD_FILE` |
  | `SB_DOMAIN` | `SEEDBOX_DOMAIN` |
  | `SB_DATA` | `SEEDBOX_DATA_DIR` |
  | `SB_LETSENCRYPT` | `SEEDBOX_LETSENCRYPT` |
  | `SB_ACME` | `SEEDBOX_LETSENCRYPT_SERVER` |
  | `SB_SSH_KEYS_FILE` | `SEEDBOX_SSH_KEYS_FILE` |
  | `SB_SFTP_PASSWORD` | `SEEDBOX_SFTP_PASSWORD` |

- `seedtunnel backup` and `seedtunnel doctor` no longer wait for a menu left open in another window. When the script is already running, the message says which process, since when, and how to stop it.
- Removing both the VPN and the seedbox also turns the weekly backup off (the existing backups are kept).

### Fixed
- A VPN change refused by WireGuard showed « ok »: only the result of the last step was checked. Every step is now checked.
- A configuration file could be replaced by a half-written one if its generation failed (full disk). The previous version is now kept.
- A one-time link could be used more than once, with another form of the address (`?x` at the end) or with partial downloads. The file is now deleted as soon as it is opened, and served whole to one connection at a time.

### Moving from finalcut
There is no automatic migration. Remove finalcut (`finalcut seedbox uninstall`, `finalcut vpn uninstall`, `finalcut firewall disable`, then delete `/opt/finalcut`, `/etc/finalcut` and `/usr/local/bin/finalcut`), install seedtunnel, then import the new configurations of the VPN clients.

## finalcut (former name)

### [2.2.2] - 2026-10-31
- `finalcut seedbox sftp-config` is made for WinSCP first: the address to paste holds the fingerprint of the server, which WinSCP checks by itself. The FileZilla file is only created on request.

### [2.2.1] - 2026-10-31
- Main menu: the disk space also shows the total size, in color, and whether the partition holds both the system and the downloads.

### [2.2.0] - 2026-10-31
- Added `finalcut vpn share NAME` (one-time download link), `finalcut seedbox sftp-config`, the state of the server at the top of the menu, `finalcut apply`, and hardened kernel network settings.
- Fixed: fail2ban only banned attackers of SSH from port 22; `finalcut doctor` checks that the SSH port is open in the firewall.

### [2.1.3] - 2026-10-31
- The repository is renamed `finalcutgit411/finalcut`.

### [2.1.2] - 2026-10-31
- Fixed: ports 80/443 opened too late when the firewall was on before the seedbox (Let's Encrypt could not validate). The `finalcut` command goes into `/usr/local/bin`.

### [2.1.1] - 2026-10-31
- Fixed: `sysctl: command not found` after a `su` without a dash. An interrupted VPN installation is resumed.

### [2.1.0] - 2026-10-31
- Commands without the menu, configuration file, idempotent installation, Let's Encrypt test servers, SSH keys for SFTP, nftables firewall with automatic undo, Transmission locked down by systemd, `finalcut doctor`, encrypted backup and restore, `finalcut update` with a SHA-256 check, automatic tests and releases on GitHub.
- Seedbox passwords kept as hashes only.

### [2.0.0] - 2026-10-31
- Full rewrite for Debian 12/13: WireGuard instead of OpenVPN, SFTP instead of vsftpd, nftables instead of iptables, certbot from Debian, detailed log.

### [1.0.0] - 2016
- First version: Debian 7/8, OpenVPN + sslh, Transmission, vsftpd, Let's Encrypt (`certbot-auto`).
