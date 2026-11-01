# seedtunnel — WireGuard VPN + secure seedbox

*[Version française](README.fr.md)*

A bash script, readable from top to bottom, that turns a freshly installed Debian server into:

- a **WireGuard VPN**: a QR code per client for phones, and one open port per client (handy for a torrent program at home, behind the VPN);
- a **seedbox**: Transmission behind nginx over HTTPS (Let's Encrypt, renewed automatically), files over SFTP (password or SSH keys), fail2ban.

Use the **menu** to get started, or the **commands** and a **configuration file** to automate. The two parts are independent. Messages are in **English or French**.

[![CI](https://github.com/finalcutgit411/seedtunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/finalcutgit411/seedtunnel/actions/workflows/ci.yml)

## Requirements

- Debian **12 (bookworm)** or **13 (trixie)**, both tested automatically at every change;
- a KVM virtual server or a dedicated server. Container-based servers (OpenVZ, LXC) often lack WireGuard: the script detects it and tells you.

## Installation

On a freshly installed Debian, as root.

### Published version (recommended)

Download a published version and check its fingerprint before running it. The commands are chained with `&&`: at the first error, everything stops with a clear message.

```bash
apt update && apt full-upgrade -y
V=1.2.4
cd "$(mktemp -d)"
curl -fLO https://github.com/finalcutgit411/seedtunnel/releases/download/v$V/seedtunnel-$V.tar.gz \
  && curl -fLO https://github.com/finalcutgit411/seedtunnel/releases/download/v$V/SHA256SUMS \
  && sha256sum -c SHA256SUMS \
  && tar -xzf seedtunnel-$V.tar.gz \
  && mv seedtunnel-$V /opt/seedtunnel \
  && /opt/seedtunnel/seedtunnel.sh
```

The available versions are listed on the [Releases](https://github.com/finalcutgit411/seedtunnel/releases) page.

### With git

To follow the development, or if you prefer git:

```bash
apt update && apt full-upgrade -y && apt install -y git
git clone https://github.com/finalcutgit411/seedtunnel.git /opt/seedtunnel
/opt/seedtunnel/seedtunnel.sh
```

In that case, `seedtunnel update` moves to the latest published version (tag `vX.Y.Z`).

The code is meant to be read: feel free to look through `seedtunnel.sh` and `lib/` before running it.

After that, the `seedtunnel` command opens the menu again. `seedtunnel update` moves to the next version after checking its checksum, then applies the configuration again so that its fixes take effect. If that fails, the previous version comes back.

## Usage

### Menu

`seedtunnel` without arguments gives access to everything: VPN, seedbox, firewall, diagnostics, backups, update. The state of the server is shown at the top: connected VPN clients, free disk space, stopped services.

### Commands

```text
seedtunnel vpn install [--config FILE]      seedtunnel seedbox install [--config FILE] [--staging]
seedtunnel vpn add phone [--qr]             seedtunnel seedbox password [--user NAME]
seedtunnel vpn remove phone --yes           seedtunnel seedbox domain my.domain.com [--staging]
seedtunnel vpn list                         seedtunnel seedbox sftp-config [filezilla]
seedtunnel vpn show phone                   seedtunnel seedbox sftp-key add my-key.pub
seedtunnel vpn share laptop                 seedtunnel seedbox sftp-key new
                                            seedtunnel seedbox sftp-password off
                                            seedtunnel seedbox bans | unban IP
seedtunnel firewall enable|disable|status   seedtunnel doctor
seedtunnel backup [--passphrase-file F]     seedtunnel backup list | share
seedtunnel backup auto on|off|status        seedtunnel restore FILE [--passphrase-file F]
seedtunnel update                           seedtunnel apply
seedtunnel language en|fr
```

`seedtunnel help` gives the details.

Without a terminal (in a script), destructive actions require `--yes`. The password is then given on the standard input:

```bash
printf '%s\n' "$NEW_PASSWORD" | seedtunnel seedbox password
```

### Configuration file

Everything the menu asks can be written in a file. The commented template is `examples/seedtunnel.conf`.

```bash
cp /opt/seedtunnel/examples/seedtunnel.conf /root/server.conf && chmod 600 /root/server.conf
nano /root/server.conf
seedtunnel vpn install --config /root/server.conf
seedtunnel seedbox install --config /root/server.conf
```

The installation is **idempotent**: run again with the same file, it changes nothing and restarts no service. If something was changed by hand, it puts everything back in order.

The file is never executed: it is only read line by line, and unknown keys are refused.

### Language

The first time the menu opens, it asks for the language: English or French. To change it later: `seedtunnel language fr` (or `en`), or `L` in the menu. The `LANGUAGE` key of the configuration file does the same, and `SEEDTUNNEL_LANG=fr` in the environment changes it for one command only.

## What the script does

### VPN

| | |
|---|---|
| Network | 10.8.0.0/24, server at 10.8.0.1 |
| Port | 51820/UDP by default |
| Clients | up to 253, named, can be revoked, applied without restarting |
| Open port | client number N gets port 60000+N, TCP and UDP |
| Leaks | all the IPv4 and IPv6 traffic of the client goes through the tunnel, while the tunnel is up (see the kill switch below) |
| Getting the configuration | QR code for phones, or a one-time download link for computers |

### Seedbox

| | |
|---|---|
| Web interface | `https://your-domain/` (user name + password) |
| Files | SFTP (WinSCP, FileZilla, Cyberduck), password and/or SSH keys; settings ready to import with `seedtunnel seedbox sftp-config` |
| Certificate | Let's Encrypt, or self-signed if no domain name points to the server |
| Folders | `watch/` (drop a .torrent here), `incomplete/`, `complete/`, `documents/` |
| Protection | fail2ban on SSH/SFTP, the web password and repeat offenders |
| Full disk | checked every 5 minutes: under 3 GB free, Transmission is stopped cleanly; it starts again by itself above 5 GB |

No domain name? Most providers give one (for example `vps-1234abcd.vps.ovh.net`). The script suggests it if it points to the server.

For your tests, `--staging` uses the test servers of Let's Encrypt. Their limits are much higher, but browsers do not trust their certificates.

### One-time download links

No need for `scp` to get a file onto your computer:

- `seedtunnel vpn share laptop` gives a link to the WireGuard configuration of the client;
- `seedtunnel backup share` gives a link to the latest backup;
- `seedtunnel seedbox sftp-config` gives an address to paste into WinSCP, with the fingerprint of the server inside: WinSCP checks by itself that it is the right server, without a question at the first connection. With `filezilla`, it also gives a link to a file to import into FileZilla;
- `seedtunnel seedbox sftp-key new` creates an SSH key and gives a link to it as a .ppk file, ready for WinSCP and FileZilla: SFTP without a password. No copy of the private key stays on the server.

The link goes through the HTTPS site of the seedbox. It holds a random token that cannot be guessed, works **only once** and expires after **10 minutes**. nginx serves the file once: any other request on it is refused, even right after on the same connection or with another form of the address, never a partial download, and the file is deleted right away. A HEAD request is refused without using the link up. Opening the page does not count, only downloading the file does, so an automatic link preview in a messaging app does not waste it.

### Firewall

`seedtunnel firewall enable` refuses everything that reaches the server, except:
- SSH, on the port actually used;
- the VPN and the seedbox, if installed;
- the ICMP that IPv6 needs.

This concerns what reaches the server itself. The VPN clients are trusted: what comes from them through the tunnel is accepted.

In a terminal, every change is **tried first**: without a confirmation from a new SSH connection within 2 minutes, the previous rules come back (or no rules, the first time). « yes » only counts once sshd has accepted a new login since the rules were applied: from the Internet, it always counts; through the VPN, only if your session comes through the VPN too; from the server itself, never. A confirmation from the Internet proves nothing for the VPN: its port is checked by the automatic tests, with a new tunnel through the firewall. The rules loaded at boot only change once confirmed.

### Diagnostics

`seedtunnel doctor` checks, giving for every problem the command that fixes it:
- the services;
- the DNS;
- the expiry of the certificate and its renewal;
- the ports and the firewall, including the SSH port: a port changed without updating the firewall would lock you out;
- the disk space, the full disk protection and the clock;
- the backups (see below).

It exits with status 1 when it finds a problem, so it can run in a scheduled task.

### Backups

`seedtunnel backup` creates an encrypted archive (AES-256) in `/var/backups/seedtunnel`, with:
- the keys and clients of the VPN;
- the settings and password hashes of the seedbox;
- the certificates and the SSH keys of SFTP;
- the firewall;
- the state of Transmission: list of torrents, progress, settings.

`seedtunnel backup auto on` makes an encrypted backup **every week** and keeps the last 4. Its passphrase is saved on the server (readable by root only) so that it can run alone: write it down somewhere else too.

A backup that stays on the server disappears with it: `seedtunnel backup share` gives a one-time link to download the latest one onto your computer. `seedtunnel doctor` reminds you when the weekly backup is off or fails, and when no backup was downloaded for a month.

On a new server, `seedtunnel restore FILE` puts everything back. The VPN clients connect again without any change if `VPN_PUBLIC_ADDRESS` is a domain name pointing to the new server.

Downloaded files are not in the backup: copy them with `rsync`.

## Security

- The control interface of Transmission (RPC) only listens on `127.0.0.1`: it is reached through nginx, and the password is checked twice, by nginx then by Transmission. Only its BitTorrent port (60000) is open to the peers.
- Transmission is **locked down by systemd** (`ProtectSystem=strict`…): it can only write to its own folders.
- Passwords are **never written in clear**, nor given as an argument to a command. Only their hashes are kept. The one exception is the passphrase of the weekly backup, if you turn it on: it is saved readable by root only, so that the backup can run alone.
- The SFTP user is locked inside the data folder: no shell, no tunnel. If sshd does not apply all these restrictions to it, from the server, through the VPN and from the Internet (a `Match` block before them in `sshd_config`, for example), the account is suspended rather than left without them.
- The files that may hold a secret (`--config`, `SEEDBOX_PASSWORD_FILE`, `--passphrase-file`) are refused if anyone but root can read them.
- With a self-signed certificate, every download link comes with its SHA-256 fingerprint, to check before accepting the warning of the browser.
- fail2ban bans attackers of SSH from **every port**, whatever the port of SSH.
- Hardened kernel network settings (`/etc/sysctl.d/90-seedtunnel-network.conf`): ICMP redirects ignored, source routing refused.
- The SSH configuration is checked (`sshd -t`) before being reloaded. On error, the previous version is put back.
- TLS 1.2/1.3 only. HSTS is only turned on with a real certificate.
- Automatic Debian security updates (`unattended-upgrades`).
- `/etc/seedtunnel` and the backups are readable by root only.

## Development

### Files

| File | Role |
|---|---|
| `seedtunnel.sh` | entry point: options, commands, main menu |
| `lib/common.sh` | output, input, log, configuration file, apt |
| `lib/i18n.sh` | translations |
| `lib/vpn.sh` | WireGuard |
| `lib/seedbox.sh` | Transmission, nginx, Let's Encrypt, SFTP, fail2ban |
| `lib/firewall.sh` | nftables firewall |
| `lib/share.sh` | one-time download links |
| `lib/diskguard.sh` | full disk protection |
| `lib/backup.sh` | backups and restore |
| `lib/update.sh` | update, applying the configuration again |
| `lib/doctor.sh` | diagnostics |
| `lang/` | French messages (`fr.txt`) and long texts (`en.sh`, `fr.sh`) |
| `tests/` | unit tests, translation check, Debian test image, integration tests |

Every module follows the same principle:
1. read the wanted state in `/etc/seedtunnel`;
2. generate the configuration files;
3. only replace the ones that changed (`write_if_changed`);
4. only restart the services concerned.

`seedtunnel apply` runs these steps again for everything installed. `seedtunnel update` runs it after every update.

### Translations

Messages are written in English, right in the code, as `printf` formats:

```bash
ok 'Client "%s" created.' "$name"
```

In French, each format is looked up in `lang/fr.txt`, a plain text file where every English line (`en: …`) is followed by its translation (`fr: …`). A missing translation simply shows the English text. Longer texts (help, summaries) are functions in `lang/en.sh` and `lang/fr.sh`.

`make i18n` checks that every message has its translation, with the same `%s`; `python3 tests/i18n_check.py --missing` prints the missing ones, ready to fill in.

### Automatic tests

At every push to GitHub, `.github/workflows/ci.yml`:

1. analyzes the code with **shellcheck**, checks the formatting with **shfmt** and the translations, then runs the **unit tests** (`tests/unit.sh`: bugs found in the past, so that they never come back);
2. starts a fresh Debian 12 and a fresh Debian 13 (containers with systemd), then runs `tests/integration.sh`, which:
   - really installs the VPN and the seedbox, and checks the **idempotence**;
   - opens a **real WireGuard tunnel**;
   - connects over **SFTP** with a password then with a key, and checks the lock-down;
   - tests the web interface, adds a **torrent** through the `watch/` folder;
   - checks that a **download link** only works once, even with another form of the address;
   - checks that fail2ban bans from every port, and the **full disk protection**;
   - tests the **firewall from the outside**;
   - makes **backups**, including weekly ones, downloads one, removes everything, **restores**, and checks that the old VPN client connects again and the torrents are back.

Locally: `make check` (needs `shellcheck`, `shfmt`, `python3` and `inotify-tools`), and `make fmt` to format the code.

### Publishing a version

1. Update `APP_VERSION` in `lib/common.sh`, for example `1.1.0`.
2. Add a `## [1.1.0]` section to `CHANGELOG.md`.
3. Push to `master`.

`.github/workflows/release.yml` sees that a new version is not published yet. It runs all the tests again, then creates the tag `v1.1.0` and publishes the archive and `SHA256SUMS` on GitHub. That is where `seedtunnel update` looks for new versions. Pushing a `v1.1.0` tag yourself works too. Development versions (with a dash, such as `1.1.0-dev`) are never published.

The repository used by `seedtunnel update` is set by `APP_REPO` in `lib/common.sh`. If you rename the repository or make a copy (fork), change it, as well as the links of this README.

## Known limits

- **WireGuard only works over UDP.** On a network that blocks UDP, try UDP port 443: it is often open, since HTTP/3 uses it.
- **The VPN is IPv4 only.** The IPv6 of the clients is blocked in the tunnel rather than leaking.
- **If the tunnel drops, the client goes out without it**, with its real address: the server cannot prevent that, the client must. To block everything outside the tunnel (kill switch):
  - Windows: WireGuard app → Edit the tunnel → tick « Block untunneled traffic (kill-switch) »;
  - Android: Settings → VPN → WireGuard (gear) → « Always-on VPN » and « Block connections without VPN »;
  - qBittorrent (any system): Options → Advanced → Network interface → the WireGuard tunnel: no tunnel, no download.
- **The seedbox has a single user.**

## Uninstalling

`seedtunnel seedbox uninstall`, `seedtunnel vpn uninstall`, `seedtunnel firewall disable`, or the options of the menu.

The downloaded data is kept, unless `--purge-data` is given. The backups stay in `/var/backups/seedtunnel`. Only the packages installed by seedtunnel are removed (listed in `/etc/seedtunnel/packages`): an nginx that was there before, for example, stays.

## History

seedtunnel started in 2016 as **finalcut**, a French script for Debian 7/8 (OpenVPN, vsftpd). It was rewritten for Debian 12/13 in 2026, then renamed seedtunnel and translated into English for version 1.0.0. See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE): you can use, change and share this script freely, as long as you keep the name of the author. It comes without any warranty.
