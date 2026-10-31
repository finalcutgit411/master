# Image de test : une Debian vierge avec systemd, comme sur un vrai serveur.
# Construite et lancée par .github/workflows/ci.yml (une fois en 12, une fois en 13).
ARG DEBIAN=bookworm
FROM debian:${DEBIAN}

ENV container=docker

# Le minimum d'un VPS fraîchement installé (systemd, SSH), plus les outils
# dont les tests ont besoin pour jouer le rôle d'un client (sshpass, ping, nc).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus iproute2 procps kmod ca-certificates curl \
        openssh-server openssh-client sshpass iputils-ping netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && systemctl mask getty@tty1.service console-getty.service systemd-firstboot.service

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
