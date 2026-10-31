# Test image: a fresh Debian with systemd, like a real server.
# Built and started by .github/workflows/ci.yml (once with Debian 12, once
# with Debian 13).
ARG DEBIAN=bookworm
FROM debian:${DEBIAN}

ENV container=docker

# The minimum of a freshly installed VPS (systemd, SSH), plus the tools the
# tests need to play the part of a client (sshpass, ping, nc).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus iproute2 procps kmod ca-certificates curl \
        openssh-server openssh-client sshpass iputils-ping netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && systemctl mask getty@tty1.service console-getty.service systemd-firstboot.service

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
