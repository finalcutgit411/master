#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — protection against a full disk
#
#  When the disk fills up, downloads fail and SFTP uploads fail. Every
#  5 minutes, a systemd timer checks the free space of the data folder:
#    - under 3 GB, Transmission is stopped cleanly;
#    - above 5 GB again, it is started again (the gap avoids stopping and
#      starting in a loop).
#  It only starts Transmission again if it stopped it itself: a Transmission
#  stopped by hand is left alone. Transmission also checks the free space
#  before starting (boot included): on an almost full disk it does not start,
#  and the timer starts it once there is room again. Stopping the whole service is needed:
#  pausing the torrents one by one would require keeping the password of
#  Transmission in clear, which seedtunnel refuses to do.
# =============================================================================

DISKGUARD_STOP_BELOW_GB=3
DISKGUARD_START_ABOVE_GB=5
# present while Transmission is stopped by the guard (/run: emptied at boot)
DISKGUARD_MARKER="/run/seedtunnel-diskguard.stopped"
DISKGUARD_SERVICE="/etc/systemd/system/seedtunnel-diskguard.service"
DISKGUARD_TIMER="/etc/systemd/system/seedtunnel-diskguard.timer"

diskguard_stopped() { [[ -e $DISKGUARD_MARKER ]]; }

diskguard_generate_service() {
    cat <<EOF
# Written by seedtunnel — stops Transmission when the disk is almost full
[Unit]
Description=seedtunnel: Transmission stopped when the disk is almost full

[Service]
Type=oneshot
ExecStart=$APP_DIR/seedtunnel.sh diskguard-check
EOF
}

diskguard_generate_timer() {
    cat <<'EOF'
# Written by seedtunnel
[Unit]
Description=seedtunnel: free space check every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
}

# Called by seedbox_apply
diskguard_install() {
    local changed=0
    if write_if_changed "$DISKGUARD_SERVICE" 644 root:root diskguard_generate_service; then changed=1; fi
    if write_if_changed "$DISKGUARD_TIMER" 644 root:root diskguard_generate_timer; then changed=1; fi
    if ((changed)); then run 'Reloading systemd' systemctl daemon-reload; fi
    if ! systemctl is-active --quiet seedtunnel-diskguard.timer; then
        run 'Enabling the full disk protection' systemctl enable --now seedtunnel-diskguard.timer
    fi
}

diskguard_remove() {
    systemctl disable --now seedtunnel-diskguard.timer >>"$APP_LOG" 2>&1 || true
    rm -f "$DISKGUARD_SERVICE" "$DISKGUARD_TIMER" "$DISKGUARD_MARKER"
    systemctl daemon-reload 2>/dev/null || true
}

# Run by systemd before Transmission starts (ExecStartPre of its drop-in, boot
# included): refuses to start it on an almost full disk. The timer starts it
# again once there is room (the marker says the guard stopped it).
diskguard_prestart() {
    local free stop_below=${SEEDTUNNEL_DISKGUARD_STOP_BELOW_GB:-$DISKGUARD_STOP_BELOW_GB}
    seedbox_installed || return 0
    free=$(disk_free_gb "$SEEDBOX_DATA_DIR")
    [[ $free =~ ^[0-9]+$ ]] || return 0
    if ((free < stop_below)); then
        date +%s >"$DISKGUARD_MARKER"
        logger -t seedtunnel "Transmission not started: disk almost full ($free GB free)" 2>/dev/null || true
        say 'Transmission not started: disk almost full (%s GB free).' "$free"
        return 1
    fi
    rm -f "$DISKGUARD_MARKER"
}

# Run by the timer (« seedtunnel diskguard-check »). The thresholds can be
# changed for the tests: SEEDTUNNEL_DISKGUARD_STOP_BELOW_GB, …_START_ABOVE_GB.
diskguard_check() {
    local free stop_below=${SEEDTUNNEL_DISKGUARD_STOP_BELOW_GB:-$DISKGUARD_STOP_BELOW_GB}
    local start_above=${SEEDTUNNEL_DISKGUARD_START_ABOVE_GB:-$DISKGUARD_START_ABOVE_GB}
    seedbox_installed || return 0
    free=$(disk_free_gb "$SEEDBOX_DATA_DIR")
    [[ $free =~ ^[0-9]+$ ]] || return 0
    if diskguard_stopped; then
        if ((free >= start_above)); then
            systemctl start transmission-daemon
            rm -f "$DISKGUARD_MARKER"
            logger -t seedtunnel "Transmission started again: $free GB free"
            say 'Transmission started again: %s GB free.' "$free"
        fi
    elif ((free < stop_below)) && systemctl is-active --quiet transmission-daemon; then
        systemctl stop transmission-daemon
        date +%s >"$DISKGUARD_MARKER"
        logger -t seedtunnel "Transmission stopped: disk almost full ($free GB free)"
        say 'Transmission stopped: disk almost full (%s GB free).' "$free"
    fi
}
