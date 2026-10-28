#!/bin/sh
set -eu
# Cage supplies this private Wayland environment to its child. The terminal
# handoff exposes only a PTY to the manager, never the compositor connection.
if [ -x /usr/bin/oblivion-clipboard ] && \
    /usr/bin/grep -Fqx 'com.redhat.spice.0' /sys/class/virtio-ports/*/name 2>/dev/null; then
    (
        while :; do
            if [ -S /run/oblivion-clipboard-broker/socket ]; then
                /usr/bin/oblivion-clipboard >/dev/null 2>&1 || true
            fi
            sleep 2
        done
    ) &
fi
if [ -c /dev/vboxuser ] && [ -x /usr/bin/VBoxClient ]; then
    HOME=/run/oblivion-display VBOX_RELEASE_LOG_DEST=file=/dev/null \
        XDG_SESSION_TYPE=wayland /usr/bin/VBoxClient -d --clipboard --session-type wayland --logfile /dev/null >/dev/null 2>&1 &
fi
exec /usr/bin/foot --log-level=none --config=/etc/oblivion/foot.ini -- /usr/bin/oblivion-display --client
