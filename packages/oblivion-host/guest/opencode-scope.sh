#!/bin/sh
# This fixed root entrypoint moves only the official OpenCode tree. Agent argv
# is never a unit description, shell command or environment-expanded argument.
# v257 start_transient_scope moves this PID before exec; no extra PTY is made:
# https://github.com/systemd/systemd/blob/v257/src/run/run.c
set -eu
umask 077
test "$(/usr/bin/id -u)" = 0
test "${SUDO_UID:-}" = 1000
/usr/bin/mountpoint -q /vault
ulimit -c 0
scope=$(/usr/bin/tr -d '-' < /proc/sys/kernel/random/uuid)
test "${#scope}" = 32
case "$scope" in *[!0-9a-f]*) exit 64 ;; esac
# Always address this guest's system manager. Sudo's rendered command may hold
# native arguments; it is not part of the agent/provider environment.
unset DBUS_SYSTEM_BUS_ADDRESS DBUS_SESSION_BUS_ADDRESS SYSTEMD_BUS_ADDRESS
unset SYSTEMD_HOST SYSTEMD_MACHINE SUDO_COMMAND SUDO_USER SUDO_UID SUDO_GID
exec /usr/bin/systemd-run --system --scope --quiet --expand-environment=no \
    --unit="oblivion-opencode-$scope.scope" \
    --description='OpenCode in this Safe' \
    --property=BindsTo=oblivion-vault.service \
    --property=After=oblivion-vault.service \
    --property=RequiresMountsFor=/vault \
    --property=KillMode=control-group \
    --property=TimeoutStopSec=5 \
    --property=MemorySwapMax=0 \
    -- /usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups \
    -- /usr/lib/oblivion/guest/opencode-exec.sh "$@"
