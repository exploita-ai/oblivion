#!/bin/sh
set -eu
umask 077
. /usr/lib/oblivion/guest/safe-environment.sh
test -t 0 && test -t 1
# No user-supplied unit, executable or shell command crosses the wire.
/usr/bin/sudo -n /usr/bin/systemctl start oblivion-workspace.service
attempts=50
while ! /usr/bin/tmux -N -S /run/oblivion-workspace/tmux.sock display-message -p '#{pid}' >/dev/null 2>&1; do
    attempts=$((attempts - 1))
    test "$attempts" -gt 0 || { printf 'Workspace is not ready.\n' >&2; exit 125; }
    sleep 0.1
done
# -N prevents an attachment racing service startup from creating its own server.
exec /usr/bin/tmux -N -S /run/oblivion-workspace/tmux.sock \
    new-session -A -s workspace -c /vault/workspace /bin/bash -l
