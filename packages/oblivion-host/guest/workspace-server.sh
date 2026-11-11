#!/bin/sh
set -eu
umask 077
. /usr/lib/oblivion/guest/safe-environment.sh
cd /vault/workspace
# The foreground server belongs to the Safe service, not an attachment's cgroup.
exec /usr/bin/tmux -D -S /run/oblivion-workspace/tmux.sock -f /etc/oblivion/tmux.conf
