#!/bin/sh
set -eu
test "$(id -u)" = 1000
mountpoint -q /vault
. /usr/lib/oblivion/guest/session-environment.sh
if [ -r /run/oblivion-api/token ]; then
    . /usr/lib/oblivion/guest/tools-proxy.sh
fi
exec /usr/bin/python3 -B /usr/lib/oblivion/guest/console.py --terminal
