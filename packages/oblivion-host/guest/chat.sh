#!/bin/sh
set -eu
test "$(id -u)" = 1000
. /usr/lib/oblivion/guest/session-environment.sh
# Build channels must never select a different conversation history. Migration
# runs inside the session VM, before the provider capability is loaded.
if ! OPENCODE_DB=$(/usr/bin/python3 /usr/lib/oblivion/guest/chat-database.py 2>/dev/null); then
    printf '\033]777;oblivion;storage-failed\007'
    exit 1
fi
export OPENCODE_DB
. /usr/lib/oblivion/guest/chat-environment.sh
if [ "${1:-}" = serve ]; then
    exec /usr/bin/oblivion "$@"
fi
exec /usr/bin/oblivion "$@" --standalone
