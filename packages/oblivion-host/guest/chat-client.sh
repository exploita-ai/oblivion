#!/bin/sh
set -eu
if [ ! -r /run/oblivion-chat/password ]; then
    printf 'This workspace is offline. Start chat from the Oblivion manager first.\n'
    exit 1
fi
. /usr/lib/oblivion/guest/session-environment.sh
. /usr/lib/oblivion/guest/chat-environment.sh
OPENCODE_PASSWORD=$(cat /run/oblivion-chat/password)
export OPENCODE_PASSWORD OBLIVION_WORKSPACE=1
# Conversations share the server; client-local navigation must not move another
# pane to the same conversation. State remains inside the encrypted vault.
pane=${TMUX_PANE:-default}
OPENCODE_TUI_CHANNEL="workspace-${pane#%}"
export OPENCODE_TUI_CHANNEL
if ! /usr/bin/python3 -B /usr/lib/oblivion/guest/chat-ready.py; then
    printf 'The session chat server did not become ready. Close and reopen the session.\n'
    printf 'client-failed\n' > /run/oblivion-terminal/events
    exit 1
fi
/usr/bin/oblivion --server http://127.0.0.1:4096 "$@" || {
    printf 'client-failed\n' > /run/oblivion-terminal/events
    exit 1
}
