#!/bin/sh
set -eu
umask 077
# A single session-local server owns execution and the encrypted chat database.
# Its authentication secret is unrelated to the provider key and stays in RAM.
OPENCODE_PASSWORD=$(cat /run/oblivion-chat/password)
export OPENCODE_PASSWORD
exec /usr/lib/oblivion/guest/chat.sh serve --hostname 127.0.0.1 --port 4096
