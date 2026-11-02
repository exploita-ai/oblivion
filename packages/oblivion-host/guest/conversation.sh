#!/bin/sh
set -eu
. /usr/lib/oblivion/guest/session-environment.sh
. /usr/lib/oblivion/guest/chat-environment.sh
exec /usr/bin/python3 -B /usr/lib/oblivion/guest/console.py --workspace
