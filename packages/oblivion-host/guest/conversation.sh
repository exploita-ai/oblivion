#!/bin/sh
set -eu
# Attach the trusted viewer before migration or client startup can fail.
exec /usr/bin/python3 /usr/lib/oblivion/guest/console.py /bin/sh /usr/lib/oblivion/guest/chat.sh "$@"
