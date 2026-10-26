#!/bin/sh
set -eu
umask 077
exec 3<>"$1"
printf 'ready\n' >&3
[ "$(dd bs=1 count=1 <&3 2>/dev/null)" = G ]
exec /usr/bin/oblivion-copy documents /vault 300000
