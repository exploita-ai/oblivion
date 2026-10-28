#!/bin/sh
set -eu
umask 077
exec 3<>/dev/virtio-ports/oblivion.onion.source
printf 'ready\n' >&3
exec /usr/bin/oblivion-copy send /source 300000
