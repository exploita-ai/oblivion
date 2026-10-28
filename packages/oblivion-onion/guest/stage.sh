#!/bin/sh
set -eu
umask 077
exec 3<>/dev/virtio-ports/oblivion.onion.stage
printf 'ready\n' >&3
exec /usr/bin/oblivion-copy receive /run/oblivion-onion-stage 300000
