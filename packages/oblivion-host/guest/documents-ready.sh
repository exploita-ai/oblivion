#!/bin/sh
set -eu
port=/dev/virtio-ports/oblivion.documents
while [ ! -c "$port" ]; do sleep 0.1; done
printf 'ready\n' > "$port"
