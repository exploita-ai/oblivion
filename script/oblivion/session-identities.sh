#!/bin/sh
# Fixed, disjoint hypervisor identities. Keep in sync with scope::Slot::uid.
set -eu
for slot in $(seq 1 31); do
    for entry in '0 session' '1 gateway-vm' '2 import-vm' '3 export-vm' '5 onion-gateway-vm' '6 onion-file-vm'; do
        set -- $entry
        identity=$((16000 + slot * 16 + $1))
        name="oblivion-$2-s$slot"
        groupadd --gid "$identity" "$name"
        useradd --uid "$identity" --gid "$identity" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$name"
    done
done
