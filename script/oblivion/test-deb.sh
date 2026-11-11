#!/bin/sh
# Disposable packaging qualification. Does not build real role images or an ISO.
set -eu
cd "$(dirname "$0")/../.."
image=oblivion-debian-packaging-test
docker build --file script/oblivion/debian-test.Dockerfile --tag "$image" .
docker run --rm --network=none \
    --mount "type=bind,src=$(pwd),dst=/sources,readonly" \
    --mount "type=bind,src=$(pwd)/script/oblivion/debian/fixture-active-swaps.txt,dst=/proc/swaps,readonly" \
    "$image" /bin/sh -c 'if sh /sources/script/oblivion/debian/preinst install; then exit 1; fi'
docker run --rm --network=none --tmpfs /run:rw,nosuid,nodev,mode=755 \
    --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
    --mount "type=bind,src=$(pwd)/script/oblivion/debian/fixture-no-swaps.txt,dst=/proc/swaps,readonly" \
    --mount "type=bind,src=$(pwd),dst=/sources,readonly" "$image"
