#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
root=$(pwd)
out="$root/artifacts/oblivion-hardware-iso"
image=${OBLIVION_HARDWARE_OUTPUT:-"$out/image"}
key=${OBLIVION_TEST_KEY:-"$HOME/.ssh/oblivion-hardware-test"}
mkdir -p "$out"
# The public key is the only credential copied into the build context. This
# dedicated private key stays on the operator's Mac, outside the repository.
if [ ! -f "$key" ]; then
    mkdir -p "$(dirname "$key")"
    (umask 077; ssh-keygen -q -t ed25519 -N '' -C oblivion-hardware-test -f "$key")
fi
ssh-keygen -y -f "$key" > "$out/authorized_key.pub"
# The console handshake lives in the session guest as well as the host. Build
# both from the same sources; reusing the old ISO would preserve the black screen.
OBLIVION_IMAGE_TARGET=diagnostic-iso OBLIVION_ISO_OUTPUT="$image" sh script/oblivion/build-live.sh
printf 'ISO: %s/oblivion-hardware-test-%s.iso\n' "$image" "${OBLIVION_ARCH:-amd64}"
printf 'Private SSH key (not in ISO): %s\n' "$key"
