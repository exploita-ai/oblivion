#!/bin/sh
# initramfs local-bottom: /dev/vdb is this session's already-unlocked volume.
set -eu
case "${1:-}" in prereqs) exit 0 ;; esac
case " $(cat /proc/cmdline) " in *" oblivion.resize=1 "*) exit 0 ;; esac
. /scripts/functions
. /scripts/local

# Keep the Debian image immutable. Both overlay directories belong to the
# same encrypted session; no upper directory is ever placed on the host.
local_device_setup /dev/vdb "Oblivion session volume"
mkdir -p /run/oblivion-system/base /run/oblivion-system/volume
mount -t ext4 -o rw,nodev,nosuid,noatime /dev/vdb /run/oblivion-system/volume || panic "Cannot mount the session volume"
umask 077
mkdir -p /run/oblivion-system/volume/.oblivion-system/upper /run/oblivion-system/volume/.oblivion-system/work
chmod 0700 /run/oblivion-system /run/oblivion-system/volume/.oblivion-system
# Overlayfs takes the root directory permissions from upper, not lower.
# Keep / traversable by the session user; the backing tree remains root-only.
chmod 0755 /run/oblivion-system/volume/.oblivion-system/upper
mount -o move "${rootmnt}" /run/oblivion-system/base
mount -t overlay overlay -o rw,nodev,lowerdir=/run/oblivion-system/base,upperdir=/run/oblivion-system/volume/.oblivion-system/upper,workdir=/run/oblivion-system/volume/.oblivion-system/work "${rootmnt}" || panic "Cannot prepare the session system"
mount --bind /run/oblivion-system/volume "${rootmnt}/vault"
