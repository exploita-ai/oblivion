#!/bin/sh
set -eu
umask 077
[ "$(cat /sys/block/vdb/ro)" = 1 ]
case "$(blkid -o value -s TYPE /dev/vdb)" in
    ext4) mount -t ext4 -o ro,noload,nodev,nosuid,noexec /dev/vdb /source ;;
    vfat) mount -t vfat -o ro,nodev,nosuid,noexec,utf8=1,uid=0,gid=0,fmask=0177,dmask=0077 /dev/vdb /source ;;
    exfat) mount -t exfat -o ro,nodev,nosuid,noexec,iocharset=utf8,uid=0,gid=0,fmask=0177,dmask=0077 /dev/vdb /source ;;
    *) exit 1 ;;
esac
exec 3<>/dev/virtio-ports/oblivion.import
printf 'ready\n' >&3
case "$(dd bs=1 count=1 <&3 2>/dev/null)" in
    G) exec /usr/bin/oblivion-copy send /source 3600000 ;;
    B) exec /usr/bin/oblivion-copy send-encrypted /source 3600000 ;;
    M) exec /usr/bin/oblivion-copy media-source /source 3600000 ;;
    I) exec /usr/bin/oblivion-copy live-media-inspect /source 3600000 ;;
    *) exit 1 ;;
esac
