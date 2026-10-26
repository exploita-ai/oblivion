#!/bin/sh
set -eu
umask 077
[ "$(cat /sys/block/vdb/ro)" = 0 ]
# A virtio port need not close on the host when its guest process exits.
# End this disposable VM on failure so the relay's pidfd revokes the copy.
trap 'umount /target 2>/dev/null || :; /usr/sbin/poweroff -f' EXIT
role=export
case "$(blkid -o value -s TYPE /dev/vdb)" in
    ext4) mount -t ext4 -o rw,nodev,nosuid,noexec /dev/vdb /target ;;
    vfat)
        mount -t vfat -o rw,nodev,nosuid,noexec,utf8=1,uid=0,gid=0,fmask=0177,dmask=0077 /dev/vdb /target
        role=export-portable ;;
    exfat)
        mount -t exfat -o rw,nodev,nosuid,noexec,iocharset=utf8,uid=0,gid=0,fmask=0177,dmask=0077 /dev/vdb /target
        role=export-portable ;;
    *) exit 1 ;;
esac
exec 3<>/dev/virtio-ports/oblivion.export
printf 'ready\n' >&3
[ "$(dd bs=1 count=1 <&3 2>/dev/null)" = G ]
/usr/bin/oblivion-copy "$role" /target 300000
# The receipt alone is not an eject confirmation. Only a successful unmount
# and block-device flush authorize the relay to acknowledge the export.
umount /target
blockdev --flushbufs /dev/vdb
printf 'detached\n' >&3
trap - EXIT
