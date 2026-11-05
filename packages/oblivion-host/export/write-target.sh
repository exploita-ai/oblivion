#!/bin/sh
set -eu
umask 077
[ "$(cat /sys/block/vdb/ro)" = 0 ]
# A virtio port need not close on the host when its guest process exits.
# End this disposable VM on failure so the relay's pidfd revokes the copy.
trap 'umount /target 2>/dev/null || :; /usr/sbin/poweroff -f' EXIT
filesystem="$(blkid -o value -s TYPE /dev/vdb)"
case "$filesystem" in
    ext4) role=export; mode=posix; mount_flags=rw,nodev,nosuid,noexec ;;
    vfat) role=export-portable; mode=fat32; mount_flags=rw,nodev,nosuid,noexec,utf8=1,uid=0,gid=0,fmask=0177,dmask=0077 ;;
    exfat) role=export-portable; mode=exfat; mount_flags=rw,nodev,nosuid,noexec,iocharset=utf8,uid=0,gid=0,fmask=0177,dmask=0077 ;;
    *) exit 1 ;;
esac
case " $(cat /proc/cmdline) " in
    *" oblivion.live-export=1 "*)
        proof=/dev/virtio-ports/oblivion.export-proof
        tries=0
        while [ ! -c "$proof" ] && [ "$tries" -lt 100 ]; do
            tries=$((tries + 1))
            sleep 0.05
        done
        [ -c "$proof" ]
        exec 3<>/dev/virtio-ports/oblivion.export
        exec 4<>"$proof"
        printf 'ready\n' >&3
        # The controller has bound this port to the exact Live lease before
        # issuing M. A guest aborted before M has not mounted the medium.
        [ "$(dd bs=1 count=1 <&3 2>/dev/null)" = M ]
        mount -t "$filesystem" -o "$mount_flags" /dev/vdb /target
        result=0
        /usr/bin/oblivion-copy live-media-export /target 3600000 "$mode" || result=$?
        umount /target
        blockdev --flushbufs /dev/vdb
        printf 'detached\n' >&4
        trap - EXIT
        exit "$result"
        ;;
esac
mount -t "$filesystem" -o "$mount_flags" /dev/vdb /target
exec 3<>/dev/virtio-ports/oblivion.export
printf 'ready\n' >&3
case "$(dd bs=1 count=1 <&3 2>/dev/null)" in
    G) budget=3600000 ;;
    B) budget=3600000 ;;
    *) exit 1 ;;
esac
/usr/bin/oblivion-copy "$role" /target "$budget"
# The receipt alone is not an eject confirmation. Only a successful unmount
# and block-device flush authorize the relay to acknowledge the export.
umount /target
blockdev --flushbufs /dev/vdb
printf 'detached\n' >&3
trap - EXIT
