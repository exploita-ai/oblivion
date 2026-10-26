#!/bin/sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp
mkdir -p /dev/mapper /data /session
modprobe virtio_pci
modprobe virtio_blk
modprobe loop
modprobe dm_mod
modprobe dm_crypt
modprobe ext4
modprobe xts
modprobe aes_generic
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    [ -b /dev/vda ] && break
    sleep 1
done
# vda is an empty image created exclusively by run-storage-lab.py. Never run
# this init as a host script or attach any physical device to this laboratory.
if /usr/sbin/mkfs.ext4 -q -m 0 /dev/vda && /usr/bin/mount /dev/vda /data; then
    /storage-test
    result=$?
else
    result=1
fi
sync
if [ "$result" = 0 ]; then
    printf '\nOBLIVION_STORAGE_LAB_PASS\n'
else
    printf '\nOBLIVION_STORAGE_LAB_FAIL\n'
fi
poweroff -f
