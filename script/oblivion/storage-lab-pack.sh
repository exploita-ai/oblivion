#!/bin/sh
set -eu

# Build an initramfs laboratory, not a release live image. The build container
# needs no privileges, device mappings, host mounts or access to user credentials.
mkdir -p /out /rootfs/bin /rootfs/usr/bin /rootfs/usr/sbin /rootfs/etc /rootfs/proc /rootfs/sys /rootfs/dev /rootfs/run /rootfs/tmp /rootfs/lib
cp /usr/bin/busybox /rootfs/bin/busybox
ln -s usr/sbin /rootfs/sbin
ln -s /bin/busybox /rootfs/usr/sbin/modprobe
for name in sh mkdir chmod cat printf sleep grep cut head tail wc tr dd sync mount umount poweroff mknod modprobe readlink sha256sum blkid kill blockdev setpriv rm; do
    ln -s busybox "/rootfs/bin/$name"
done
for binary in /usr/sbin/cryptsetup /usr/sbin/mkfs.ext4 /usr/bin/mount /usr/bin/umount /usr/bin/setpriv /build/target/release/oblivion-storage /build/target/release/oblivion-control /build/target/release/examples/ipc-probe; do
    if [ "${binary#/build/}" != "$binary" ]; then
        cp "$binary" "/rootfs/usr/bin/$(basename "$binary")"
    else
        cp -L --parents "$binary" /rootfs
    fi
    ldd "$binary" | awk '/=> \// {print $3} /^\s*\// {print $1}' | while read -r lib; do
        cp -L --parents "$lib" /rootfs
    done
done
# ldd's loader line has implementation-dependent indentation.
cp -L --parents /lib/ld-linux-aarch64.so.1 /rootfs
cp -a /usr/lib/modules /rootfs/lib/
cp /lab/init /rootfs/init
cp /lab/storage-test /rootfs/storage-test
chmod 0755 /rootfs/init /rootfs/storage-test
cp /boot/vmlinuz-* /out/kernel
dpkg-query -W -f='${Package}\t${Version}\n' > /out/packages.tsv
cd /build
sha256sum Cargo.toml Cargo.lock src/*.rs examples/*.rs /lab/init /lab/storage-test /lab/pack > /out/sources.sha256
cd /rootfs
find . -print0 | cpio --null -o --format=newc --quiet | gzip -1 > /out/initramfs.gz
cd /out
sha256sum kernel initramfs.gz packages.tsv sources.sha256 > SHA256SUMS
