#!/bin/sh
set -eu
mkdir -p /out /iso/live /iso/boot/grub
# Keep the previously verified production guests byte-identical. Only the
# physical host is rebuilt with the current controller, persistence setup and diagnostics.
xorriso -osirrox on -indev /base.iso -extract /live/filesystem.squashfs /tmp/base.squashfs
unsquashfs -processors 2 -d /base /tmp/base.squashfs usr/lib/oblivion/vm
mv /base/usr/lib/oblivion/vm /host/usr/lib/oblivion/
rm /tmp/base.squashfs
cp /host/boot/vmlinuz-* /iso/live/vmlinuz
cp /host/boot/initrd.img-* /iso/live/initrd.img
cp /sources/hardware/grub.cfg /iso/boot/grub/grub.cfg
chroot /host dpkg-query -W -f='${Package}\t${Version}\n' > /out/host-packages.tsv
(cd /host && sha256sum usr/bin/oblivion-* etc/oblivion/controller.json usr/lib/oblivion/vm/*/root.squashfs) > /out/runtime.sha256
(cd /iso && sha256sum live/vmlinuz live/initrd.img boot/grub/grub.cfg) > /out/boot.sha256
cp /host/etc/oblivion/hardware/client-fingerprint /out/client-fingerprint.txt
cp /sources/host-sources.sha256 /out/
(cd /sources && find . -type f -print0 | sort -z | xargs -0 sha256sum) > /out/iso-sources.sha256
printf '%s  oblivion-development-amd64.iso\n' "$BASE_ISO_SHA256" > /out/base-iso.sha256
test -z "$(find /host/etc/ssh -name 'ssh_host_*' -print)"
mksquashfs /host /iso/live/filesystem.squashfs -noappend -comp zstd -processors 2 -quiet -wildcards -e 'boot/*'
grub-mkrescue --locales='' --fonts=unicode --product-name=Oblivion \
    -o /out/oblivion-hardware-test-amd64.iso /iso
cd /out
sha256sum *.iso *.tsv *.txt *.sha256 > SHA256SUMS
