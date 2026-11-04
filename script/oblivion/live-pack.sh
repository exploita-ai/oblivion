#!/bin/sh
# Pack the outer launcher OS; the embedded controller ISO is built separately.
set -eu
mkdir -p /out /iso/live /iso/boot/grub
python3 -B /sources/hypervisor-kernel.py verify /host --controller /host/usr/lib/oblivion/desktop/evidence/runtime/hypervisor-kernel.json > /out/hypervisor-kernel.json
cp /host/boot/vmlinuz-* /iso/live/vmlinuz
cp /host/boot/initrd.img-* /iso/live/initrd.img
python3 -B /sources/hypervisor-kernel.py grub /host /sources/live-grub.cfg > /iso/boot/grub/grub.cfg
chroot /host dpkg-query -W -f='${Package}\t${Version}\n' > /out/live-packages.tsv
cp /host/usr/lib/oblivion/desktop/bundle.json /out/controller-bundle.json
(cd /sources && find . -type f -print0 | sort -z | xargs -0 sha256sum) > /out/live-sources.sha256
name=${OBLIVION_IMAGE_NAME:-oblivion-development}
mksquashfs /host /iso/live/filesystem.squashfs -noappend -comp zstd -processors 2 -quiet -wildcards -e 'boot/*'
grub-mkrescue --locales='' --fonts=unicode --product-name=Oblivion -o "/out/$name-$(chroot /host dpkg --print-architecture).iso" /iso
cd /out
sha256sum *.iso *.tsv *.json live-sources.sha256 > SHA256SUMS
