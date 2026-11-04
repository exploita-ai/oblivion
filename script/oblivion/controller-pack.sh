#!/bin/sh
set -eu
mkdir -p /out /iso/live /iso/boot/grub /host/usr/lib/oblivion/vm/qemu-root
python3 -B /sources/hypervisor-kernel.py verify /host > /out/hypervisor-kernel.json
cp /host/boot/vmlinuz-* /iso/live/vmlinuz
cp /host/boot/initrd.img-* /iso/live/initrd.img
sh /sources/pack-vm-assets.sh /host / /out
chroot /host dpkg-query -W -f='${Package}\t${Version}\n' > /out/host-packages.tsv
(cd /host && sha256sum usr/bin/oblivion-* usr/lib/oblivion/vm/*/root.squashfs) > /out/runtime.sha256
cp /session/usr/lib/oblivion/build-evidence.json /out/client-evidence.json
cp /sources/host-sources.sha256 /sources/gateway-sources.sha256 /out/
(cd /sources && find . -type f -print0 | sort -z | xargs -0 sha256sum) > /out/iso-sources.sha256
python3 -B /sources/hypervisor-kernel.py grub /host /sources/live-grub.cfg > /iso/boot/grub/grub.cfg
name=${OBLIVION_IMAGE_NAME:-oblivion-development}
mksquashfs /host /iso/live/filesystem.squashfs -noappend -comp zstd -processors 2 -quiet -wildcards -e 'boot/*'
# x86 supports BIOS + UEFI; ARM64 uses UEFI. No Secure Boot claim.
grub-mkrescue --locales='' --fonts=unicode --product-name=Oblivion \
    -o "/out/$name-$(chroot /host dpkg --print-architecture).iso" /iso
cd /out
sha256sum *.iso *.tsv *.json *sources.sha256 runtime.sha256 > SHA256SUMS
