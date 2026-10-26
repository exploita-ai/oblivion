#!/bin/sh
set -eu
mkdir -p /out /iso/live /iso/boot/grub /host/usr/lib/oblivion/vm/qemu-root
cp /host/boot/vmlinuz-* /iso/live/vmlinuz
cp /host/boot/initrd.img-* /iso/live/initrd.img
for role in session gateway import export; do
    mkdir -p "/host/usr/lib/oblivion/vm/$role"
    cp /"$role"/boot/vmlinuz-* "/host/usr/lib/oblivion/vm/$role/kernel"
    cp /"$role"/boot/initrd.img-* "/host/usr/lib/oblivion/vm/$role/initrd"
    chmod 0644 "/host/usr/lib/oblivion/vm/$role/kernel" "/host/usr/lib/oblivion/vm/$role/initrd"
    chroot "/$role" dpkg-query -W -f='${Package}\t${Version}\n' > "/out/$role-packages.tsv"
    mksquashfs "/$role" "/host/usr/lib/oblivion/vm/$role/root.squashfs" \
        -noappend -comp zstd -processors 2 -quiet -wildcards -e 'boot/*'
done
# Same restricted hypervisor root used by the controller in the VM laboratory.
for tree in usr/share/qemu usr/share/seabios usr/share/ipxe; do
    if [ -e "/host/$tree" ]; then
        mkdir -p "/host/usr/lib/oblivion/vm/qemu-root/$(dirname "$tree")"
        cp -a "/host/$tree" "/host/usr/lib/oblivion/vm/qemu-root/$tree"
    fi
done
for binary in /host/usr/bin/qemu-system-* /host/usr/lib/*/qemu/*.so; do
    [ -f "$binary" ] || continue
    relative=${binary#/host}
    (cd /host && cp -L --parents ".$relative" /host/usr/lib/oblivion/vm/qemu-root/)
    chroot /host /usr/bin/ldd "$relative" | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' | while read -r library; do
        (cd /host && cp -L --parents ".$library" /host/usr/lib/oblivion/vm/qemu-root/)
    done
done
for directory in dev proc sys run/oblivion-session run/oblivion-gateway-vm run/oblivion-import-vm run/oblivion-export-vm tmp; do
    mkdir -p "/host/usr/lib/oblivion/vm/qemu-root/$directory"
done
touch /host/usr/lib/oblivion/vm/qemu-root/kernel /host/usr/lib/oblivion/vm/qemu-root/initrd /host/usr/lib/oblivion/vm/qemu-root/root.squashfs
chroot /host dpkg-query -W -f='${Package}\t${Version}\n' > /out/host-packages.tsv
(cd /host && sha256sum usr/bin/oblivion-* usr/lib/oblivion/vm/*/root.squashfs) > /out/runtime.sha256
cp /session/usr/lib/oblivion/build-evidence.json /out/client-evidence.json
cp /sources/host-sources.sha256 /sources/gateway-sources.sha256 /out/
(cd /sources && find . -type f -print0 | sort -z | xargs -0 sha256sum) > /out/iso-sources.sha256
cp /sources/live-grub.cfg /iso/boot/grub/grub.cfg
name=oblivion-development
if [ -f /host/etc/oblivion/hardware/authorized_key.pub ]; then
    name=oblivion-hardware-test
    cp /sources/hardware/grub.cfg /iso/boot/grub/grub.cfg
    cp /host/etc/oblivion/hardware/client-fingerprint /out/client-fingerprint.txt
    test -z "$(find /host/etc/ssh -name 'ssh_host_*' -print)"
fi
mksquashfs /host /iso/live/filesystem.squashfs -noappend -comp zstd -processors 2 -quiet -wildcards -e 'boot/*'
# x86 supports BIOS + UEFI; ARM64 uses UEFI. No Secure Boot claim.
grub-mkrescue --locales='' --fonts=unicode --product-name=Oblivion \
    -o "/out/$name-$(chroot /host dpkg --print-architecture).iso" /iso
cd /out
sha256sum *.iso *.tsv *.json *sources.sha256 runtime.sha256 > SHA256SUMS
