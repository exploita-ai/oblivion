#!/bin/sh
set -eu
mkdir -p /out /host/usr/lib/oblivion/vm/qemu-root/usr/bin
cp /host/boot/vmlinuz-* /out/kernel
cp /host/boot/initrd.img-* /out/initrd
chroot /host /usr/bin/dpkg-query -W -f='${Package}\t${Version}\n' > /out/host-packages.tsv
chroot /guest /usr/bin/dpkg-query -W -f='${Package}\t${Version}\n' > /out/guest-packages.tsv
cp /out/kernel /host/usr/lib/oblivion/vm/kernel
cp /out/initrd /host/usr/lib/oblivion/vm/initrd
if [ -f /host/usr/lib/oblivion/vm/manager-lab ]; then
    (cd /host && sha256sum usr/bin/oblivion-manager) > /out/manager.sha256
fi
if [ -f /host/usr/lib/oblivion/vm/tui-lab ]; then touch /out/tui-lab; fi
chmod 0644 /host/usr/lib/oblivion/vm/kernel /host/usr/lib/oblivion/vm/initrd
if [ -f /guest/usr/bin/oblivion ]; then
    touch /host/usr/lib/oblivion/vm/chat-lab
    cp /guest/usr/lib/oblivion/build-evidence.json /out/opencode-build.json
    (cd /guest && sha256sum usr/bin/oblivion) > /out/opencode.sha256
fi
# The hypervisor's root contains public executables/libraries, no configuration,
# profile, host devices or session filesystems. systemd binds just the active disk.
for tree in usr/share/qemu usr/share/qemu-efi-aarch64 usr/share/seabios usr/share/ipxe; do
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
for directory in dev proc sys run/oblivion-session run/oblivion-gateway-vm run/oblivion-import-vm run/oblivion-export-vm tmp; do mkdir -p "/host/usr/lib/oblivion/vm/qemu-root/$directory"; done
# Mount targets must exist before packing the immutable hypervisor root.
touch /host/usr/lib/oblivion/vm/qemu-root/kernel /host/usr/lib/oblivion/vm/qemu-root/initrd /host/usr/lib/oblivion/vm/qemu-root/root.squashfs
rm -rf /guest/boot /guest/var/cache/apt /guest/var/lib/apt/lists /host/var/cache/apt /host/var/lib/apt/lists
mkdir -p /guest/boot
mksquashfs /guest /host/usr/lib/oblivion/vm/guest.squashfs -noappend -comp zstd -processors 2 -quiet
mksquashfs /import /host/usr/lib/oblivion/vm/import.squashfs -noappend -comp zstd -processors 2 -quiet -wildcards -e 'boot/*'
mksquashfs /export /host/usr/lib/oblivion/vm/export.squashfs -noappend -comp zstd -processors 2 -quiet -wildcards -e 'boot/*'
if [ -f /host/usr/lib/oblivion/vm/import-lab ]; then
    touch /out/import-lab
    mkdir -p /fixture/documenti/vuota
    printf OBLIVION_USB_SELECTED_CANARY_82f1 > /fixture/documenti/note.txt
    printf OBLIVION_USB_SELECTED_CANARY_82f1 > /fixture/documenti/caffè.txt
    printf OBLIVION_USB_UNSELECTED_CANARY_29a1 > /fixture/unselected.txt
    truncate -s 32M /out/import-source.raw
    mkfs.ext4 -q -m 0 -d /fixture /out/import-source.raw
fi
if [ -f /host/usr/lib/oblivion/vm/export-lab ]; then
    touch /out/export-lab
    mkdir /export-fixture
    printf OBLIVION_EXPORT_EXISTING_CANARY_f4a8 > /export-fixture/existing.txt
    truncate -s 64M /out/export-target.raw
    mkfs.ext4 -q -m 0 -d /export-fixture /out/export-target.raw
fi
mksquashfs /host /out/host.squashfs -noappend -comp zstd -processors 2 -quiet
cd /sources
find packages script -type f -print0 | sort -z | xargs -0 sha256sum > /out/sources.sha256
cd /out
sha256sum kernel initrd host.squashfs host-packages.tsv guest-packages.tsv sources.sha256 > SHA256SUMS
if [ -f opencode.sha256 ]; then sha256sum opencode.sha256 opencode-build.json >> SHA256SUMS; fi
if [ -f manager.sha256 ]; then sha256sum manager.sha256 >> SHA256SUMS; fi
if [ -f tui-lab ]; then sha256sum tui-lab >> SHA256SUMS; fi

if [ -f import-lab ]; then sha256sum import-lab import-source.raw >> SHA256SUMS; fi
if [ -f export-lab ]; then sha256sum export-lab export-target.raw >> SHA256SUMS; fi
