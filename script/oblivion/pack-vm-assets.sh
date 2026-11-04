#!/bin/sh
# Shared immutable assets for Live and the installed Debian stack. No ISO here.
set -eu
[ "$#" -eq 3 ] || { echo 'Usage: pack-vm-assets.sh HOST_ROOT ROLE_ROOT OUTPUT' >&2; exit 2; }
host=$1
roles=$2
output=$3
assets="$host/usr/lib/oblivion/vm"
mkdir -p "$output" "$assets/qemu-root"
packages="$output/qemu-package-names.txt"
: > "$packages"
for role in session gateway import export onion-gateway onion-file; do
    source="$roles/$role"
    mkdir -p "$assets/$role"
    cp "$source"/boot/vmlinuz-* "$assets/$role/kernel"
    cp "$source"/boot/initrd.img-* "$assets/$role/initrd"
    chmod 0644 "$assets/$role/kernel" "$assets/$role/initrd"
    chroot "$source" dpkg-query -W -f='${Package}\t${Version}\t${source:Package}\t${source:Version}\n' > "$output/$role-packages.tsv"
    mksquashfs "$source" "$assets/$role/root.squashfs" \
        -noappend -comp zstd -processors 2 -quiet -wildcards -e 'boot/*'
done
for tree in usr/share/qemu usr/share/seabios usr/share/ipxe; do
    if [ -e "$host/$tree" ]; then
        mkdir -p "$assets/qemu-root/$(dirname "$tree")"
        cp -a "$host/$tree" "$assets/qemu-root/$tree"
        chroot "$host" dpkg-query -S "/$tree" "/$tree/*" | sed 's/: .*//' >> "$packages"
    fi
done
for binary in "$host"/usr/bin/qemu-system-* "$host"/usr/lib/*/qemu/*.so; do
    [ -f "$binary" ] || continue
    relative=${binary#"$host"}
    canonical=$(chroot "$host" /usr/bin/readlink -f "$relative")
    install -D -m "$(stat -c '%a' "$host$canonical")" "$host$canonical" "$assets/qemu-root$relative"
    chroot "$host" dpkg-query -S "$relative" | sed 's/: .*//' >> "$packages"
    chroot "$host" /usr/bin/ldd "$relative" | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' | while read -r library; do
        canonical=$(chroot "$host" /usr/bin/readlink -f "$library")
        install -D -m "$(stat -c '%a' "$host$canonical")" "$host$canonical" "$assets/qemu-root$library"
        chroot "$host" dpkg-query -S "$canonical" | sed 's/: .*//' >> "$packages"
    done
done
sort -u "$packages" -o "$packages"
mkdir -p "$assets/qemu-root/usr/share/doc"
while read -r package; do
    name=${package%%:*}
    if [ -d "$host/usr/share/doc/$name" ]; then
        cp -aL "$host/usr/share/doc/$name" "$assets/qemu-root/usr/share/doc/"
    fi
done < "$packages"
# Arguments are Debian-owned package names obtained above, never shell code.
xargs chroot "$host" dpkg-query -W -f='${Package}\t${Version}\t${source:Package}\t${source:Version}\n' < "$packages" > "$output/qemu-packages.tsv"
for directory in dev proc sys tmp run/oblivion-session run/oblivion-gateway-vm run/oblivion-import-vm run/oblivion-export-vm run/oblivion-onion-uplink run/oblivion-onion-gateway-vm run/oblivion-onion-file-vm; do
    mkdir -p "$assets/qemu-root/$directory"
done
for slot in $(seq 1 31); do
    for role in session gateway-vm import-vm export-vm onion-uplink onion-gateway-vm onion-file-vm; do
        mkdir -p "$assets/qemu-root/run/oblivion-$role-s$slot"
    done
done
touch "$assets/qemu-root/kernel" "$assets/qemu-root/initrd" "$assets/qemu-root/root.squashfs"
