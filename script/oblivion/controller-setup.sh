#!/bin/sh
# Private Debian runtime. Only the native launcher's boot profile starts it.
set -eu
groupadd --gid 1000 oblivion-manager
useradd --uid 1000 --gid 1000 --no-create-home --home-dir /run/oblivion-manager --shell /usr/sbin/nologin oblivion-manager
for entry in '1100 oblivion-vm' '1101 oblivion-gateway-vm' '1102 oblivion-import-vm' '1103 oblivion-export-vm' '1105 oblivion-onion-gateway-vm' '1106 oblivion-onion-file-vm'; do
    set -- $entry
    groupadd --gid "$1" "$2"
    useradd --uid "$1" --gid "$1" --no-create-home --shell /usr/sbin/nologin "$2"
done
passwd -l root
chmod 0600 /etc/oblivion/controller.json
printf '{"version":1,"mode":"controller-runtime"}\n' > /etc/oblivion/installation.json
mkdir -p /persist /etc/modules-load.d /etc/NetworkManager/conf.d
printf 'tmpfs /persist tmpfs ro,nosuid,nodev,noexec,size=4k,mode=0700 0 0\n' >> /etc/fstab
cat > /etc/NetworkManager/conf.d/80-oblivion.conf <<'EOF'
[main]
plugins=keyfile
no-auto-default=driver:hv_netvsc
dns=none
rc-manager=unmanaged
[keyfile]
path=/run/NetworkManager/system-connections
[connectivity]
enabled=false
[connection]
connection.mdns=0
connection.llmnr=0
ipv6.method=disabled
EOF
for unit in NetworkManager oblivion-controller; do
    mkdir -p "/etc/systemd/system/$unit.service.d"
    printf '[Unit]\nRequires=oblivion-host-firewall.service\nAfter=oblivion-host-firewall.service\n' > "/etc/systemd/system/$unit.service.d/firewall.conf"
done
systemctl enable oblivion-controller.service oblivion-host-firewall.service NetworkManager.service
printf '[Unit]\nRequires=oblivion-runtime-network.service\nAfter=oblivion-runtime-network.service\n' > /etc/systemd/system/NetworkManager.service.d/runtime-network.conf
systemctl mask NetworkManager-wait-online.service e2scrub_reap.service e2scrub_all.timer dpkg-db-backup.timer dpkg-db-backup.service
printf 'loop\ndm_crypt\nkvm\nvsock\nvmw_vsock_virtio_transport\n' > /etc/modules-load.d/oblivion-runtime.conf
# Ephemeral Safe volumes reserve space in /run. Raise its tmpfs ceiling while
# leaving actual allocations subject to the controller's memory admission.
printf 'MODULES=most\nCOMPRESS=gzip\nRESUME=none\nRUNSIZE=40%%\n' > /etc/initramfs-tools/conf.d/oblivion
# Preserve VirtIO and explicitly include the same amd64 controller's Hyper-V
# storage/network/vsock modules. Built-in drivers need no archive entry.
python3 -B /tmp/hypervisor-kernel.py initramfs-modules / --role controller >> /etc/initramfs-tools/modules
update-initramfs -u -k all
ln -sf /usr/lib/systemd/system/multi-user.target /etc/systemd/system/default.target
printf 'Oblivion private controller runtime\n' > /etc/issue
