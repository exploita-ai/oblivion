#!/bin/sh
set -eu
groupadd --gid 1000 oblivion-manager
useradd --uid 1000 --gid 1000 --no-create-home --home-dir /run/oblivion-manager --shell /usr/sbin/nologin oblivion-manager
for entry in '1100 oblivion-vm' '1101 oblivion-gateway-vm' '1102 oblivion-import-vm' '1103 oblivion-export-vm'; do
    set -- $entry
    groupadd --gid "$1" "$2"
    useradd --uid "$1" --gid "$1" --no-create-home --shell /usr/sbin/nologin "$2"
done
passwd -l root
chmod 0600 /etc/oblivion/controller.json
mkdir -p /persist /etc/systemd/system/oblivion-manager.service.d /etc/modules-load.d
mkdir -p /etc/network
# Keep the base network configuration explicit even without ifupdown.
printf 'auto lo\niface lo inet loopback\n' > /etc/network/interfaces
# The live controller discovers the data partition on its own boot USB.
# Keep the legacy file destination readonly: never fall back to a RAM archive.
printf 'tmpfs /persist tmpfs ro,nosuid,nodev,noexec,size=4k,mode=0700 0 0\n' >> /etc/fstab
cat > /etc/systemd/system/oblivion-manager.service.d/live.conf <<'EOF'
[Service]
# PrivateDevices keeps physical devices hidden; expose only this console.
BindPaths=/dev/tty1
DeviceAllow=/dev/tty1 rw
EOF
mkdir -p /etc/NetworkManager/conf.d /usr/lib/oblivion
cat > /etc/NetworkManager/conf.d/80-oblivion.conf <<'EOF'
[main]
plugins=keyfile
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
cat > /usr/lib/oblivion/network-menu.sh <<'EOF'
#!/bin/sh
while :; do
    clear
    printf '\033[35mOBLIVION - NETWORK\033[0m\n\n'
    printf 'Alt+F1: return to the manager.\n'
    printf 'After connecting, choose Network > Save network profiles in the manager.\n'
    printf 'Unsaved network settings remain in RAM until shutdown.\n\n'
    printf '[Enter] Configure Wi-Fi / Ethernet\n'
    read -r answer || exit
    nmtui
done
EOF
chmod 0755 /usr/lib/oblivion/network-menu.sh
cat > /etc/systemd/system/oblivion-network-console.service <<'EOF'
[Unit]
Description=Oblivion local network configuration
After=NetworkManager.service
Wants=NetworkManager.service
Conflicts=getty@tty2.service
[Service]
ExecStart=/usr/lib/oblivion/network-menu.sh
Restart=always
RestartSec=2
StandardInput=tty-force
StandardOutput=tty
StandardError=null
TTYPath=/dev/tty2
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes
UMask=0077
LimitCORE=0
[Install]
WantedBy=multi-user.target
EOF
# The host must load its deny policy before configuring any connection or
# accepting manager requests. A failed firewall prevents either dependency.
for unit in NetworkManager oblivion-controller; do
    mkdir -p "/etc/systemd/system/$unit.service.d"
    printf '[Unit]\nRequires=oblivion-host-firewall.service\nAfter=oblivion-host-firewall.service\n' > "/etc/systemd/system/$unit.service.d/firewall.conf"
done
systemctl enable oblivion-host-firewall.service NetworkManager.service oblivion-network-console.service
systemctl mask NetworkManager-wait-online.service e2scrub_reap.service e2scrub_all.timer \
    dpkg-db-backup.timer dpkg-db-backup.service
printf 'loop\ndm_crypt\nkvm\n' > /etc/modules-load.d/oblivion-live.conf
# The guest's minimal initrd is not enough for booting physical USB or SATA.
printf 'MODULES=most\nCOMPRESS=gzip\nRESUME=none\n' > /etc/initramfs-tools/conf.d/oblivion
printf 'squashfs\noverlay\next4\niso9660\nloop\nvirtio_gpu\nvirtio_console\nxhci_pci\nusb_storage\nusbhid\n' > /etc/initramfs-tools/modules
update-initramfs -u -k all
# No live-config autologin, SSH, network setup, disk persistence or swap probing.
systemctl enable oblivion-controller.service
ln -sf /usr/lib/systemd/system/multi-user.target /etc/systemd/system/default.target
printf 'Oblivion development boot image\n' > /etc/issue
rm -f /var/log/*log /var/log/wtmp /var/log/btmp /var/log/lastlog
