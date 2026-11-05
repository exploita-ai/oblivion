#!/bin/sh
# Outer Debian Live contains only the launcher, terminal and virtualizer.
set -eu
groupadd --gid 1000 oblivion-manager
useradd --uid 1000 --gid 1000 --no-create-home --home-dir /run/oblivion-live/user --shell /bin/sh oblivion-manager
passwd -l root
mkdir -p /etc/oblivion /etc/tmpfiles.d /etc/sudoers.d /etc/modules-load.d /etc/systemd/system/oblivion-display.service.d
# live-boot already provides a RAM-backed root overlay. Preserve the installed
# dpkg/debconf database in /var so Debian's own configuration dialogs work.
printf 'tmpfs /tmp tmpfs nosuid,nodev,mode=1777,size=64M 0 0\n' > /etc/fstab
chmod 0755 /usr/lib/oblivion/live-os/console.sh
cp /usr/lib/oblivion/live-os/*.service /usr/lib/oblivion/live-os/*.path /etc/systemd/system/
install -m 0644 /usr/lib/oblivion/live-os/display.conf /etc/systemd/system/oblivion-display.service.d/debian-keyboard.conf
printf '{"version":1,"mode":"live-launcher"}\n' > /etc/oblivion/installation.json
printf 'd /run/oblivion-live 0755 root root -\nd /run/oblivion-live/user 0700 1000 1000 -\nf /run/oblivion-keymap-applied 0644 1104 1104 -\n' > /etc/tmpfiles.d/oblivion-live.conf
# No arbitrary device or pathname is accepted by this root-owned helper.
printf 'oblivion-manager ALL=(root) NOPASSWD: /usr/lib/oblivion/live-storage.py review, /usr/lib/oblivion/live-storage.py prepare *\n' > /etc/sudoers.d/oblivion-live-storage
chmod 0440 /etc/sudoers.d/oblivion-live-storage
visudo -c -f /etc/sudoers.d/oblivion-live-storage
cat > /etc/sudoers.d/oblivion-live-media <<'EOF'
Cmnd_Alias OBLIVION_USB = /usr/lib/oblivion/live-media.py ^lease (import|export) [0-9a-f]{64}$
Defaults!OBLIVION_USB !use_pty, !log_input, !log_output, !log_allowed
oblivion-manager ALL=(root) TIMEOUT=5s NOPASSWD: NOSETENV: OBLIVION_USB
EOF
chmod 0440 /etc/sudoers.d/oblivion-live-media
visudo -c -f /etc/sudoers.d/oblivion-live-media
usermod -a -G kvm oblivion-manager
cat > /etc/udev/rules.d/71-oblivion-runtime.rules <<'EOF'
KERNEL=="vhost-vsock", GROUP="kvm", MODE="0660"
EOF
cat > /etc/systemd/system/oblivion-manager.service <<'EOF'
[Unit]
Description=Oblivion Live launcher
After=systemd-tmpfiles-setup.service NetworkManager.service
Wants=NetworkManager.service
Conflicts=getty@tty1.service
[Service]
Type=exec
User=1000
Group=1000
SupplementaryGroups=kvm
ExecStart=/usr/lib/oblivion/desktop/bin/oblivion
Restart=on-failure
RestartSec=2
Environment=HOME=/run/oblivion-live/user XDG_RUNTIME_DIR=/run/oblivion-live/user
Environment=TMPDIR=/run/oblivion-live/user TERM=linux LANG=C.UTF-8 LC_ALL=C.UTF-8
UMask=0077
LimitCORE=0
MemorySwapMax=0
StandardInput=tty-force
StandardOutput=tty
StandardError=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/oblivion-network-console.service <<'EOF'
[Unit]
Description=Debian network configuration
After=NetworkManager.service
Wants=NetworkManager.service
Conflicts=getty@tty2.service
[Service]
ExecStart=/usr/bin/nmtui
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
# Let Debian resolve/bootstrap the outer physical link; the per-Safe deny policy
# lives exclusively in the controller VM and its gateway VMs.
mkdir -p /etc/NetworkManager/conf.d
printf '[connectivity]\nenabled=false\n[keyfile]\npath=/run/NetworkManager/system-connections\n' > /etc/NetworkManager/conf.d/80-oblivion-live.conf
printf 'kvm\nvhost_vsock\nvsock\n' > /etc/modules-load.d/oblivion-live.conf
printf 'MODULES=most\nCOMPRESS=gzip\nRESUME=none\n' > /etc/initramfs-tools/conf.d/oblivion
printf 'squashfs\noverlay\next4\niso9660\nloop\nvirtio_gpu\nvirtio_console\nxhci_pci\nusb_storage\nusbhid\n' > /etc/initramfs-tools/modules
update-initramfs -u -k all
systemctl enable oblivion-manager.service NetworkManager.service oblivion-network-console.service \
    oblivion-os-keyboard-console.service oblivion-os-timezone-console.service oblivion-live-keymap.path
systemctl mask NetworkManager-wait-online.service e2scrub_reap.service e2scrub_all.timer dpkg-db-backup.timer dpkg-db-backup.service
ln -sf /usr/lib/systemd/system/multi-user.target /etc/systemd/system/default.target
