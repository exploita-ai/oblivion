#!/bin/sh
set -eu
cp /usr/lib/oblivion/guest/oblivion-vault.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-documents-ready.service /etc/systemd/system/
ln -sf /usr/lib/oblivion/guest/agent.sh /usr/bin/oblivion-agent
cp /usr/lib/oblivion/guest/oblivion-agent@.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-workspace.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/shell-profile.sh /etc/profile.d/oblivion-safe.sh
chmod 0644 /etc/profile.d/oblivion-safe.sh
cp /usr/lib/oblivion/guest/oblivion-history.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-safe-tools.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-file@.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-safe-admin@.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-share-export@.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-share-import@.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-resize.service /etc/systemd/system/
mkdir -p /etc/systemd/system/vault.mount.d
printf '[Unit]\nConditionKernelCommandLine=!oblivion.resize=1\n' > /etc/systemd/system/vault.mount.d/maintenance.conf
mkdir -p /etc/oblivion
cp /usr/lib/oblivion/guest/tmux.conf /etc/oblivion/tmux.conf
cp /usr/lib/oblivion/guest/oblivion-session-network.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-import-receive@.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-export-send@.service /etc/systemd/system/
chmod 0755 /usr/lib/oblivion/guest/*.sh /usr/libexec/oblivion
mkdir -p /etc/modules-load.d /etc/udev/rules.d
printf 'virtio_net\nvirtio_console\n' > /etc/modules-load.d/oblivion-session.conf
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.session", OWNER="root", GROUP="root", MODE="0600"' > /etc/udev/rules.d/70-oblivion-session.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.documents", OWNER="root", GROUP="root", MODE="0600"' >> /etc/udev/rules.d/70-oblivion-session.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.resize", OWNER="root", GROUP="root", MODE="0600"' >> /etc/udev/rules.d/70-oblivion-session.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.safe-tools", OWNER="root", GROUP="root", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}="oblivion-safe-tools.service"' >> /etc/udev/rules.d/70-oblivion-session.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.copy.*", OWNER="1001", GROUP="1000", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}="oblivion-import-receive@%k.service"' > /etc/udev/rules.d/71-oblivion-import.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.export.*", OWNER="1000", GROUP="1000", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}="oblivion-export-send@%k.service"' > /etc/udev/rules.d/72-oblivion-export.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.agent.*", OWNER="1000", GROUP="1000", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}="oblivion-agent@%k.service"' > /etc/udev/rules.d/74-oblivion-agent.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.file.*", OWNER="1000", GROUP="1000", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}="oblivion-file@%k.service"' > /etc/udev/rules.d/75-oblivion-file.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.admin.*", OWNER="1000", GROUP="1000", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}="oblivion-safe-admin@$attr{name}.service"' > /etc/udev/rules.d/76-oblivion-safe-admin.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.share-export.*", OWNER="1000", GROUP="1000", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}="oblivion-share-export@%k.service"' > /etc/udev/rules.d/77-oblivion-share.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.share-import.*", OWNER="root", GROUP="root", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}="oblivion-share-import@%k.service"' >> /etc/udev/rules.d/77-oblivion-share.rules
printf '/dev/vdb /vault ext4 nodev,nosuid,noatime 0 0\n' >> /etc/fstab
# Session package state must survive together with its binaries. Other VM
# roles retain vm-common-setup.sh's read-only root and RAM-backed /var.
sed -i '\|^tmpfs /var tmpfs |d' /etc/fstab
printf 'tmpfs /var/log tmpfs nosuid,nodev,mode=0755,size=32M 0 0\ntmpfs /var/tmp tmpfs nosuid,nodev,mode=1777,size=64M 0 0\n' >> /etc/fstab
mkdir -p /etc/initramfs-tools/scripts/local-bottom /etc/sudoers.d
cp /usr/lib/oblivion/guest/system-overlay.sh /etc/initramfs-tools/scripts/local-bottom/oblivion-system
chmod 0755 /etc/initramfs-tools/scripts/local-bottom/oblivion-system
printf 'overlay\n' >> /etc/initramfs-tools/modules
# The root is already mounted with the correct options by initramfs. The
# kernel command line still says ro for the squashfs lower and resize boots.
ln -sf /dev/null /etc/systemd/system/systemd-remount-fs.service
cp /usr/lib/oblivion/guest/sudoers /etc/sudoers.d/oblivion-session
chmod 0440 /etc/sudoers.d/oblivion-session
visudo -cf /etc/sudoers
cp /usr/lib/oblivion/guest/apt-session.conf /etc/apt/apt.conf.d/90oblivion-session
sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources
update-initramfs -u -k all
systemctl enable oblivion-history.service oblivion-vault.service oblivion-documents-ready.service oblivion-resize.service
