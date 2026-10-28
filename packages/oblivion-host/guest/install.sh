#!/bin/sh
set -eu
cp /usr/lib/oblivion/guest/oblivion-vault.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-documents-ready.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-conversation.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-terminal.service /etc/systemd/system/
mkdir -p /etc/oblivion
cp /usr/lib/oblivion/guest/tmux.conf /etc/oblivion/tmux.conf
cp /usr/lib/oblivion/guest/oblivion-session-network.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-import-receive@.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-export-send@.service /etc/systemd/system/
cp /usr/lib/oblivion/guest/oblivion-chat-export@.service /etc/systemd/system/
chmod 0755 /usr/lib/oblivion/guest/*.sh /usr/libexec/oblivion
mkdir -p /etc/modules-load.d /etc/udev/rules.d
printf 'virtio_net\nvirtio_console\n' > /etc/modules-load.d/oblivion-session.conf
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.session", OWNER="root", GROUP="root", MODE="0600"' > /etc/udev/rules.d/70-oblivion-session.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.documents", OWNER="root", GROUP="root", MODE="0600"' >> /etc/udev/rules.d/70-oblivion-session.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.copy.*", OWNER="1001", GROUP="1000", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}="oblivion-import-receive@%k.service"' > /etc/udev/rules.d/71-oblivion-import.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.export.*", OWNER="1000", GROUP="1000", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}="oblivion-export-send@%k.service"' > /etc/udev/rules.d/72-oblivion-export.rules
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.archive.*", OWNER="1000", GROUP="1000", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}="oblivion-chat-export@$attr{name}.service"' > /etc/udev/rules.d/73-oblivion-chat-export.rules
printf '/dev/vdb /vault ext4 nodev,nosuid,noatime 0 0\n' >> /etc/fstab
systemctl enable oblivion-vault.service oblivion-conversation.service oblivion-documents-ready.service oblivion-terminal.service
