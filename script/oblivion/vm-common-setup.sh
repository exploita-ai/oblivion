#!/bin/sh
set -eu
printf 'MODULES=list\nCOMPRESS=gzip\nRESUME=none\n' > /etc/initramfs-tools/conf.d/oblivion
printf 'virtio_pci\nvirtio_blk\nvirtio_rng\nsquashfs\next4\nevdev\n' > /etc/initramfs-tools/modules
if [ "$(dpkg --print-architecture)" = arm64 ]; then
    printf 'gpio_keys\n' >> /etc/initramfs-tools/modules
fi
update-initramfs -u -k all
mkdir -p /etc/systemd/journald.conf.d /etc/systemd/system.conf.d /etc/systemd/logind.conf.d
# Debian's syslog.conf sorts after oblivion.conf and otherwise reenables forwarding.
ln -sf /dev/null /etc/systemd/journald.conf.d/syslog.conf
printf '[Journal]\nStorage=none\nForwardToSyslog=no\nForwardToKMsg=no\nForwardToConsole=no\n' > /etc/systemd/journald.conf.d/oblivion.conf
printf '[Manager]\nDefaultLimitCORE=0\n' > /etc/systemd/system.conf.d/oblivion.conf
printf '[Login]\nHandlePowerKey=poweroff\n' > /etc/systemd/logind.conf.d/oblivion.conf
printf 'tmpfs /var tmpfs nosuid,nodev,mode=0755,size=128M 0 0\ntmpfs /tmp tmpfs nosuid,nodev,mode=1777,size=64M 0 0\n' > /etc/fstab
for unit in getty.target swap.target sleep.target suspend.target hibernate.target hybrid-sleep.target systemd-networkd.service systemd-timesyncd.service apt-daily.timer apt-daily-upgrade.timer fstrim.timer; do
    ln -sf /dev/null "/etc/systemd/system/$unit"
done
rm -f /etc/machine-id /var/lib/dbus/machine-id
touch /etc/machine-id
mkdir -p /var/lib/dbus
ln -s /etc/machine-id /var/lib/dbus/machine-id
systemctl enable systemd-logind.service dbus.service
