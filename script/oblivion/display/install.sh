#!/bin/sh
set -eu
groupadd --gid 1104 oblivion-display
useradd --uid 1104 --gid 1104 --no-create-home --home-dir /run/oblivion-display --shell /usr/sbin/nologin oblivion-display
mkdir -p /etc/oblivion /etc/systemd/system/oblivion-manager.service.d
install -m 0644 /usr/lib/oblivion/display/foot.ini /etc/oblivion/foot.ini
cp /usr/lib/oblivion/display/*.service /usr/lib/oblivion/display/*.socket /etc/systemd/system/
cp /usr/lib/oblivion/display/manager.conf /etc/systemd/system/oblivion-manager.service.d/terminal.conf
systemctl disable seatd.service 2>/dev/null || true
systemctl enable oblivion-terminal.socket oblivion-display.service
