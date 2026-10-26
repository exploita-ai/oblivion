#!/bin/sh
set -eu
mkdir -p /data /usr/lib/oblivion/vm /etc/systemd/system/oblivion-lab.target.wants
mkdir -p /etc/modules-load.d
printf 'loop\ndm_crypt\n' > /etc/modules-load.d/oblivion.conf
# Diagnostics are volatile and contain only synthetic laboratory data.
printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=16M\n' > /etc/systemd/journald.conf.d/oblivion.conf
cat > /etc/systemd/system/oblivion-lab.service <<'EOF'
[Unit]
Description=Oblivion synthetic VM integration laboratory
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/libexec/oblivion-vm-test
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
TimeoutStartSec=15min
ExecStopPost=/usr/bin/systemctl --no-block poweroff
EOF
cat > /etc/systemd/system/oblivion-lab.target <<'EOF'
[Unit]
Requires=multi-user.target oblivion-lab.service
After=multi-user.target
AllowIsolate=yes
EOF
ln -sf /etc/systemd/system/oblivion-lab.target /etc/systemd/system/default.target
