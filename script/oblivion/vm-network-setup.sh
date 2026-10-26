#!/bin/sh
set -eu
for role in gateway chat; do
    requires=multi-user.target
    if [ "$role" = gateway ]; then requires=oblivion-gateway.target; fi
    cat > "/etc/systemd/system/oblivion-$role-lab.service" <<EOF
[Unit]
Requires=$requires
After=$requires
[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/libexec/oblivion-network-fixture $role
StandardInput=tty
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
TTYReset=yes
LimitCORE=0
ExecStopPost=/usr/bin/systemctl --no-block poweroff
EOF
    cat > "/etc/systemd/system/oblivion-$role-lab.target" <<EOF
[Unit]
Requires=oblivion-$role-lab.service
After=oblivion-$role-lab.service
AllowIsolate=yes
EOF
done
