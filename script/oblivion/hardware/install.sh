#!/bin/sh
set -eu
groupadd --gid 1050 oblivion-test
useradd --uid 1050 --gid 1050 --no-create-home --home-dir /run/oblivion-test --shell /bin/bash --password '*' oblivion-test
mkdir -p /etc/sudoers.d /etc/NetworkManager/conf.d /etc/sysctl.d /etc/profile.d
printf 'oblivion-test ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/oblivion-hardware
chmod 0440 /etc/sudoers.d/oblivion-hardware
visudo -cf /etc/sudoers.d/oblivion-hardware
ssh-keygen -lf /etc/oblivion/hardware/authorized_key.pub > /etc/oblivion/hardware/client-fingerprint
chmod 0644 /etc/oblivion/hardware/authorized_key.pub
# Server identity is unique to the running live boot, never embedded in an ISO.
rm -f /etc/ssh/ssh_host_*
systemctl mask ssh.service ssh.socket ssh@.service
cp /usr/lib/oblivion/hardware/*.service /etc/systemd/system/
cp /usr/lib/oblivion/hardware/sshd_config /etc/oblivion/hardware/sshd_config
chmod 0755 /usr/lib/oblivion/hardware/*.py
# Only the privileged controller invokes the debug API helper.
chmod 0700 /usr/lib/oblivion/hardware/debug.py
python3 -c 'import sys; sys.path.insert(0, "/usr/lib/oblivion/hardware"); from ssh_control import addresses; addresses()'
printf 'd /run/oblivion-test 0700 oblivion-test oblivion-test -\nd /run/sshd 0755 root root -\n' > /etc/tmpfiles.d/oblivion-hardware.conf
printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=16M\nForwardToSyslog=no\nForwardToConsole=no\n' > /etc/systemd/journald.conf.d/oblivion.conf
printf 'if [ "$(id -u)" = 1050 ]; then unset HISTFILE; fi\n' > /etc/profile.d/oblivion-hardware.sh
cat > /etc/NetworkManager/conf.d/90-oblivion-hardware.conf <<'EOF'
[main]
plugins=keyfile
dns=none
rc-manager=unmanaged
[connectivity]
enabled=false
[connection]
connection.mdns=0
connection.llmnr=0
ipv6.method=disabled
EOF
# Initial remote diagnostics use IPv4 only. The agent's VM/gateway isolation is
# unchanged; this connection belongs to the trusted hardware test operator.
printf 'net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\n' > /etc/sysctl.d/90-oblivion-hardware.conf
mkdir -p /etc/NetworkManager/dispatcher.d
cat > /etc/NetworkManager/dispatcher.d/90-oblivion-hardware <<'EOF'
#!/bin/sh
if systemctl is-active --quiet oblivion-hardware-ssh.service; then
    /usr/lib/oblivion/hardware/ssh_control.py refresh || systemctl --no-block stop oblivion-hardware-ssh.service
fi
EOF
chmod 0700 /etc/NetworkManager/dispatcher.d/90-oblivion-hardware
systemctl enable NetworkManager.service oblivion-hardware-console.service
systemctl disable oblivion-network-console.service
systemctl mask NetworkManager-wait-online.service e2scrub_reap.service e2scrub_all.timer
printf 'nf_tables\n' > /etc/modules-load.d/oblivion-hardware.conf
update-initramfs -u -k all
