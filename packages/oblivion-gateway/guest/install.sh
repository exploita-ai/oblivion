#!/bin/sh
set -eu
for command in ip nft busybox tor setpriv; do command -v "$command" > /dev/null; done
busybox --list | grep -qx sysctl
mkdir -p /etc/oblivion /etc/systemd/network /etc/systemd/system/oblivion-gateway.target.wants
install -m 0644 /gateway-config/firewall.nft /gateway-config/torrc /etc/oblivion/
install -m 0755 /gateway-config/network.sh /usr/libexec/oblivion-gateway-network
install -m 0644 /gateway-config/*.service /etc/systemd/system/
groupmod -g 1200 debian-tor
usermod -u 1200 -g 1200 debian-tor
groupadd --gid 1201 oblivion-egress
useradd --uid 1201 --gid 1201 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin oblivion-egress
groupadd --gid 1300 oblivion-api
useradd --uid 1300 --gid 1300 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin oblivion-api
groupadd --gid 1301 oblivion-tools
useradd --uid 1301 --gid 1301 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin oblivion-tools
# /var is a fresh tmpfs. The controller needs its writable mount before Tor
# starts; create only an empty private directory, also in SOCKS mode.
mkdir -p /etc/tmpfiles.d
printf 'd /var/lib/tor 0700 debian-tor debian-tor -\n' > /etc/tmpfiles.d/oblivion-tor.conf
passwd -l root
for role in inside outside; do
    octet=01
    if [ "$role" = outside ]; then octet=02; fi
    printf '[Match]\nMACAddress=52:54:00:6f:00:%s\n\n[Link]\nName=%s0\n' "$octet" "$role" > "/etc/systemd/network/10-oblivion-$role.link"
done
printf 'virtio_net\nvirtio_console\nnf_tables\nnf_conntrack\n' > /etc/modules-load.d/oblivion-gateway.conf
mkdir -p /etc/udev/rules.d
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.gateway", OWNER="root", GROUP="root", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}+="oblivion-gateway-control.service"' > /etc/udev/rules.d/70-oblivion-gateway.rules
# Drivers must also be available while the initramfs sees the NICs, so udev
# assigns the intended names exactly once using the custom link files.
printf 'virtio_net\n' >> /etc/initramfs-tools/modules
cat > /etc/initramfs-tools/hooks/oblivion-network <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in prereqs) exit 0;; esac
mkdir -p "$DESTDIR/etc/systemd/network"
cp /etc/systemd/network/10-oblivion-*.link "$DESTDIR/etc/systemd/network/"
EOF
chmod 0755 /etc/initramfs-tools/hooks/oblivion-network
update-initramfs -u -k all
systemctl mask tor.service tor@default.service nftables.service
cat > /etc/systemd/system/oblivion-gateway.target <<'EOF'
[Unit]
Description=Oblivion isolated network gateway
Requires=multi-user.target oblivion-gateway-network.service
After=multi-user.target oblivion-gateway-network.service
AllowIsolate=yes
EOF
ln -sf /etc/systemd/system/oblivion-gateway.target /etc/systemd/system/default.target
# No resolver can quietly become an alternative DNS path. Tor resolves remote
# SOCKS destinations through its circuits; hostname bridges need explicit work.
setpriv --reuid=1200 --regid=1200 --clear-groups tor --verify-config -f /etc/oblivion/torrc
