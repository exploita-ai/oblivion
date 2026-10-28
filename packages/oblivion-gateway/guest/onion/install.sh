#!/bin/sh
set -eu
test "$(id -u)" = 0
install -m 0644 /onion-config/firewall.nft /onion-config/torrc /etc/oblivion/
install -m 0755 /onion-config/network.sh /usr/libexec/oblivion-onion-network
install -m 0644 /onion-config/*.service /etc/systemd/system/
# systemd dependency lists cannot be cleared in drop-ins. Replace the complete
# unit's two network dependencies while retaining the common Tor hardening.
test "$(grep -c 'oblivion-gateway-network.service' /etc/systemd/system/oblivion-tor.service)" = 2
sed 's/oblivion-gateway-network.service/oblivion-onion-network.service/g' /etc/systemd/system/oblivion-tor.service > /tmp/oblivion-onion-tor.service
install -m 0644 /tmp/oblivion-onion-tor.service /etc/systemd/system/oblivion-tor.service
rm /tmp/oblivion-onion-tor.service
printf '%s\n' 'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.onion-gateway", OWNER="root", GROUP="root", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}+="oblivion-onion-gateway.service"' > /etc/udev/rules.d/71-oblivion-onion.rules
cat > /etc/systemd/system/oblivion-onion-gateway.target <<'EOF'
[Unit]
Description=Oblivion isolated Tor transfer gateway
Requires=multi-user.target oblivion-onion-network.service
After=multi-user.target oblivion-onion-network.service
AllowIsolate=yes
EOF
# This is an image-build transformation of the common gateway base. Remove
# unused model services/binaries rather than leaving two controllers available.
rm /etc/systemd/system/oblivion-gateway-control.service /etc/systemd/system/oblivion-gateway-network.service
rm /etc/udev/rules.d/70-oblivion-gateway.rules /usr/libexec/oblivion-gateway-network
rm /usr/bin/oblivion-api /usr/bin/oblivion-gateway-control /usr/bin/oblivion-egress /usr/bin/oblivion-tools
systemctl mask oblivion-gateway-control.service oblivion-gateway-network.service
ln -sf /etc/systemd/system/oblivion-onion-gateway.target /etc/systemd/system/default.target
setpriv --reuid=1200 --regid=1200 --clear-groups tor --verify-config -f /etc/oblivion/torrc
