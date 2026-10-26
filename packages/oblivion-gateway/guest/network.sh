#!/bin/sh
set -eu
test "$(id -u)" = 0
test "$(wc -l < /proc/swaps)" = 1
# A failed policy load keeps both interfaces down and prevents Tor startup.
ip link set inside0 down
ip link set outside0 down
nft -f /etc/oblivion/firewall.nft
busybox sysctl -q -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 \
    net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 \
    net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0 \
    net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0 \
    net.ipv4.conf.all.route_localnet=0 net.ipv4.conf.default.route_localnet=0 \
    net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
ip address replace 10.88.0.1/30 dev inside0
ip address replace 10.0.2.15/24 dev outside0
ip link set inside0 up
ip link set outside0 up
ip route replace default via 10.0.2.2 dev outside0
