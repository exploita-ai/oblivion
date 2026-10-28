#!/bin/sh
set -eu
test "$(id -u)" = 0
test "$(wc -l < /proc/swaps)" = 1
ip link set file0 down
nft -f /etc/oblivion/onion-file.nft
busybox sysctl -q -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 \
    net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 \
    net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0 \
    net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0 \
    net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
ip address replace 10.89.0.2/30 dev file0
ip link set file0 up
# Never create a default route, including during service start/failure.
test "$(ip -4 route show default | wc -l)" = 0
