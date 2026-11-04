#!/bin/sh
set -eu
umask 077
test "$(id -u)" = 0
test "$(wc -l < /proc/swaps)" = 1
# This channel carries only a fresh local tool-proxy token. Native provider
# authentication remains in the Safe's own encrypted profile, not this channel.
# RuntimeDirectory is a tmpfs-backed, root-owned directory.
until [ -e /dev/virtio-ports/oblivion.session ]; do sleep 0.1; done
exec 3<> /dev/virtio-ports/oblivion.session
printf 'token\n' >&3
dd bs=64 count=1 iflag=fullblock status=none <&3 > /run/oblivion-network/token
test "$(wc -c < /run/oblivion-network/token)" = 64
LC_ALL=C grep -Eq '^[a-f0-9]{64}$' /run/oblivion-network/token
IFS= read -r profile <&3
test "$profile" = native
IFS= read -r web_access <&3
case "$web_access" in
    strict|open) ;;
    *) exit 1 ;;
esac
printf '%s\n' "$web_access" > /run/oblivion-network/web-access
chmod 0640 /run/oblivion-network/token /run/oblivion-network/web-access
busybox sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
for address in /sys/class/net/*/address; do
    if [ "$(cat "$address")" = 52:54:00:6f:00:03 ]; then
        network_device=${address%/address}
        network_device=${network_device##*/}
        busybox ip address add 10.88.0.2/30 dev "$network_device"
        busybox ip link set "$network_device" up
        # No default route, DHCP, DNS or path to the host network.
        printf 'ready\n' >&3
        exit 0
    fi
done
exit 1
