#!/bin/sh
# Synthetic, networkless boot test. Installed only into audit probe images.
set -eu
trap 'printf "OBLIVION_TRIM_FAIL\n" > /dev/console' EXIT
role=$(cat /etc/oblivion-probe-role)
grep -q ' / squashfs ro,' /proc/mounts
grep -q ' /tmp tmpfs ' /proc/mounts
grep -q ' /var tmpfs ' /proc/mounts
[ "$(wc -l < /proc/swaps)" = 1 ]
systemctl is-active --quiet systemd-udevd.service systemd-logind.service
# Exercise the merged policy using systemd's own configuration resolver.
systemd-analyze cat-config systemd/journald.conf > /tmp/journal-policy
for field in Syslog KMsg Console Wall; do
    [ "$(sed -n "s/^ForwardTo$field=//p" /tmp/journal-policy | tail -n 1)" = no ]
done
[ "$(sed -n 's/^Storage=//p' /tmp/journal-policy | tail -n 1)" = none ]
case "$role" in
    session)
        mountpoint -q /vault
        [ "$(ls /sys/class/net)" = lo ]
        setpriv --reuid=1000 --regid=1000 --init-groups --no-new-privs \
            --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
            env HOME=/vault/home XDG_CONFIG_HOME=/vault/config XDG_STATE_HOME=/vault/state \
            XDG_DATA_HOME=/vault/state XDG_CACHE_HOME=/tmp/oblivion-cache \
            /bin/sh -eu -c '
                cd /vault/workspace
                mkdir probe && cd probe
                git init -q
                printf "print(6 * 7)\n" > answer.py
                [ "$(python3 answer.py)" = 42 ]
                rg -q "print" answer.py
                git add answer.py
                git diff --cached --exit-code --quiet && exit 1
                test "$(id -u)" = 1000
                ! touch /etc/oblivion-probe-write 2>/dev/null
                /usr/bin/oblivion --version
            '
        ;;
    gateway)
        systemctl is-active --quiet oblivion-gateway-network.service
        nft list ruleset | grep -q 'policy drop'
        [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ]
        [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" = 1 ]
        setpriv --reuid=1200 --regid=1200 --clear-groups tor --verify-config -f /etc/oblivion/torrc
        ;;
    import|export)
        [ "$(ls /sys/class/net)" = lo ]
        # Loading these modules includes their declared dependencies; the real
        # transfer regression still owns filesystem edge cases and receipts.
        modprobe vfat
        modprobe exfat
        modprobe nls_utf8
        mkdir /tmp/probe-disk
        mount -t ext4 -o nodev,nosuid,noexec /dev/vdb /tmp/probe-disk
        printf 'synthetic document\n' > /tmp/probe-disk/document.txt
        sync
        umount /tmp/probe-disk
        if /usr/bin/oblivion-copy >/tmp/endpoint.out 2>&1; then exit 1; fi
        grep -qx transfer_failed /tmp/endpoint.out
        ;;
esac
systemctl list-units --type=service --state=running --no-legend --plain | awk '{print "OBLIVION_SERVICE " $1}'
systemctl list-units --type=socket,timer --state=active --no-legend --plain | awk '{print "OBLIVION_ACTIVATION " $1}'
awk '{print "OBLIVION_MODULE " $1}' /proc/modules
printf 'OBLIVION_TRIM_PASS %s\n' "$role" > /dev/console
trap - EXIT
# The runner sends an ACPI power key through QMP. Do not force shutdown here:
# retaining logind and its input driver must be validated by actual power-off.
