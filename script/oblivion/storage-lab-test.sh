#!/bin/sh
set -eu
umask 077
trap 'result=$?; if [ "$result" != 0 ]; then cat /run/client-error /run/daemon-error /run/failed-error 2>/dev/null; fi' EXIT

cat > /etc/oblivion-storage.json <<'EOF'
{"general_image":"/data/general.luks","general_mib":768,"session_mib":128,"pbkdf_memory_kib":65536,"manager_uid":1000}
EOF

ctl() {
    /usr/bin/oblivion-storage --config /etc/oblivion-storage.json "$@"
}

must_fail() {
    if "$@" > /run/failed-out 2> /run/failed-error; then
        printf 'FAIL: operation unexpectedly succeeded\n'
        exit 1
    fi
}

check() {
    printf 'PASS: %s\n' "$1"
}

printf 'synthetic-general-password' | ctl init-general
header_before=$(dd if=/data/general.luks bs=1048576 count=16 2>/dev/null | sha256sum)
printf 'different-general-password' | must_fail ctl init-general
header_after=$(dd if=/data/general.luks bs=1048576 count=16 2>/dev/null | sha256sum)
[ "$header_before" = "$header_after" ]
check 'existing image cannot be initialized again'
printf 'wrong-password' | must_fail ctl unlock
[ ! -e /dev/mapper/oblivion-general ]
check 'wrong general password leaves volume locked'
printf 'synthetic-general-password' | ctl unlock
mkdir -p /run/oblivion/general/profile
printf 'OBLIVION_PROFILE_CANARY_b3de' > /run/oblivion/general/profile/settings
a=$(printf 'synthetic-session-password-a' | ctl create)
b=$(printf 'synthetic-session-password-b' | ctl create)
[ "$a" != "$b" ]
[ ! -e /dev/mapper/oblivion-session ]
uuid_a=$(/usr/sbin/cryptsetup luksUUID "/run/oblivion/general/sessions/$a.luks")
uuid_b=$(/usr/sbin/cryptsetup luksUUID "/run/oblivion/general/sessions/$b.luks")
[ "$uuid_a" != "$uuid_b" ]
check 'independent session containers are created locked'
printf 'synthetic-general-password' | must_fail ctl open "$a"
printf 'synthetic-session-password-a' | must_fail ctl open "$b"
printf 'synthetic-session-password-a' | must_fail ctl open ../../profile
[ ! -e /dev/mapper/oblivion-session ]
check 'general and other session passwords cannot unlock A or B'
printf 'synthetic-session-password-a' | ctl open "$a"
printf 'synthetic-session-password-b' | must_fail ctl open "$b"
printf 'synthetic-session-password-c' | must_fail ctl create
check 'only one session mapping can be open'
rm /dev/mapper/oblivion-session
ctl status > /run/missing-device-status
grep -q '"session_open":true' /run/missing-device-status
printf 'synthetic-session-password-b' | must_fail ctl open "$b"
ctl close
printf 'synthetic-session-password-a' | ctl open "$a"
check 'missing userspace device alias cannot hide an active kernel mapping'

# A trusted fixture mounts the volume for storage tests only. The production
# controller never mounts a session FS; VM ownership is tested separately.
/usr/bin/mount /dev/mapper/oblivion-session /session
printf 'OBLIVION_SESSION_A_CANARY_a67c' > /session/document.txt
mkdir -p /session/home
printf 'OBLIVION_CHAT_CANARY_c92e' > /session/home/chat.txt
must_fail ctl close
must_fail ctl lock
[ -e /dev/mapper/oblivion-session ]
[ -e /dev/mapper/oblivion-general ]
check 'busy session prevents close and global lock'
/usr/bin/umount /session
ctl close
[ ! -e /dev/mapper/oblivion-session ]

printf 'synthetic-session-password-b' | ctl open "$b"
/usr/bin/mount /dev/mapper/oblivion-session /session
[ ! -e /session/document.txt ]
[ ! -e /session/home/chat.txt ]
printf 'OBLIVION_SESSION_B_CANARY_b98d' > /session/document.txt
/usr/bin/umount /session
ctl close
check 'B has an independent filesystem'
printf 'synthetic-session-password-a' | ctl open "$a"
/usr/bin/mount /dev/mapper/oblivion-session /session
[ "$(cat /session/document.txt)" = OBLIVION_SESSION_A_CANARY_a67c ]
[ "$(cat /session/home/chat.txt)" = OBLIVION_CHAT_CANARY_c92e ]
/usr/bin/umount /session
ctl close
check 'A persists after switching to B and back'

# Stop an actual cryptsetup child, then kill its controller. The child must keep
# the operation lock, otherwise a second controller can race the first mapping.
printf 'synthetic-session-password-a' | /usr/bin/oblivion-storage --config /etc/oblivion-storage.json open "$a" > /run/crash-out 2> /run/crash-error &
controller=$!
deadline=$(( $(cut -d. -f1 /proc/uptime) + 10 ))
child=
while [ -z "$child" ]; do
    children=$(cat "/proc/$controller/task/$controller/children")
    for candidate in $children; do child=$candidate; break; done
    [ "$(cut -d. -f1 /proc/uptime)" -lt "$deadline" ]
done
# Wait until the parent has finished writing the password and is in waitpid.
# Killing it before that would test an incomplete request, not recovery after an
# admitted unlock, and could legitimately leave the mapping unopened.
while [ "$(cat "/proc/$controller/wchan")" != do_wait ]; do
    [ "$(cut -d. -f1 /proc/uptime)" -lt "$deadline" ]
done
kill -STOP "$child"
kill -KILL "$controller"
wait "$controller" 2>/dev/null || true
must_fail ctl status
grep -q controller_busy /run/failed-error
kill -CONT "$child"
deadline=$(( $(cut -d. -f1 /proc/uptime) + 20 ))
while ! ctl status > /run/recovered-status 2>/run/recovered-error; do
    [ "$(cut -d. -f1 /proc/uptime)" -lt "$deadline" ]
    sleep 0.05
done
[ -e /dev/mapper/oblivion-session ]
printf 'synthetic-session-password-b' | must_fail ctl open "$b"
ctl close
check 'controller death preserves child interlock and kernel-state recovery'

ctl lock
[ ! -e /dev/mapper/oblivion-session ]
[ ! -e /dev/mapper/oblivion-general ]
printf 'synthetic-general-password' | ctl unlock
[ "$(cat /run/oblivion/general/profile/settings)" = OBLIVION_PROFILE_CANARY_b3de ]
ctl status > /run/status.json
grep -q "$a" /run/status.json
grep -q "$b" /run/status.json
ctl lock
ctl lock
check 'general profile and opaque session index survive relock'
check 'global lock is idempotent and removes both mappings'

before=$(sha256sum /data/general.luks)
printf 'synthetic-general-password' | ctl unlock-ephemeral
[ "$(blockdev --getro /dev/mapper/oblivion-general)" = 1 ]
[ "$(cat /run/oblivion/general/profile/settings)" = OBLIVION_PROFILE_CANARY_b3de ]
ctl status > /run/readonly-status
grep -q '"general_readonly":true' /run/readonly-status
printf 'synthetic-session-password-c' | must_fail ctl create
printf 'synthetic-session-password-a' | must_fail ctl open "$a"
must_fail /usr/bin/mount -o remount,rw /run/oblivion/general
ctl lock
after=$(sha256sum /data/general.luks)
[ "$before" = "$after" ]
check 'ephemeral profile unlock is block-readonly and leaves image byte-identical'

/usr/bin/oblivion-storage --config /etc/oblivion-storage.json serve > /run/daemon-out 2>/run/daemon-error &
daemon=$!
client() {
    /usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups /usr/bin/oblivion-control "$@"
}
deadline=$(( $(cut -d. -f1 /proc/uptime) + 10 ))
while ! client status > /run/client-status 2>/run/client-error; do
    kill -0 "$daemon"
    [ "$(cut -d. -f1 /proc/uptime)" -lt "$deadline" ]
    sleep 0.02
done
grep -q '"general_open":false' /run/client-status
must_fail /usr/bin/oblivion-control status
must_fail /usr/bin/setpriv --reuid=1001 --regid=1001 --clear-groups /usr/bin/oblivion-control status
must_fail client shell
/usr/bin/ipc-probe unauthorized
/usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups /usr/bin/ipc-probe
check 'control socket accepts only the manager UID and enumerated operations'
check 'malformed, oversized, incomplete and path-injection requests are rejected'
printf 'synthetic-general-password' | client unlock
printf 'synthetic-session-password-a' | must_fail client open "$a"
grep -q control_request_failed /run/failed-error
printf 'synthetic-session-password-a' | must_fail ctl enter "$a"
grep -q vm_not_configured /run/failed-error
[ ! -e /dev/mapper/oblivion-session ]
check 'manager open refuses storage-only configuration without a VM'
printf 'synthetic-session-password-a' | ctl open "$a"
[ -e /dev/mapper/oblivion-session ]
must_fail /usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups cat /run/oblivion/general/profile/settings
client close
client lock
[ ! -e /dev/mapper/oblivion-general ]
kill "$daemon"
wait "$daemon" 2>/dev/null || true
[ ! -s /run/daemon-out ]
[ ! -s /run/daemon-error ]
check 'unprivileged manager controls storage without access to the general filesystem'
/usr/bin/umount /data
