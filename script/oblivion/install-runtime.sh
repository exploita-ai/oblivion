#!/bin/sh
# Install a prepared Debian runtime root, or stage it for a Debian package.
# The source contains /usr/bin/oblivion*, /usr/lib/oblivion and controller.json.
set -eu

source_root=
target_root=/
manager_uid=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --source|--root|--manager-uid)
            [ "$#" -ge 2 ] || { echo 'missing argument' >&2; exit 2; }
            case "$1" in
                --source) source_root=$2 ;;
                --root) target_root=$2 ;;
                --manager-uid) manager_uid=$2 ;;
            esac
            shift 2
            ;;
        --help)
            echo 'Usage: install-runtime.sh --source ROOT --manager-uid UID [--root DESTDIR]'
            exit 0
            ;;
        *) echo 'unknown argument' >&2; exit 2 ;;
    esac
done

case "$manager_uid" in
    ''|*[!0-9]*|0) echo 'a non-root manager UID is required' >&2; exit 2 ;;
esac
[ -n "$source_root" ] && [ -d "$source_root" ] && [ -d "$target_root" ] || {
    echo 'source and target directories are required' >&2; exit 2;
}
source_root=$(cd "$source_root" && pwd -P)
target_root=$(cd "$target_root" && pwd -P)
[ "$source_root" != "$target_root" ] || { echo 'source must differ from target' >&2; exit 2; }
if [ "$target_root" = / ]; then
    [ "$(id -u)" -eq 0 ] || { echo 'root is required for installation' >&2; exit 1; }
fi

# Preflight the entire input before installing any files.
for unit in oblivion-controller oblivion-manager oblivion-recover; do
    [ -f "$source_root/etc/systemd/system/$unit.service" ] || {
        echo "missing runtime service: $unit" >&2; exit 1;
    }
done
for binary in oblivion oblivion-storage oblivion-control oblivion-console oblivion-copy oblivion-manager; do
    [ -f "$source_root/usr/bin/$binary" ] && [ -x "$source_root/usr/bin/$binary" ] || {
        echo "missing runtime binary: $binary" >&2; exit 1;
    }
done
[ -d "$source_root/usr/lib/oblivion/vm" ] && [ -d "$source_root/usr/lib/oblivion/manager" ] || {
    echo 'missing immutable runtime assets' >&2; exit 1;
}
python3 - "$source_root" "$manager_uid" "$target_root" <<'PY'
import json
import pathlib
import pwd
import grp
import sys

root = pathlib.Path(sys.argv[1])
config = json.loads((root / 'etc/oblivion/controller.json').read_text())
assert 0 < int(sys.argv[2]) < 2**32 - 1, 'invalid manager UID'
destination = pathlib.Path(sys.argv[3]) / 'etc/oblivion/controller.json'
if destination.exists():
    installed = json.loads(destination.read_text())
    assert installed['manager_uid'] == int(sys.argv[2]), 'installed manager UID differs'
if sys.argv[3] == '/':
    pwd.getpwuid(int(sys.argv[2]))
    identities = [(1100, 'oblivion-vm'), (1101, 'oblivion-gateway-vm'),
                  (1102, 'oblivion-import-vm'), (1103, 'oblivion-export-vm'),
                  (1105, 'oblivion-onion-gateway-vm'), (1106, 'oblivion-onion-file-vm')]
    identities += [(16000 + slot * 16 + offset, f'oblivion-{role}-s{slot}')
                   for slot in range(1, 32)
                   for offset, role in ((0, 'session'), (1, 'gateway-vm'), (2, 'import-vm'),
                                        (3, 'export-vm'), (5, 'onion-gateway-vm'), (6, 'onion-file-vm'))]
    users = {entry.pw_uid: entry.pw_name for entry in pwd.getpwall()}
    groups = {entry.gr_gid: entry.gr_name for entry in grp.getgrall()}
    for uid, name in identities:
        assert uid not in users or users[uid] == name, f'reserved UID occupied: {uid}'
        assert uid not in groups or groups[uid] == name, f'reserved GID occupied: {uid}'
        assert name not in users.values() or users.get(uid) == name, f'user has unexpected UID: {name}'
        assert name not in groups.values() or groups.get(uid) == name, f'group has unexpected GID: {name}'
for role in ('vm', 'gateway', 'import', 'export'):
    assert role in config, f'missing VM role: {role}'
    for field in ('root', 'kernel', 'initrd', 'filesystem'):
        path = pathlib.Path(config[role][field])
        assert path.is_absolute() and '..' not in path.parts, 'invalid VM asset path'
        assert path.is_relative_to('/usr/lib/oblivion/vm'), 'VM asset outside runtime'
        assert (root / str(path).lstrip('/')).exists(), f'missing VM asset: {role}/{field}'
PY

install -d -m 0755 "$target_root/usr/bin" "$target_root/usr/lib/oblivion" \
    "$target_root/usr/lib/systemd/system" "$target_root/usr/lib/sysusers.d" \
    "$target_root/etc/oblivion" "$target_root/etc/systemd/system/oblivion-manager.service.d"
install -d -m 0700 "$target_root/var/lib/oblivion"
for binary in oblivion oblivion-storage oblivion-control oblivion-console oblivion-copy oblivion-manager; do
    install -m 0755 "$source_root/usr/bin/$binary" "$target_root/usr/bin/$binary"
done
cp -a "$source_root/usr/lib/oblivion/." "$target_root/usr/lib/oblivion/"
# The Live host firewall owns its whole Debian network policy. Installed
# runtimes retain Debian's network configuration and enforce each Safe at its
# private gateway boundary.
for unit in "$source_root"/etc/systemd/system/oblivion-*.service; do
    case "$(basename "$unit")" in
        oblivion-controller.service|oblivion-manager.service|oblivion-recover.service|oblivion-runtime-prepare.service|oblivion-control-relay.service|oblivion-gateway-host*.service|oblivion-transfer-host*.service|oblivion-onion-host*.service)
            install -m 0644 "$unit" "$target_root/usr/lib/systemd/system/$(basename "$unit")"
            ;;
    esac
done
if [ -f "$source_root/usr/lib/systemd/system-generators/oblivion-runtime-generator" ]; then
    install -d -m 0755 "$target_root/usr/lib/systemd/system-generators"
    install -m 0755 "$source_root/usr/lib/systemd/system-generators/oblivion-runtime-generator" "$target_root/usr/lib/systemd/system-generators/oblivion-runtime-generator"
fi
python3 - "$source_root" "$target_root" "$manager_uid" <<'PY'
import json
import os
import pathlib
import sys

source, target = map(pathlib.Path, sys.argv[1:3])
destination = target / 'etc/oblivion/controller.json'
if not destination.exists():
    config = json.loads((source / 'etc/oblivion/controller.json').read_text())
    config.update(manager_uid=int(sys.argv[3]), usb_persistence=False,
                  network_profiles=False, manage_os_preferences=False,
                  general_image='/var/lib/oblivion/general.luks')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(config, output, indent=2)
        output.write('\n')
else:
    config = json.loads(destination.read_text())
    assert config['manager_uid'] == int(sys.argv[3]), 'installed manager UID differs'
PY
cat > "$target_root/etc/systemd/system/oblivion-manager.service.d/user.conf" <<EOF
[Service]
User=$manager_uid
Group=
EOF

# Keep these identities aligned with scope::Slot::uid. sysusers refuses to
# replace existing users, so the caller must supply a clean Debian runtime.
{
    for entry in '1100 oblivion-vm' '1101 oblivion-gateway-vm' '1102 oblivion-import-vm' '1103 oblivion-export-vm' '1105 oblivion-onion-gateway-vm' '1106 oblivion-onion-file-vm'; do
        set -- $entry
        printf 'u %s %s - /nonexistent /usr/sbin/nologin\n' "$2" "$1"
    done
    for slot in $(seq 1 31); do
        for entry in '0 session' '1 gateway-vm' '2 import-vm' '3 export-vm' '5 onion-gateway-vm' '6 onion-file-vm'; do
            set -- $entry
            printf 'u oblivion-%s-s%s %s - /nonexistent /usr/sbin/nologin\n' "$2" "$slot" "$((16000 + slot * 16 + $1))"
        done
    done
} > "$target_root/usr/lib/sysusers.d/oblivion.conf"

if [ "$target_root" = / ]; then
    [ "$(id -u)" -eq 0 ] || { echo 'root is required for installation' >&2; exit 1; }
    systemd-sysusers /usr/lib/sysusers.d/oblivion.conf
    systemctl daemon-reload
    systemctl enable oblivion-controller.service
fi
echo 'Oblivion runtime installed. The controller starts independently of the manager.'
