#!/usr/bin/env python3
"""Test host packet policy on a live ARM64 ISO with a RAM-only diagnostic overlay.

No writable guest disk, physical device, network uplink or user archive is attached.
This is direct-kernel qualification, not an unmodified UEFI/USB acceptance test.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import resource
import shutil
import subprocess
import tempfile
import zlib

parser = argparse.ArgumentParser()
parser.add_argument('--iso', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
iso = args.iso.resolve(strict=True)
output = args.output.resolve()
assert ',' not in str(iso) and ',' not in str(output)
output.mkdir(parents=True, exist_ok=False)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
subprocess.run(['bsdtar', '-xf', str(iso), '-C', str(output), 'live/vmlinuz', 'live/initrd.img'], check=True)
initrd = (output/'live/initrd.img').read_bytes()
order = None
for header in re.finditer(b'\x1f\x8b\x08', initrd):
    try:
        archive = gzip.decompress(initrd[header.start():])
    except (zlib.error, EOFError, gzip.BadGzipFile):
        continue
    order = subprocess.check_output(['bsdtar', '-xOf', '-', 'scripts/init-bottom/ORDER'], input=archive)
    break
assert order is not None
scripts = Path(__file__).parent
with tempfile.TemporaryDirectory(prefix='oblivion-policy-initrd-') as directory:
    root = Path(directory)
    (root/'scripts/init-bottom').mkdir(parents=True)
    shutil.copyfile(scripts/'test-host-firewall.py', root/'scripts/policy-test.py')
    shutil.copyfile(scripts/'host-firewall.nft', root/'scripts/host-firewall.nft')
    shutil.copyfile(scripts/'audit-runtime.py', root/'scripts/audit-runtime.py')
    shutil.copyfile(scripts.parent.parent/'packages/oblivion-host/host/oblivion-host-firewall.service', root/'scripts/oblivion-host-firewall.service')
    hook = root/'scripts/init-bottom/zz-oblivion-policy-test'
    hook.write_text('''#!/bin/sh
set -eu
case "${1:-}" in prereqs) exit 0;; esac
cp /scripts/policy-test.py /scripts/host-firewall.nft /scripts/audit-runtime.py "${rootmnt:-/root}/usr/libexec/"
cp /scripts/oblivion-host-firewall.service "${rootmnt:-/root}/etc/systemd/system/"
cat > "${rootmnt:-/root}/usr/libexec/oblivion-policy-probe" <<'PROBE'
#!/bin/sh
exec >/dev/ttyAMA0 2>&1
set -eu
trap 'systemctl --no-block poweroff' EXIT
# Use the immutable Debian tools already shipped in the session/gateway images.
# Their filesystems are mounted read-only solely in this disposable diagnostic.
mkdir -p /run/policy-session /run/policy-gateway
mount -t squashfs -o loop,ro,nodev,nosuid /usr/lib/oblivion/vm/session/root.squashfs /run/policy-session
mount -t squashfs -o loop,ro,nodev,nosuid /usr/lib/oblivion/vm/gateway/root.squashfs /run/policy-gateway
export PATH=/run/policy-session/usr/bin:/run/policy-gateway/usr/sbin:/usr/sbin:/usr/bin:/sbin:/bin
export PYTHONHOME=/run/policy-session/usr
export PYTHONDONTWRITEBYTECODE=1
export LD_LIBRARY_PATH=/run/policy-session/usr/lib/aarch64-linux-gnu:/run/policy-gateway/usr/lib/aarch64-linux-gnu
if test -x /usr/sbin/nft; then
    systemctl is-active --quiet oblivion-host-firewall.service
    nft list table inet oblivion_host >/dev/null
    python3 -c 'import subprocess; get=lambda unit,key:subprocess.check_output(["systemctl","show",unit,"--property="+key,"--value"],text=True).strip(); policy=int(get("oblivion-host-firewall.service","ActiveEnterTimestampMonotonic")); assert policy>0; units=["NetworkManager.service","oblivion-controller.service"]; assert all("oblivion-host-firewall.service" in get(unit,"Requires").split() and policy<=int(get(unit,"ActiveEnterTimestampMonotonic")) for unit in units)'
    echo 'PASS: rebuilt host loads firewall before NetworkManager and controller activation'
fi
unshare --net python3 /usr/libexec/policy-test.py /usr/libexec/host-firewall.nft
# Exercise the real systemd confinement using the immutable image's nft binary.
# Only its executable/library locations differ from the rebuilt host package.
mkdir -p /run/systemd/system/oblivion-host-firewall.service.d
cp /usr/libexec/host-firewall.nft /etc/oblivion/host-firewall.nft
cat > /run/systemd/system/oblivion-host-firewall.service.d/lab.conf <<'POLICY'
[Service]
Environment=LD_LIBRARY_PATH=/run/policy-gateway/usr/lib/aarch64-linux-gnu
ExecStart=
ExecStart=/run/policy-gateway/usr/sbin/nft -f /etc/oblivion/host-firewall.nft
POLICY
systemctl daemon-reload
systemctl start oblivion-host-firewall.service
nft list table inet oblivion_host >/dev/null
python3 /usr/libexec/audit-runtime.py >/run/audit-runtime.json
python3 -c 'import json; from pathlib import Path; print("OBLIVION_RUNTIME " + json.dumps(json.loads(Path("/run/audit-runtime.json").read_text())))'
systemctl stop oblivion-host-firewall.service
nft list table inet oblivion_host >/dev/null
echo 'PASS: confined firewall service installs policy and stopping it retains enforcement'
printf 'invalid-policy\\n' > /etc/oblivion/host-firewall.nft
if systemctl start oblivion-host-firewall.service; then exit 1; fi
nft list table inet oblivion_host >/dev/null
echo 'PASS: invalid replacement fails the service without removing the existing policy'
echo OBLIVION_LIVE_POLICY_PASS
PROBE
chmod 0755 "${rootmnt:-/root}/usr/libexec/oblivion-policy-probe"
cat > "${rootmnt:-/root}/etc/systemd/system/oblivion-policy-probe.service" <<'UNIT'
[Unit]
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/usr/libexec/oblivion-policy-probe
UNIT
ln -s ../oblivion-policy-probe.service "${rootmnt:-/root}/etc/systemd/system/multi-user.target.wants/oblivion-policy-probe.service"
''')
    hook.chmod(0o755)
    (hook.parent/'ORDER').write_bytes(order+b'\n/scripts/init-bottom/zz-oblivion-policy-test "$@"\n')
    archive = subprocess.check_output(['bsdtar', '--format=newc', '--uid=0', '--gid=0', '-cf', '-', 'scripts'], cwd=root)
(output/'probe-initrd').write_bytes(initrd+gzip.compress(archive, mtime=0))
command = ['qemu-system-aarch64', '-machine', 'virt', '-accel', 'hvf', '-cpu', 'host', '-m', '2048', '-smp', '2',
    '-nodefaults', '-no-reboot', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-nic', 'none',
    '-kernel', str(output/'live/vmlinuz'), '-initrd', str(output/'probe-initrd'),
    '-append', 'boot=live live-media=/dev/vda components nopersistence noeject nonetworking ip=off pstore.backend=none efi_pstore.pstore_disable=1 systemd.mask=systemd-pstore.service systemd.getty_auto=no console=ttyAMA0',
    '-drive', f'file={iso},format=raw,if=virtio,readonly=on', '-device', 'virtio-rng-pci']
with (output/'serial.log').open('xb') as log:
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=180)
serial = (output/'serial.log').read_text(errors='replace')
report = {'scope': __doc__.strip(), 'iso_sha256': hashlib.sha256(iso.read_bytes()).hexdigest(),
    'policy_sha256': hashlib.sha256((scripts/'host-firewall.nft').read_bytes()).hexdigest(),
    'fixture_sha256': hashlib.sha256((scripts/'test-host-firewall.py').read_bytes()).hexdigest(),
    'qemu_exit': result.returncode, 'passed': 'OBLIVION_LIVE_POLICY_PASS' in serial,
    'runtime': next((json.loads(line.removeprefix('OBLIVION_RUNTIME ')) for line in serial.splitlines() if line.startswith('OBLIVION_RUNTIME ')), None),
    'checks': [line for line in serial.splitlines() if line.startswith('PASS:')]}
(output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({key: value for key, value in report.items() if key != 'runtime'}, indent=2))
assert report['passed'] and result.returncode == 0
