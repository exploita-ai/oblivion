#!/usr/bin/env python3
"""Kill and reboot a disposable live VM at the compiled chat API commit boundary.

No user media, network, hibernation or saved VM memory. The tested crash loses
Linux guest RAM, not the physical Mac's storage caches or power supply.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import shutil
import subprocess
import tempfile
import time
import zlib

parser = argparse.ArgumentParser(description=__doc__)
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
with tempfile.TemporaryDirectory(prefix='oblivion-crash-initrd-') as directory:
    root = Path(directory)
    (root/'scripts/init-bottom').mkdir(parents=True)
    shutil.copyfile(scripts/'vm-chat-powerloss.py', root/'scripts/vm-chat-powerloss.py')
    shutil.copyfile(scripts.parent.parent/'packages/oblivion-host/guest/chat-database.py', root/'scripts/chat-database.py')
    hook = root/'scripts/init-bottom/zz-oblivion-crash-test'
    hook.write_text('''#!/bin/sh
set -eu
case "${1:-}" in prereqs) exit 0;; esac
cp /scripts/vm-chat-powerloss.py /scripts/chat-database.py "${rootmnt:-/root}/usr/libexec/"
cat > "${rootmnt:-/root}/usr/libexec/oblivion-crash-probe" <<'PROBE'
#!/bin/sh
exec >/dev/ttyAMA0 2>&1
set -eu
trap 'systemctl --no-block poweroff' EXIT
mkdir /run/audit-guest
mount -t squashfs -o loop,ro,nodev,nosuid /usr/lib/oblivion/vm/session/root.squashfs /run/audit-guest
mkdir /run/audit-client
chown 1000:1000 /run/audit-client
export PATH=/run/audit-guest/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PYTHONHOME=/run/audit-guest/usr
export PYTHONDONTWRITEBYTECODE=1
export LD_LIBRARY_PATH=/run/audit-guest/usr/lib/aarch64-linux-gnu
python3 /usr/libexec/vm-chat-powerloss.py
PROBE
chmod 0755 "${rootmnt:-/root}/usr/libexec/oblivion-crash-probe"
cat > "${rootmnt:-/root}/etc/systemd/system/oblivion-crash-probe.service" <<'UNIT'
[Unit]
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/usr/libexec/oblivion-crash-probe
TimeoutStartSec=180
UNIT
ln -s ../oblivion-crash-probe.service "${rootmnt:-/root}/etc/systemd/system/multi-user.target.wants/oblivion-crash-probe.service"
''')
    hook.chmod(0o755)
    (hook.parent/'ORDER').write_bytes(order+b'\n/scripts/init-bottom/zz-oblivion-crash-test "$@"\n')
    archive = subprocess.check_output(['bsdtar', '--format=newc', '--uid=0', '--gid=0', '-cf', '-', 'scripts'], cwd=root)
(output/'probe-initrd').write_bytes(initrd+gzip.compress(archive, mtime=0))
with (output/'synthetic.raw').open('xb') as file:
    file.truncate(512*1024*1024)
command = ['qemu-system-aarch64', '-machine', 'virt', '-accel', 'hvf', '-cpu', 'host', '-m', '2048', '-smp', '2',
    '-nodefaults', '-no-reboot', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-nic', 'none',
    '-kernel', str(output/'live/vmlinuz'), '-initrd', str(output/'probe-initrd'),
    '-append', 'boot=live live-media=/dev/vda components nopersistence noeject nonetworking ip=off pstore.backend=none efi_pstore.pstore_disable=1 systemd.mask=systemd-pstore.service systemd.mask=oblivion-controller.service systemd.getty_auto=no console=ttyAMA0',
    '-drive', f'file={iso},format=raw,if=virtio,readonly=on',
    '-drive', f'file={output}/synthetic.raw,format=raw,if=virtio,cache=none', '-device', 'virtio-rng-pci']
cut = False
with (output/'before.log').open('xb') as log, subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
    try:
        deadline = time.monotonic()+180
        data = b''
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if not selector.select(1):
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                log.write(chunk)
                data = (data+chunk)[-131072:]
                if b'OBLIVION_POWERLOSS_CUT_NOW' in data:
                    process.kill()
                    cut = True
                    break
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
assert cut, 'commit boundary not reached; inspect before.log'
with (output/'after.log').open('xb') as log:
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=180)
serial = (output/'after.log').read_text(errors='replace')
markers = [b'OBLIVION_POWERLOSS_CHAT_91e38', b'synthetic-powerloss-password']
leaks = []
with (output/'synthetic.raw').open('rb') as file:
    tail = b''
    while chunk := file.read(1024*1024):
        leaks.extend(marker.decode() for marker in markers if marker in tail+chunk)
        tail = chunk[-128:]
with iso.open('rb') as file:
    digest = hashlib.file_digest(file, 'sha256').hexdigest()
report = {'scope': __doc__.strip(), 'iso_sha256': digest, 'outer_vm_killed_after_commit': cut,
    'fixture_sha256': hashlib.sha256((scripts/'vm-chat-powerloss.py').read_bytes()).hexdigest(),
    'storage_helper_sha256': hashlib.sha256((scripts.parent.parent/'packages/oblivion-host/guest/chat-database.py').read_bytes()).hexdigest(),
    'passed': result.returncode == 0 and 'OBLIVION_POWERLOSS_PASS' in serial and not leaks,
    'plaintext_markers': leaks, 'checks': [line for line in serial.splitlines() if line.startswith('PASS:')]}
(output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
assert report['passed']
