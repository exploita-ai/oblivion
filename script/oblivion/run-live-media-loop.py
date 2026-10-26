#!/usr/bin/env python3
"""Verify Debian live-boot's zero-offset loop on a disposable prepared USB.

Direct kernel boot with a RAM-only diagnostic service: not a UEFI ISO test.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zlib

parser = argparse.ArgumentParser()
parser.add_argument('--iso', type=Path, required=True)
parser.add_argument('--usb', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
iso, usb, output = args.iso.resolve(), args.usb.resolve(), args.output.resolve()
assert iso.is_file() and usb.is_file()
assert all(',' not in str(p) for p in [iso, usb, output])
output.mkdir(parents=True, exist_ok=False)

def digest(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()

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
with tempfile.TemporaryDirectory(prefix='oblivion-live-loop-') as temporary:
    root = Path(temporary)
    (root/'scripts/init-bottom').mkdir(parents=True)
    hook = root/'scripts/init-bottom/zz-oblivion-loop-probe'
    hook.write_text('''#!/bin/sh
set -eu
case "${1:-}" in prereqs) exit 0;; esac
cat > "${rootmnt:-/root}/usr/libexec/oblivion-loop-probe" <<'PROBE'
#!/bin/sh
exec >/dev/ttyS0 2>&1
set -ex
trap 'systemctl --no-block poweroff' EXIT
source=$(findmnt -n -o SOURCE /run/live/medium)
case "$(findmnt -n -o FSTYPE /run/live/medium)" in iso9660|hfsplus) ;; *) exit 1;; esac
findmnt -n -o OPTIONS /run/live/medium | tr ',' '\\n' | grep -qx ro
test "$(cat /sys/block/${source##*/}/loop/offset)" = 0
backing=$(cat /sys/block/${source##*/}/loop/backing_file)
case "$backing" in /dev/sda|/dev/sda[1-4]) ;; *) exit 1;; esac
test -b /dev/sda5
echo OBLIVION_LIVE_LOOP_PASS
systemctl --no-block poweroff
PROBE
chmod 0755 "${rootmnt:-/root}/usr/libexec/oblivion-loop-probe"
cat > "${rootmnt:-/root}/etc/systemd/system/oblivion-loop-probe.service" <<'UNIT'
[Unit]
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/usr/libexec/oblivion-loop-probe
StandardOutput=journal+console
StandardError=journal+console
UNIT
ln -s ../oblivion-loop-probe.service "${rootmnt:-/root}/etc/systemd/system/multi-user.target.wants/oblivion-loop-probe.service"
''')
    hook.chmod(0o755)
    (hook.parent/'ORDER').write_bytes(order+b'\n/scripts/init-bottom/zz-oblivion-loop-probe "$@"\n')
    archive = subprocess.check_output(['bsdtar', '--format=newc', '--uid=0', '--gid=0', '-cf', '-', 'scripts'], cwd=root)
(output/'probe-initrd').write_bytes(initrd+gzip.compress(archive, mtime=0))
shutil.copyfile(usb, output/'usb.raw')
before = digest(output/'usb.raw')
with (output/'serial.log').open('xb') as log:
    result = subprocess.run(['qemu-system-x86_64', '-machine', 'q35', '-accel', 'tcg', '-cpu', 'max',
        '-m', '2048', '-smp', '2', '-nodefaults', '-no-reboot', '-display', 'none', '-monitor', 'none',
        '-serial', 'stdio', '-nic', 'none', '-kernel', str(output/'live/vmlinuz'), '-initrd', str(output/'probe-initrd'),
        '-append', 'boot=live live-media-offset=0 components nopersistence noeject nonetworking ip=off ipv6.disable=1 pstore.backend=none efi_pstore.pstore_disable=1 systemd.mask=systemd-pstore.service systemd.getty_auto=no console=ttyS0',
        '-device', 'qemu-xhci,id=xhci', '-drive', f'file={output / "usb.raw"},format=raw,if=none,id=usb,cache=none',
        '-device', 'usb-storage,drive=usb,bus=xhci.0'], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=180)
report = {'scope': 'actual Debian live-boot from existing amd64 ISO on prepared USB; direct kernel, injected RAM probe, no network; not UEFI or candidate ISO acceptance',
    'iso_sha256': digest(iso), 'usb_before_sha256': before, 'usb_after_sha256': digest(output/'usb.raw'),
    'runner_sha256': digest(Path(__file__)), 'log_sha256': digest(output/'serial.log'),
    'loop_boot_passed': result.returncode == 0 and 'OBLIVION_LIVE_LOOP_PASS' in (output/'serial.log').read_text(errors='replace')}
report['passed'] = report['loop_boot_passed'] and report['usb_before_sha256'] == report['usb_after_sha256']
(output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report), flush=True)
assert report['passed'], 'live-boot loop test failed'
