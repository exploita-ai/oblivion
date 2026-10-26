#!/usr/bin/env python3
"""Three real power cycles with a disposable USB copy; never pass a host device."""
import argparse
import gzip
import hashlib
import json
import platform
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import zlib

parser=argparse.ArgumentParser()
parser.add_argument('--image',type=Path,required=True)
parser.add_argument('--iso',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--bundle',type=Path,help='Verified current host binaries, overlaid only in laboratory RAM')
parser.add_argument('--fixture',type=Path,help='Current laboratory fixture, overlaid only in RAM')
args=parser.parse_args()
assert platform.system()=='Darwin' and platform.machine()=='arm64', 'Mac ARM/HVF required'
image=args.image.resolve()
iso=args.iso.resolve()
output=args.output.resolve()
assert iso.is_file() and not iso.is_symlink()
assert all(',' not in str(path) for path in [image,iso,output])

def digest(path):
    with path.open('rb') as file:return hashlib.file_digest(file,'sha256').hexdigest()

for line in (image/'SHA256SUMS').read_text().splitlines():
    expected,name=line.split()
    assert Path(name).name==name and digest(image/name)==expected
output.mkdir(parents=True,exist_ok=False)
bundle=args.bundle.resolve() if args.bundle else image/'host'
for line in (bundle/'SHA256SUMS').read_text().splitlines():
    expected,name=line.split()
    assert Path(name).name==name and digest(bundle/name)==expected
fixture=args.fixture.resolve() if args.fixture else image/'vm-persistence-test.py'
initrd=image/'initrd'
if args.bundle or args.fixture:
    order=None
    for header in re.finditer(b'\x1f\x8b\x08',initrd.read_bytes()):
        try:archive=gzip.decompress(initrd.read_bytes()[header.start():])
        except (zlib.error,EOFError,gzip.BadGzipFile):continue
        order=subprocess.check_output(['bsdtar','-xOf','-','scripts/init-bottom/ORDER'],input=archive)
        break
    assert order is not None
    with tempfile.TemporaryDirectory(prefix='oblivion-usb-lab-') as temporary:
        root=Path(temporary)
        (root/'scripts/init-bottom').mkdir(parents=True)
        (root/'scripts/usb-test.py').write_bytes(fixture.read_bytes())
        (root/'scripts/usb-host').mkdir()
        for name in ['oblivion-storage','oblivion-control','oblivion-manager']:
            shutil.copy2(bundle/name,root/'scripts/usb-host'/name)
        hook=root/'scripts/init-bottom/zz-oblivion-usb-lab'
        hook.write_text('#!/bin/sh\nset -eu\ncase "${1:-}" in prereqs) exit 0;; esac\n'
            'mount --bind /scripts/usb-test.py "${rootmnt:-/root}/usr/libexec/oblivion-vm-test"\n'
            'mkdir /run/oblivion-usb-bundle\nmount -t tmpfs -o mode=0755,nodev,nosuid,size=16m tmpfs /run/oblivion-usb-bundle\n'
            'cp -a /scripts/usb-host/. /run/oblivion-usb-bundle/\nmount -o remount,ro /run/oblivion-usb-bundle\n'
            'for binary in oblivion-storage oblivion-control oblivion-manager; do\n'
            ' mount --bind "/run/oblivion-usb-bundle/$binary" "${rootmnt:-/root}/usr/bin/$binary"\ndone\n')
        hook.chmod(0o755)
        (hook.parent/'ORDER').write_bytes(order+b'\n/scripts/init-bottom/zz-oblivion-usb-lab "$@"\n')
        archive=subprocess.check_output(['bsdtar','--format=newc','--uid=0','--gid=0','-cf','-','scripts'],cwd=root)
    initrd=output/'lab-initrd'
    initrd.write_bytes((image/'initrd').read_bytes()+gzip.compress(archive,mtime=0))
usb=output/'usb.raw'
shutil.copyfile(iso,usb)
with usb.open('r+b') as file:file.truncate(max(3*1024**3,iso.stat().st_size+1024**3))
foreign=output/'foreign.raw'
with foreign.open('xb') as file:
    file.write(b'OBLIVION_FOREIGN_DISK_MUST_NOT_CHANGE')
    file.truncate(32*1024**2)
foreign_hash=digest(foreign)
def boot_unchanged():
    # GPT headers/backup and the protective MBR size change when growing the
    # disk. GRUB boot code, existing GPT entries and ISO payload must not.
    with iso.open('rb') as original, usb.open('rb') as prepared:
        assert original.read(446)==prepared.read(446), 'MBR boot code changed'
        original.seek(1024); prepared.seek(1024)
        assert original.read(4*128)==prepared.read(4*128), 'boot partition entries changed'
        original.seek(32768); prepared.seek(32768)
        while chunk:=original.read(4*1024**2):
            assert chunk==prepared.read(len(chunk)), 'ISO boot payload changed'
    return True
report={'scope':'production storage controller and manager, real USB/GPT/LUKS in offline ARM/HVF lab; no physical USB or full live ISO boot',
    'iso_sha256':digest(iso),'storage_sha256':digest(bundle/'oblivion-storage'),
    'bundle_manifest_sha256':digest(bundle/'SHA256SUMS'),
    'fixture_sha256':digest(fixture),'phases':[]}
markers=[b'oblivion-usb-general-canary-82ab',b'oblivion-usb-session-canary-91cd',
    b'OBLIVION_USB_API_CANARY_46c1',b'OBLIVION_USB_WIFI_CANARY_f81a',b'OBLIVION_USB_DOCUMENT_CANARY_44d7']
for phase in ['prepare','reopen','readonly']:
    before=digest(usb) if phase=='readonly' else None
    command=['qemu-system-aarch64','-machine','virt','-accel','hvf','-cpu','host',
        '-m','2048','-smp','2','-nodefaults','-no-reboot','-display','none','-monitor','none','-serial','stdio','-nic','none',
        '-kernel',str(image/'kernel'),'-initrd',str(initrd),
        '-append','console=ttyAMA0 root=/dev/vda rootfstype=squashfs ro panic=-1 systemd.getty_auto=no systemd.show_status=false oblivion.phase='+phase,
        '-drive',f'file={image / "host.squashfs"},format=raw,if=none,id=root,readonly=on','-device','virtio-blk-pci,drive=root',
        '-device','qemu-xhci,id=xhci','-drive',f'file={usb},format=raw,if=none,id=usb,cache=none',
        '-device','usb-storage,drive=usb,bus=xhci.0',
        '-drive',f'file={foreign},format=raw,if=none,id=foreign,cache=none','-device','virtio-blk-pci,drive=foreign']
    started=time.monotonic()
    with (output/(phase+'.log')).open('xb') as log:
        result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,timeout=300)
    text=(output/(phase+'.log')).read_text(errors='replace')
    passed=result.returncode==0 and 'OBLIVION_PERSISTENCE_PASS '+phase in text
    assert digest(foreign)==foreign_hash,'foreign disk changed'
    found=set()
    with usb.open('rb') as file:
        previous=b''
        while chunk:=file.read(4*1024**2):
            found.update(m.decode() for m in markers if m in previous+chunk)
            previous=chunk[-128:]
    entry={'phase':phase,'passed':passed,'seconds':round(time.monotonic()-started,2),
        'checks':[x[6:] for x in text.splitlines() if x.startswith('PASS: ')],
        'plaintext_markers':sorted(found),'foreign_disk_unchanged':True,'boot_payload_unchanged':boot_unchanged(),'log_sha256':digest(output/(phase+'.log'))}
    if before:entry['entire_usb_unchanged']=before==digest(usb)
    report['phases'].append(entry)
    (output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(entry),flush=True)
    assert passed and not found and (not before or entry['entire_usb_unchanged']), 'USB lab phase failed; inspect local log'
    assert 'OBLIVION_PERSISTENCE_STORAGE_SHA256 '+report['storage_sha256'] in text
    assert 'OBLIVION_PERSISTENCE_FIXTURE_SHA256 '+report['fixture_sha256'] in text
report['passed']=True
report['usb_sha256']=digest(usb)
(output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
