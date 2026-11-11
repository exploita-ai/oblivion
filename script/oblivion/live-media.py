#!/usr/bin/python3 -I
"""Inspect and lease unused USB block devices from the Debian Live host."""

import argparse
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct


LIVE_MOUNTS = ('/run/live/medium', '/lib/live/mount/medium')
LIVE_UID = 1000
INSTALLATION = Path('/etc/oblivion/installation.json')
NATIVE_HELPER = Path('/usr/lib/oblivion/desktop/bin/oblivion-vm')
MAX_PROFILE_BYTES = 1024
MAX_DEVICES = 64
MAX_SECTORS = (2**53 - 1) // 512
# Linux uapi/linux/fs.h, with the native 64-bit ABI used on amd64 and arm64.
BLKROGET = 0x125e
BLKGETSIZE64 = 0x80081272
BLKGETDISKSEQ = 0x80081280


@dataclass(frozen=True)
class ObservedMedia:
    id: str
    name: str
    bytes: int
    read_only: bool
    major_minor: str
    diskseq: int

    def public(self):
        return {'id': self.id, 'name': self.name, 'bytes': self.bytes, 'read_only': self.read_only}


def attribute(path):
    return path.read_text(encoding='ascii').strip()


def number(value):
    if not re.fullmatch(r'[0-9]+:[0-9]+', value):
        raise ValueError('invalid_block_device_number')
    return value


def device_number(value):
    return f'{os.major(value)}:{os.minor(value)}'


def kernel_path(value):
    return re.sub(r'\\(040|011|012|134)', lambda match: chr(int(match[1], 8)), value)


def mounts_and_swaps(proc, sysfs, stat_path):
    boot = []
    used = set()
    for line in (proc / 'self/mountinfo').read_text(errors='surrogateescape').split('\n'):
        if not line:
            continue
        mount, separator, filesystem = line.partition(' - ')
        fields = mount.split()
        fs_fields = filesystem.split()
        if not separator or len(fields) < 6 or len(fs_fields) != 3:
            raise ValueError('invalid_live_mountinfo')
        major_minor = number(fields[2])
        used.add(major_minor)
        if fields[4] in LIVE_MOUNTS:
            boot.append(major_minor)
        # A FUSE mount can have an anonymous superblock and a block source.
        source = kernel_path(fs_fields[1])
        if source.startswith('/dev/'):
            try:
                info = stat_path(Path(source))
            except FileNotFoundError:
                continue
            if stat.S_ISBLK(info.st_mode):
                used.add(device_number(info.st_rdev))

    # A mounted multi-device Btrfs filesystem may name only one block source.
    try:
        btrfs_filesystems = list((sysfs / 'fs/btrfs').iterdir())
    except FileNotFoundError:
        btrfs_filesystems = []
    for filesystem in btrfs_filesystems:
        if not re.fullmatch(r'[0-9a-f-]{36}', filesystem.name):
            continue
        try:
            members = list((filesystem / 'devices').iterdir())
        except FileNotFoundError:
            continue
        for member in members:
            used.add(number(attribute(member / 'dev')))

    swaps = (proc / 'swaps').read_text(errors='surrogateescape').split('\n')
    if not swaps or swaps[0].split() != ['Filename', 'Type', 'Size', 'Used', 'Priority']:
        raise ValueError('invalid_live_swaps')
    for line in swaps[1:]:
        if not line:
            continue
        fields = line.split()
        if len(fields) != 5 or not fields[0].startswith('/'):
            raise ValueError('invalid_live_swaps')
        info = stat_path(Path(kernel_path(fields[0])))
        if stat.S_ISBLK(info.st_mode):
            used.add(device_number(info.st_rdev))
        elif stat.S_ISREG(info.st_mode):
            used.add(device_number(info.st_dev))
        else:
            raise ValueError('invalid_live_swaps')
    return boot, used


def block(sysfs, major_minor):
    path = (sysfs / 'dev/block' / number(major_minor)).resolve(strict=True)
    root = sysfs / 'devices'
    if not path.is_relative_to(root) or attribute(path / 'dev') != major_minor:
        raise ValueError('invalid_block_device_path')
    return path


def has_type(path, kind):
    # Partition labels may contain Unicode and are outside this observation.
    return f'DEVTYPE={kind}'.encode('ascii') in (path / 'uevent').read_bytes().split(b'\n')


def usb_identity(sysfs, disk):
    for ancestor in disk.parents:
        if ancestor == sysfs / 'devices':
            break
        try:
            subsystem = (ancestor / 'subsystem').resolve(strict=True)
        except FileNotFoundError:
            continue
        if subsystem == sysfs / 'bus/usb' and has_type(ancestor, 'usb_device'):
            bus = int(attribute(ancestor / 'busnum'))
            address = int(attribute(ancestor / 'devnum'))
            vendor = attribute(ancestor / 'idVendor')
            product = attribute(ancestor / 'idProduct')
            if (bus < 1 or not 1 <= address <= 127
                    or not all(re.fullmatch(r'[0-9a-f]{4}', value) for value in (vendor, product))):
                raise ValueError('invalid_usb_identity')
            return [str(ancestor.relative_to(sysfs)), bus, address, vendor, product]
    return None


def inspect_disk(sysfs, dev, disk, used, boot_id, stat_path):
    if any((disk / 'slaves').iterdir()):
        return []
    usb = usb_identity(sysfs, disk)
    if usb is None:
        return []
    generation = int(attribute(disk / 'diskseq'))
    disk_size = int(attribute(disk / 'size'))
    disk_ro = attribute(disk / 'ro')
    if generation < 1 or not 1 <= disk_size <= MAX_SECTORS or disk_ro not in ('0', '1'):
        raise ValueError('invalid_usb_disk_metadata')

    parts = [entry for entry in disk.iterdir() if (entry / 'partition').is_file()]
    disk_number = number(attribute(disk / 'dev'))
    for member in (disk, *parts):
        if attribute(member / 'dev') in used or any((member / 'holders').iterdir()):
            return []

    found = []
    for leaf in parts or [disk]:
        major_minor = number(attribute(leaf / 'dev'))
        if block(sysfs, major_minor) != leaf or not re.fullmatch(r'[A-Za-z0-9_-]{1,63}', leaf.name):
            raise ValueError('invalid_usb_device_leaf')
        info = stat_path(dev / leaf.name, follow_symlinks=False)
        if not stat.S_ISBLK(info.st_mode) or device_number(info.st_rdev) != major_minor:
            raise ValueError('invalid_usb_device_node')

        start = 0
        sectors = disk_size
        read_only = disk_ro == '1'
        if leaf != disk:
            if not has_type(leaf, 'partition'):
                raise ValueError('invalid_usb_partition_type')
            start = int(attribute(leaf / 'start'))
            sectors = int(attribute(leaf / 'size'))
            leaf_ro = attribute(leaf / 'ro')
            if start < 0 or sectors < 1 or start + sectors > disk_size or leaf_ro not in ('0', '1'):
                raise ValueError('invalid_usb_partition_geometry')
            read_only = read_only or leaf_ro == '1'

        identity = [1, boot_id, usb, str(disk.relative_to(sysfs)), disk_number, generation, disk_size,
                    leaf.name, major_minor, start, sectors, read_only]
        device_id = hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode('ascii')).hexdigest()
        found.append(ObservedMedia(device_id, leaf.name, sectors * 512, read_only, major_minor, generation))

    if int(attribute(disk / 'diskseq')) != generation:
        return []
    return found


def observe_media(proc, sysfs, dev, stat_path):
    if 'boot=live' not in (proc / 'cmdline').read_text().split():
        raise ValueError('debian_live_boot_required')
    boot_id = attribute(proc / 'sys/kernel/random/boot_id')
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot_id):
        raise ValueError('invalid_live_boot_id')
    boot, used = mounts_and_swaps(proc, sysfs, stat_path)
    if len(boot) != 1:
        raise ValueError('one_live_boot_medium_required')
    boot_disk = block(sysfs, boot[0])
    if has_type(boot_disk, 'partition'):
        boot_disk = boot_disk.parent
    if (boot_disk.is_relative_to(sysfs / 'devices/virtual') or not has_type(boot_disk, 'disk')
            or any((boot_disk / 'slaves').iterdir())):
        raise ValueError('physical_live_boot_medium_required')

    devices = []
    for entry in (sysfs / 'dev/block').iterdir():
        try:
            disk = block(sysfs, entry.name)
            if disk == boot_disk or disk.is_relative_to(sysfs / 'devices/virtual') or not has_type(disk, 'disk'):
                continue
            devices.extend(inspect_disk(sysfs, dev, disk, used, boot_id, stat_path))
        except (OSError, ValueError):
            # A disappearing or partially observed disk cannot be offered.
            continue
    return sorted(devices, key=lambda device: device.name)[:MAX_DEVICES]


def list_media(proc=Path('/proc'), sysfs=Path('/sys'), dev=Path('/dev'), stat_path=Path.stat):
    return [device.public() for device in observe_media(proc, sysfs, dev, stat_path)]


def block_u64(fd, request):
    return struct.unpack('=Q', fcntl.ioctl(fd, request, bytes(8)))[0]


def open_media(direction, device_id, proc=Path('/proc'), sysfs=Path('/sys'), dev=Path('/dev'), stat_path=Path.stat):
    """Return an exclusively held block FD and its public selection metadata."""
    access = {'import': os.O_RDONLY, 'export': os.O_RDWR}.get(direction)
    if access is None:
        raise ValueError('invalid_live_media_direction')
    if not isinstance(device_id, str) or not re.fullmatch(r'[0-9a-f]{64}', device_id):
        raise ValueError('invalid_live_media_id')
    observed = observe_media(proc, sysfs, dev, stat_path)
    selected = next((device for device in observed if device.id == device_id), None)
    if selected is None:
        raise ValueError('live_media_unavailable')
    if direction == 'export' and selected.read_only:
        raise ValueError('live_media_read_only')

    fd = os.open(dev / selected.name, access | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISBLK(info.st_mode) or device_number(info.st_rdev) != selected.major_minor:
            raise ValueError('live_media_device_changed')
        # Refresh host use checks while the selected leaf is claimed, then
        # compare the descriptor's size and parent generation with the selection.
        if (selected not in observe_media(proc, sysfs, dev, stat_path)
                or block_u64(fd, BLKGETSIZE64) != selected.bytes
                or block_u64(fd, BLKGETDISKSEQ) != selected.diskseq):
            raise ValueError('live_media_device_changed')
        if direction == 'export' and fcntl.ioctl(fd, BLKROGET, bytes(4)) != bytes(4):
            raise ValueError('live_media_read_only')
    except BaseException:
        os.close(fd)
        raise
    return fd, selected.public()


def require_live_profile(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ValueError('unsafe_installation_profile')
        raw = source.read(MAX_PROFILE_BYTES + 1)
    if len(raw) > MAX_PROFILE_BYTES:
        raise ValueError('invalid_installation_profile')
    try:
        pairs = json.loads(raw.decode('utf-8'), object_pairs_hook=tuple)
    except ValueError:
        raise ValueError('invalid_installation_profile') from None
    if not isinstance(pairs, tuple) or len(pairs) != 2:
        raise ValueError('invalid_installation_profile')
    profile = dict(pairs)
    if profile != {'version': 1, 'mode': 'live-launcher'} or type(profile.get('version')) is not int:
        raise ValueError('invalid_installation_profile')


def lease_media(direction, device_id, peer, profile=INSTALLATION, helper=NATIVE_HELPER):
    if os.geteuid() != 0 or os.environ.get('SUDO_UID') != str(LIVE_UID):
        raise ValueError('live_media_lease_requires_live_sudo')
    require_live_profile(profile)
    if peer.family != socket.AF_UNIX or peer.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
        raise ValueError('invalid_live_media_lease_socket')
    peer.getpeername()
    credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('=iII'))
    pid, uid, _ = struct.unpack('=iII', credentials)
    if pid <= 0 or uid != LIVE_UID:
        raise ValueError('invalid_live_media_lease_peer')
    installed = helper.lstat()
    if (not stat.S_ISREG(installed.st_mode) or installed.st_uid != 0 or installed.st_mode & 0o022
            or not os.path.samestat(installed, Path(f'/proc/{pid}/exe').stat())):
        raise ValueError('invalid_live_media_lease_peer')

    descriptor, _ = open_media(direction, device_id)
    try:
        rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('=i', descriptor))]
        if peer.sendmsg([b'M'], rights, socket.MSG_DONTWAIT) != 1:
            raise ValueError('live_media_lease_transfer_failed')
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('list')
    lease = commands.add_parser('lease')
    lease.add_argument('direction', choices=('import', 'export'))
    lease.add_argument('id')
    args = parser.parse_args()
    try:
        if args.command == 'list':
            print(json.dumps({'version': 1, 'devices': list_media()}, separators=(',', ':')))
            return
        with socket.socket(fileno=1) as peer:
            lease_media(args.direction, args.id, peer)
    except (OSError, UnicodeError):
        parser.exit(1, 'live_media_observation_failed\n')
    except ValueError as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
