#!/usr/bin/python3 -I
"""List unused USB block devices from the Debian Live host namespace."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


LIVE_MOUNTS = ('/run/live/medium', '/lib/live/mount/medium')
MAX_DEVICES = 64
MAX_SECTORS = (2**53 - 1) // 512


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
        found.append({'id': device_id, 'name': leaf.name, 'bytes': sectors * 512, 'read_only': read_only})

    if int(attribute(disk / 'diskseq')) != generation:
        return []
    return found


def list_media(proc=Path('/proc'), sysfs=Path('/sys'), dev=Path('/dev'), stat_path=Path.stat):
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
    return sorted(devices, key=lambda device: device['name'])[:MAX_DEVICES]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('list',))
    parser.parse_args()
    try:
        devices = list_media()
    except (OSError, UnicodeError):
        parser.exit(1, 'live_media_observation_failed\n')
    except ValueError as error:
        parser.exit(1, f'{error}\n')
    print(json.dumps({'version': 1, 'devices': devices}, separators=(',', ':')))


if __name__ == '__main__':
    main()
