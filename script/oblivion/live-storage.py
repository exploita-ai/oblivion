#!/usr/bin/python3
"""Authorize only a dedicated data partition on this Debian Live boot USB.

The outer OS never mounts the partition. Its first block carries the same
installation identity as a desktop RAW disk; the controller guest owns ext4 and
both LUKS layers. No caller-supplied device paths are accepted.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid


MIB = 1024 * 1024
MIN_BYTES = 4 * 1024**3
MAX_BYTES = 1024**4
RECORD = Path('/run/oblivion-live/storage.json')


def run(*args, input=None):
    return subprocess.run(args, input=input, check=True, stdin=subprocess.DEVNULL if input is None else None,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout


def nodes(entries):
    for entry in entries:
        yield entry
        yield from nodes(entry.get('children', []))


def plan(table, device_bytes, boot_device, device_number):
    """Use only free trailing sectors, without changing any existing partition."""
    sector = table['sectorsize']
    if table['label'] not in ('gpt', 'dos') or sector not in (512, 4096):
        raise ValueError('unsupported_live_partition_table')
    partitions = table.get('partitions', [])
    if not partitions or len(partitions) > 127:
        raise ValueError('invalid_live_partition_table')
    geometry = []
    for part in partitions:
        if type(part.get('start')) is not int or type(part.get('size')) is not int or part['start'] < 1 or part['size'] < 1:
            raise ValueError('invalid_live_partition_table')
        if not re.fullmatch(r'/dev/[A-Za-z0-9_-]+', part.get('node', '')):
            raise ValueError('invalid_live_partition_path')
        geometry.append({key: part[key] for key in ('node', 'start', 'size', 'type')})
    # Flashed hybrid ISOs retain the GPT backup at the image's old end. Moving
    # only that metadata is an explicit part of the reviewed preparation plan.
    last = device_bytes // sector - MIB // sector
    relocate = table['label'] == 'gpt' and table.get('lastlba', last) < last
    start = max(part['start'] + part['size'] for part in geometry)
    alignment = MIB // sector
    start = ((start + alignment - 1) // alignment) * alignment
    size = min(last - start, MAX_BYTES // sector)
    numbers = [int(re.search(r'(\d+)$', part['node'])[1]) for part in geometry]
    free = [number for number in range(1, 5 if table['label'] == 'dos' else 129) if number not in numbers]
    if not free or size * sector < MIN_BYTES:
        raise ValueError('insufficient_unallocated_live_space')
    value = {'version': 1, 'boot_device': boot_device, 'device_number': device_number,
             'table': table['label'], 'table_id': table.get('id'), 'sector_bytes': sector,
             'partitions': geometry, 'number': free[0], 'start': start, 'sectors': size,
             'bytes': size * sector, 'relocate_gpt_backup': relocate}
    value['plan_sha256'] = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return value


def boot_usb():
    if os.geteuid() != 0:
        raise ValueError('live_storage_requires_root_helper')
    if 'boot=live' not in Path('/proc/cmdline').read_text().split():
        raise ValueError('debian_live_boot_required')
    mounts = json.loads(run('/usr/bin/findmnt', '--json', '--output', 'SOURCE,TARGET'))['filesystems']
    media = [entry for entry in nodes(mounts) if entry.get('target') in ('/run/live/medium', '/lib/live/mount/medium')]
    if len(media) != 1:
        raise ValueError('one_live_boot_medium_required')
    source = Path(media[0]['source'])
    if not source.is_absolute() or not stat.S_ISBLK(source.stat().st_mode):
        raise ValueError('physical_live_usb_required')
    listing = json.loads(run('/usr/bin/lsblk', '--json', '--bytes', '--paths', '--output',
                             'NAME,TYPE,PKNAME,TRAN,SIZE,RO,MAJ:MIN,PARTLABEL'))['blockdevices']
    flat = list(nodes(listing))
    source_info = source.stat()
    source_number = f'{os.major(source_info.st_rdev)}:{os.minor(source_info.st_rdev)}'
    entry = next((item for item in flat if item['maj:min'] == source_number), None)
    if entry is None:
        raise ValueError('live_boot_device_unavailable')
    while entry.get('pkname'):
        entry = next((item for item in flat if item['name'] == entry['pkname']), None)
        if entry is None:
            raise ValueError('live_boot_device_unavailable')
    if entry['type'] != 'disk' or entry.get('tran') != 'usb' or entry['ro']:
        raise ValueError('writable_boot_usb_required')
    path = Path(entry['name'])
    if not stat.S_ISBLK(path.stat().st_mode):
        raise ValueError('live_boot_device_unavailable')
    table = json.loads(run('/usr/sbin/sfdisk', '--json', str(path)))['partitiontable']
    if table['device'] != str(path):
        raise ValueError('live_partition_table_changed')
    return entry, table, flat


def identity(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb', buffering=0) as source:
        if not stat.S_ISBLK(os.fstat(source.fileno()).st_mode):
            raise ValueError('live_partition_required')
        first = source.read(4096)
    marker = re.fullmatch(rb'OBLIVION-RUNTIME-1\n([a-f0-9]{32})\n\x00*', first)
    if marker:
        return marker[1].decode()
    if len(first) == 4096 and first[1080:1082] == b'\x53\xef' and first[1144:1160] == b'OBLIVION-RUNTIME':
        return uuid.UUID(bytes=first[1128:1144]).hex
    return None


def review():
    device, table, listing = boot_usb()
    candidates = []
    for part in table['partitions']:
        native = next((item for item in listing if item['name'] == part['node']), None)
        if native is None:
            raise ValueError('live_partition_unavailable')
        identifier = identity(part['node'])
        if identifier:
            if native.get('ro') or not MIN_BYTES <= part['size'] * table['sectorsize'] <= MAX_BYTES:
                raise ValueError('invalid_live_data_partition')
            candidates.append({'path': part['node'], 'runtime_id': identifier,
                               'device_number': native['maj:min'], 'bytes': native['size']})
        elif native.get('partlabel') == 'OBLIVION-DATA':
            raise ValueError('unrecognized_live_data_partition')
    if len(candidates) > 1:
        raise ValueError('ambiguous_live_data_partitions')
    if candidates:
        result = {'version': 1, 'boot_device': device['name'], 'existing': candidates[0]}
        result['plan_sha256'] = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return result
    return plan(table, device['size'], device['name'], device['maj:min'])


def authorize(value):
    path = Path(value['path'])
    info = path.lstat()
    number = f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}'
    if not stat.S_ISBLK(info.st_mode) or number != value['device_number'] or identity(path) != value['runtime_id']:
        raise ValueError('live_data_partition_changed')
    for row in Path('/proc/self/mountinfo').read_text().splitlines():
        if row.split()[2] == number:
            raise ValueError('live_data_partition_mounted')
    for row in Path('/proc/swaps').read_text().splitlines()[1:]:
        if os.stat(row.split()[0]).st_rdev == info.st_rdev:
            raise ValueError('live_data_partition_is_swap')
    os.chown(path, 1000, 1000)
    os.chmod(path, 0o600)
    RECORD.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if RECORD.exists():
        if json.loads(RECORD.read_text()) != {'version': 1, **value}:
            raise ValueError('live_storage_authorization_changed')
        return value
    descriptor = os.open(RECORD, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, 'w') as output:
        json.dump({'version': 1, **value}, output, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    return value


def append_partition(value):
    type_id = '0FC63DAF-8483-4772-8E79-3D69D8477DE4' if value['table'] == 'gpt' else '83'
    spec = f"start={value['start']}, size={value['sectors']}, type={type_id}"
    if value['table'] == 'gpt':
        spec += ', name="OBLIVION-DATA"'
    # The original starts/sizes stay fixed, including the mounted boot volume.
    if value['relocate_gpt_backup']:
        run('/usr/sbin/sfdisk', '--no-reread', '--no-tell-kernel', '--relocate', 'gpt-bak-std', value['boot_device'])
    # Add only the new partition to the kernel; rereading the entire USB table
    # would fail with EBUSY because Debian Live is using its boot partition.
    run('/usr/sbin/sfdisk', '--append', '--no-reread', '--no-tell-kernel', value['boot_device'], input=(spec + '\n').encode())
    table = json.loads(run('/usr/sbin/sfdisk', '--json', value['boot_device']))['partitiontable']
    original = {part['node']: part for part in value['partitions']}
    current = {part['node']: {key: part[key] for key in ('node', 'start', 'size', 'type')} for part in table['partitions']}
    if any(current.get(node) != part for node, part in original.items()) or len(current) != len(original) + 1:
        raise ValueError('live_partition_table_changed')
    added = [part for part in table['partitions'] if part['node'] not in original]
    if len(added) != 1 or added[0]['start'] != value['start'] or added[0]['size'] != value['sectors']:
        raise ValueError('live_partition_table_changed')
    return added[0]



def prepare(expected):
    value = review()
    if value['plan_sha256'] != expected:
        raise ValueError('live_storage_review_changed')
    if 'existing' in value:
        return authorize(value['existing'])
    added = append_partition(value)
    run('/usr/bin/partx', '--add', '--nr', str(value['number']), value['boot_device'])
    run('/usr/bin/udevadm', 'settle', '--timeout=10')
    path = Path(added['node'])
    metadata = path.lstat()
    if not stat.S_ISBLK(metadata.st_mode):
        raise ValueError('live_partition_unavailable')
    identifier = uuid.uuid4().hex
    descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'wb', buffering=0) as target:
        marker = f'OBLIVION-RUNTIME-1\n{identifier}\n'.encode()
        target.write(marker + bytes(4096 - len(marker)))
        os.fsync(target.fileno())
    return authorize({'path': str(path), 'runtime_id': identifier,
                      'device_number': f'{os.major(metadata.st_rdev)}:{os.minor(metadata.st_rdev)}',
                      'bytes': value['bytes']})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('review', 'prepare'))
    parser.add_argument('plan_sha256', nargs='?')
    args = parser.parse_args()
    if args.operation == 'review' and args.plan_sha256 is None:
        return review()
    if args.operation == 'prepare' and args.plan_sha256 and re.fullmatch('[a-f0-9]{64}', args.plan_sha256):
        RECORD.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        descriptor = os.open(RECORD.parent / 'prepare.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return prepare(args.plan_sha256)
    raise ValueError('invalid_live_storage_command')


if __name__ == '__main__':
    try:
        print(json.dumps(main(), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(str(error) if isinstance(error, ValueError) else 'live_storage_operation_failed', file=sys.stderr)
        sys.exit(1)
