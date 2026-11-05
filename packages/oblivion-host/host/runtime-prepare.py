#!/usr/bin/python3
"""Prepare the dedicated data disk of the native launcher's Debian runtime."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

SCSI_CLASS = '{ba6163d9-04a1-4d29-b605-72e2ffb1dc7f}'
INITIALIZATION = Path('/run/oblivion-runtime-auth/new-disk')


def run(*arguments, pass_fds=()):
    return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          pass_fds=pass_fds).stdout


def profile(arguments):
    if 'oblivion.runtime=1' not in arguments:
        raise RuntimeError('native_runtime_required')
    backends = [value.split('=', 1)[1] for value in arguments if value.startswith('oblivion.runtime-backend=')]
    if len(backends) != 1 or backends[0] not in ('apple-vz', 'qemu-kvm', 'hcs-hyperv'):
        raise RuntimeError('runtime_backend_profile_required')
    identities = [value.split('=', 1)[1] for value in arguments if value.startswith('oblivion.runtime-id=')]
    if len(identities) != 1 or len(identities[0]) != 32 or any(char not in '0123456789abcdef' for char in identities[0]):
        raise RuntimeError('runtime_identity_required')
    return backends[0], uuid.UUID(hex=identities[0])


def select_disk(backend, identity, sysfs=Path('/sys')):
    blocks = sysfs / 'class/block'
    if backend in ('apple-vz', 'qemu-kvm'):
        system = blocks / 'vdb'
        if 'virtio' not in str((system / 'device').resolve(strict=True)):
            raise RuntimeError('runtime_virtio_disk_required')
    elif backend == 'hcs-hyperv':
        # HCS Devices.Scsi keys which are GUIDs become channel instance IDs;
        # Attachments keys are LUNs (Microsoft HCS schema). Linux vmbus_drv.c
        # exposes if_instance as device_id; storvsc_drv.c registers the SCSI
        # host beneath that VMBus device and sends the SCSI device's LUN.
        # This pins the configured controller and data LUN, not an sdX name.
        controller = (sysfs / 'bus/vmbus/devices' / str(identity)).resolve(strict=True)
        if (controller / 'device_id').read_text().strip() != '{' + str(identity) + '}' or (controller / 'class_id').read_text().strip() != SCSI_CLASS:
            raise RuntimeError('runtime_scsi_controller_required')
        if (controller / 'driver').resolve(strict=True) != (sysfs / 'bus/vmbus/drivers/hv_storvsc').resolve(strict=True):
            raise RuntimeError('runtime_scsi_controller_required')
        candidates = []
        for entry in blocks.iterdir():
            if not re.fullmatch(r'sd[a-z]+', entry.name) or (entry / 'partition').exists():
                continue
            scsi = (entry / 'device').resolve(strict=True)
            address = re.fullmatch(r'([0-9]+):0:0:1', scsi.name)
            if not address or scsi.parent.name != f'target{address[1]}:0:0' or scsi.parent.parent.name != f'host{address[1]}' or scsi.parent.parent.parent != controller:
                continue
            if (scsi / 'type').read_text().strip() != '0' or entry.resolve(strict=True) != scsi / 'block' / entry.name:
                continue
            candidates.append(entry)
        if len(candidates) != 1:
            raise RuntimeError('runtime_scsi_disk_required')
        system = candidates[0]
    else:
        raise RuntimeError('runtime_backend_profile_required')
    size = int((system / 'size').read_text()) * 512
    if (system / 'ro').read_text().strip() != '0' or (system / 'partition').exists() or any((entry / 'partition').exists() for entry in system.iterdir()) or any((system / 'holders').iterdir()) or not 4 * 1024**3 <= size <= 1024**4:
        raise RuntimeError('invalid_runtime_disk')
    return system, size


def device_metadata(device, system):
    metadata = device.lstat()
    if not stat.S_ISBLK(metadata.st_mode):
        raise RuntimeError('runtime_block_device_required')
    if (system / 'dev').read_text().strip() != f'{os.major(metadata.st_rdev)}:{os.minor(metadata.st_rdev)}':
        raise RuntimeError('runtime_block_device_mismatch')
    return metadata


def disk_marker(identity):
    marker = f'OBLIVION-RUNTIME-1\n{identity.hex}\n'.encode('ascii')
    return marker + bytes(4096 - len(marker))


def consume_authority(backend, identity, size, authority, required=False):
    if required and backend != 'hcs-hyperv':
        raise RuntimeError('runtime_disk_identity_mismatch')
    try:
        authorization = os.open(authority, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        if required:
            raise RuntimeError('runtime_disk_identity_mismatch') from None
        return False
    try:
        if backend != 'hcs-hyperv':
            raise RuntimeError('runtime_disk_identity_mismatch')
        info = os.fstat(authorization)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= 512):
            raise RuntimeError('invalid_runtime_data_authority')
        data = json.loads(os.read(authorization, 513))
        if (type(data) is not dict or type(data.get('bytes')) is not int
                or data != {'kind': 'new-disk', 'runtime_id': identity.hex, 'bytes': size}):
            raise RuntimeError('invalid_runtime_data_authority')
        os.unlink(authority)
        return True
    finally:
        os.close(authorization)


def initialize_blank_disk(fd, backend, identity, size, authority):
    # Blank origin is attested by the host's SDK-created, privately pinned disk
    # and durable pending ticket. This head check is not an all-device scan.
    if os.pread(fd, 4096, 0) != bytes(4096):
        raise RuntimeError('runtime_disk_identity_mismatch')
    consume_authority(backend, identity, size, authority, required=True)
    marker = disk_marker(identity)
    written = 0
    while written < len(marker):
        count = os.pwrite(fd, marker[written:], written)
        if count <= 0:
            raise RuntimeError('runtime_disk_marker_write_failed')
        written += count
    os.fsync(fd)


def format_check(fd, backend, identity, size, authority):
    # Pass the reviewed open object, never a re-resolved /dev spelling. mke2fs
    # opens this procfd with O_EXCL itself; the parent must not claim O_EXCL.
    # https://github.com/tytso/e2fsprogs/blob/master/lib/ext2fs/unix_io.c
    # https://github.com/tytso/e2fsprogs/blob/master/misc/mke2fs.c
    device = f'/proc/self/fd/{fd}'
    probe = subprocess.run(['/usr/sbin/blkid', '-p', '-o', 'export', device],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, check=False, pass_fds=(fd,))
    if probe.returncode == 2:
        if os.pread(fd, 4096, 0) != disk_marker(identity):
            initialize_blank_disk(fd, backend, identity, size, authority)
        else:
            # Pending setup may authenticate again after the marker was made
            # durable. Validate and consume that per-boot capability as well.
            consume_authority(backend, identity, size, authority)
        run('/usr/sbin/mkfs.ext4', '-q', '-m', '0', '-L', 'OBLIVION-RUNTIME',
            '-U', str(identity), device, pass_fds=(fd,))
    elif probe.returncode == 0:
        values = dict(line.split('=', 1) for line in probe.stdout.decode().splitlines() if '=' in line)
        if values.get('TYPE') != 'ext4' or values.get('LABEL') != 'OBLIVION-RUNTIME' or values.get('UUID') != str(identity):
            raise RuntimeError('runtime_disk_identity_mismatch')
        consume_authority(backend, identity, size, authority)
        checked = subprocess.run(['/usr/sbin/e2fsck', '-p', device],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, check=False, pass_fds=(fd,))
        if checked.returncode not in (0, 1):
            raise RuntimeError('runtime_filesystem_recovery_required')
    else:
        raise RuntimeError('runtime_disk_probe_failed')


def readonly_disk(fd):
    # Linux filesystem mounts may restrict other writable block-device opens.
    # Retain the exact object with a read-only pin before releasing the writer.
    # https://github.com/torvalds/linux/blob/v6.12/include/linux/blkdev.h
    reviewed = os.fstat(fd)
    reader = os.open(f'/proc/self/fd/{fd}', os.O_RDONLY | os.O_CLOEXEC)
    opened = os.fstat(reader)
    if (opened.st_dev, opened.st_ino, opened.st_rdev) != (reviewed.st_dev, reviewed.st_ino, reviewed.st_rdev):
        os.close(reader)
        raise RuntimeError('runtime_block_device_mismatch')
    return reader


def mount_disk(fd, destination):
    # mount(8) otherwise canonicalizes procfd back to a mutable pathname. Do
    # not delegate to mount.type helpers, which do not inherit this option.
    # https://github.com/util-linux/util-linux/blob/master/sys-utils/mount.8.adoc
    run('/usr/bin/mount', '--no-canonicalize', '--internal-only', '-t', 'ext4',
        '-o', 'nodev,nosuid,noexec', f'/proc/self/fd/{fd}', str(destination), pass_fds=(fd,))


def prepare():
    if os.geteuid() != 0:
        raise RuntimeError('root_required')
    backend, identity = profile(Path('/proc/cmdline').read_text().split())
    system, size = select_disk(backend, identity)
    device = Path('/dev') / system.name
    metadata = device_metadata(device, system)
    # Compare device numbers, not path spellings, so an alias cannot conceal an
    # existing mount or swap area. A runtime disk is dedicated to this service.
    major_minor = f'{os.major(metadata.st_rdev)}:{os.minor(metadata.st_rdev)}'
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        if line.split()[2] == major_minor:
            raise RuntimeError('runtime_disk_already_mounted')
    for line in Path('/proc/swaps').read_text().splitlines()[1:]:
        if os.stat(line.split()[0]).st_rdev == metadata.st_rdev:
            raise RuntimeError('runtime_disk_is_swap')
    fd = os.open(device, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISBLK(opened.st_mode) or opened.st_rdev != metadata.st_rdev
                or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)):
            raise RuntimeError('runtime_block_device_mismatch')
        format_check(fd, backend, identity, size, INITIALIZATION)
        reader = readonly_disk(fd)
    finally:
        os.close(fd)
    try:
        destination = Path('/var/lib/oblivion')
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        mount_disk(reader, destination)
    finally:
        os.close(reader)
    destination.chmod(0o700)
    config = json.loads(Path('/etc/oblivion/controller.json').read_text())
    config.update(general_image=str(destination / 'general.luks'),
                  general_mib=min(1024 * 1024, size // (1024 * 1024) - 512),
                  session_mib=2048, ephemeral_mib=512)
    runtime = Path('/run/oblivion-runtime')
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime.chmod(0o700)
    fd = os.open(runtime / 'controller.json', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(config, output)
        output.write('\n')


if __name__ == '__main__':
    try:
        prepare()
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError):
        print('native_runtime_prepare_failed', file=sys.stderr)
        sys.exit(1)
