#!/usr/bin/python3
"""Prepare the dedicated data disk of the native launcher's Debian runtime."""
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import uuid

SCSI_CLASS = '{ba6163d9-04a1-4d29-b605-72e2ffb1dc7f}'
INITIALIZATION = Path('/run/oblivion-runtime-auth/new-disk')
DESTINATION = Path('/var/lib/oblivion')
RUNTIME = Path('/run/oblivion-runtime')
BLKROSET = 0x125d
BLKROGET = 0x125e
BLKGETDISKSEQ = 0x80081280
BACKING_COMMANDS = ('backing-status', 'backing-writable', 'backing-repair', 'backing-fence')


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


def select_disk(backend, identity, sysfs=Path('/sys'), *, allow_readonly=False):
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
    modes = ('0', '1') if allow_readonly else ('0',)
    if (system / 'ro').read_text().strip() not in modes or (system / 'partition').exists() or any((entry / 'partition').exists() for entry in system.iterdir()) or any((system / 'holders').iterdir()) or not 4 * 1024**3 <= size <= 1024**4:
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


def probe_disk(fd, identity):
    probe = subprocess.run(['/usr/sbin/blkid', '-p', '-o', 'export', f'/proc/self/fd/{fd}'],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, check=False, pass_fds=(fd,))
    if probe.returncode == 2:
        return 'blank' if os.pread(fd, 4096, 0) == disk_marker(identity) else 'unidentified'
    if probe.returncode != 0:
        raise RuntimeError('runtime_disk_probe_failed')
    values = dict(line.split('=', 1) for line in probe.stdout.decode().splitlines() if '=' in line)
    if values.get('TYPE') != 'ext4' or values.get('LABEL') != 'OBLIVION-RUNTIME' or values.get('UUID') != str(identity):
        raise RuntimeError('runtime_disk_identity_mismatch')
    # A clean state bit alone does not rule out journal replay or orphan cleanup.
    # https://docs.kernel.org/filesystems/ext4/super.html
    superblock = os.pread(fd, 1024, 1024)
    if len(superblock) != 1024:
        raise RuntimeError('runtime_disk_probe_failed')
    state, = struct.unpack_from('<H', superblock, 0x3a)
    incompat, ro_compat = struct.unpack_from('<II', superblock, 0x60)
    last_orphan, = struct.unpack_from('<I', superblock, 0xe8)
    if state != 1 or incompat & 0x4 or ro_compat & 0x10000 or last_orphan:
        return 'recovery-required'
    return 'readonly'


def make_filesystem(fd, identity):
    # mke2fs opens the pinned procfd with O_EXCL itself.
    run('/usr/sbin/mkfs.ext4', '-q', '-m', '0', '-L', 'OBLIVION-RUNTIME',
        '-U', str(identity), f'/proc/self/fd/{fd}', pass_fds=(fd,))


def check_filesystem(fd):
    checked = subprocess.run(['/usr/sbin/e2fsck', '-p', f'/proc/self/fd/{fd}'],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, check=False, pass_fds=(fd,))
    if checked.returncode not in (0, 1):
        raise RuntimeError('runtime_filesystem_recovery_required')


def format_check(fd, backend, identity, size, authority, *, require_authority=False):
    state = probe_disk(fd, identity)
    if state == 'unidentified':
        initialize_blank_disk(fd, backend, identity, size, authority)
    else:
        # Pending setup may authenticate again after the marker was made
        # durable. Validate and consume that per-boot capability as well.
        consume_authority(backend, identity, size, authority, required=require_authority)
    if state in ('unidentified', 'blank'):
        make_filesystem(fd, identity)
    else:
        check_filesystem(fd)


def reopen_disk(fd, flags=os.O_RDONLY):
    # Linux filesystem mounts may restrict other writable block-device opens.
    # Keep a read-only pin across the writer and mount phases.
    # https://github.com/torvalds/linux/blob/v6.12/include/linux/blkdev.h
    reviewed = os.fstat(fd)
    reopened = os.open(f'/proc/self/fd/{fd}', flags | os.O_CLOEXEC)
    opened = os.fstat(reopened)
    if (opened.st_dev, opened.st_ino, opened.st_rdev) != (reviewed.st_dev, reviewed.st_ino, reviewed.st_rdev):
        os.close(reopened)
        raise RuntimeError('runtime_block_device_mismatch')
    return reopened


def mount_disk(fd, destination, *, readonly=False):
    # mount(8) otherwise canonicalizes procfd back to a mutable pathname. Do
    # not delegate to mount.type helpers, which do not inherit this option.
    # https://github.com/util-linux/util-linux/blob/master/sys-utils/mount.8.adoc
    options = 'nodev,nosuid,noexec'
    if readonly:
        options += ',ro,noload,noatime'
    run('/usr/bin/mount', '--no-canonicalize', '--internal-only', '-t', 'ext4',
        '-o', options, f'/proc/self/fd/{fd}', str(destination), pass_fds=(fd,))


def mount_mode(fd, destination):
    # Compare device numbers, not path spellings, so an alias cannot conceal an
    # existing mount. Reject a different mount at the destination as well.
    rdev = os.fstat(fd).st_rdev
    major_minor = f'{os.major(rdev)}:{os.minor(rdev)}'
    mode = None
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        mount, filesystem = (part.split() for part in line.split(' - ', 1))
        if mount[2] != major_minor and mount[4] != str(destination):
            continue
        if (mode is not None or mount[2:5] != [major_minor, '/', str(destination)]
                or filesystem[0] != 'ext4'):
            raise RuntimeError('runtime_disk_mount_mismatch')
        options = set(mount[5].split(','))
        if not {'nodev', 'nosuid', 'noexec'} <= options:
            raise RuntimeError('runtime_disk_mount_mismatch')
        super_options = set(filesystem[2].split(','))
        if {'ro', 'noatime'} <= options and 'ro' in super_options and {'noload', 'norecovery'} & super_options:
            mode = 'readonly'
        elif 'rw' in options and 'rw' in super_options:
            mode = 'writable'
        else:
            raise RuntimeError('runtime_disk_mount_mismatch')
    return mode


def check_not_swap(fd):
    rdev = os.fstat(fd).st_rdev
    for line in Path('/proc/swaps').read_text().splitlines()[1:]:
        if os.stat(line.split()[0]).st_rdev == rdev:
            raise RuntimeError('runtime_disk_is_swap')


def block_readonly(fd):
    return struct.unpack('i', fcntl.ioctl(fd, BLKROGET, struct.pack('i', 0)))[0] != 0


def set_block_readonly(fd, readonly):
    if block_readonly(fd) == readonly:
        return
    fcntl.ioctl(fd, BLKROSET, struct.pack('i', readonly))
    if block_readonly(fd) != readonly:
        raise RuntimeError('runtime_block_mode_mismatch')


def check_mountpoint(destination):
    info = destination.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700 or any(destination.iterdir())):
        raise RuntimeError('runtime_mountpoint_unavailable')


class Backing:
    def __init__(self, fd, identity, destination, record):
        self.fd = fd
        self.identity = identity
        self.destination = destination
        self.record = record
        disk = os.fstat(fd)
        sequence = struct.unpack('Q', fcntl.ioctl(fd, BLKGETDISKSEQ, bytes(8)))[0]
        self.pin = [identity.hex, disk.st_dev, disk.st_ino, disk.st_rdev, sequence]

    def status(self):
        saved = json.loads(self.record.read_text())
        if type(saved) is not dict or saved.get('pin') != self.pin:
            raise RuntimeError('runtime_block_device_mismatch')
        mode = saved.get('mode')
        if mode not in ('blank', 'readonly', 'writable', 'recovery-required'):
            raise RuntimeError('runtime_block_mode_mismatch')
        mounted = mount_mode(self.fd, self.destination)
        if mounted is None:
            check_mountpoint(self.destination)
        if (mounted != (mode if mode in ('readonly', 'writable') else None)
                or block_readonly(self.fd) != (mode != 'writable')):
            raise RuntimeError('runtime_block_mode_mismatch')
        return mode

    def remember(self, mode):
        temporary = self.record.with_suffix('.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump({'pin': self.pin, 'mode': mode}, output)
        temporary.replace(self.record)
        return self.status()

    def unmount(self):
        run('/usr/bin/umount', '--no-canonicalize', '--internal-only', str(self.destination))
        if mount_mode(self.fd, self.destination) is not None:
            raise RuntimeError('runtime_disk_already_mounted')

    def fence(self):
        self.record.unlink(missing_ok=True)
        mounted = mount_mode(self.fd, self.destination)
        if mounted == 'writable':
            self.unmount()
            mounted = None
        set_block_readonly(self.fd, True)
        mode = probe_disk(self.fd, self.identity)
        if mode == 'unidentified':
            raise RuntimeError('runtime_disk_identity_mismatch')
        if mode == 'readonly':
            if mounted is None:
                check_mountpoint(self.destination)
                mount_disk(self.fd, self.destination, readonly=True)
        elif mounted is not None:
            self.unmount()
        return self.remember(mode)

    def change(self, *, repair):
        current = self.status()
        if (repair and current != 'recovery-required') or (not repair and current in ('writable', 'recovery-required')):
            return current
        if probe_disk(self.fd, self.identity) != current:
            raise RuntimeError('runtime_block_mode_mismatch')
        self.record.unlink()
        try:
            if current == 'readonly':
                # A noload mount cannot be promoted to journaled read-write in place.
                self.unmount()
            check_mountpoint(self.destination)
            set_block_readonly(self.fd, False)
            if repair or current == 'blank':
                writer = reopen_disk(self.fd, os.O_RDWR)
                try:
                    if repair:
                        check_filesystem(writer)
                    else:
                        make_filesystem(writer, self.identity)
                finally:
                    os.close(writer)
            if not repair:
                mount_disk(self.fd, self.destination)
                if mount_mode(self.fd, self.destination) != 'writable':
                    raise RuntimeError('runtime_block_mode_mismatch')
                self.destination.chmod(0o700)
                return self.remember('writable')
        except (OSError, RuntimeError, subprocess.CalledProcessError):
            self.fence()
            raise
        return self.fence()


def prepare(fd, backend, identity, size, *, live):
    DESTINATION.mkdir(mode=0o700, parents=True, exist_ok=True)
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    RUNTIME.chmod(0o700)
    if live or INITIALIZATION.exists() or INITIALIZATION.is_symlink():
        # Live owns its separate writable boot flow. On desktop, only a pending
        # authenticated Windows NewDisk ticket permits a boot-time write.
        if mount_mode(fd, DESTINATION) is not None:
            raise RuntimeError('runtime_disk_already_mounted')
        check_mountpoint(DESTINATION)
        if not live and backend != 'hcs-hyperv':
            raise RuntimeError('runtime_disk_identity_mismatch')
        writer = reopen_disk(fd, os.O_RDWR)
        try:
            format_check(writer, backend, identity, size, INITIALIZATION, require_authority=not live)
        finally:
            os.close(writer)
            if not live:
                set_block_readonly(fd, True)
        if live:
            mount_disk(fd, DESTINATION)
            DESTINATION.chmod(0o700)
    if not live:
        Backing(fd, identity, DESTINATION, RUNTIME / 'backing-state').fence()
    config = json.loads(Path('/etc/oblivion/controller.json').read_text())
    config.update(general_image=str(DESTINATION / 'general.luks'),
                  general_mib=min(1024 * 1024, size // (1024 * 1024) - 512),
                  session_mib=2048, ephemeral_mib=512)
    if not live:
        config['backing_fence'] = True
    config_fd = os.open(RUNTIME / 'controller.json', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(config_fd, 'w') as output:
        json.dump(config, output)
        output.write('\n')


def main(command=None):
    if os.geteuid() != 0:
        raise RuntimeError('root_required')
    arguments = Path('/proc/cmdline').read_text().split()
    backend, identity = profile(arguments)
    live_flags = [argument for argument in arguments if argument.startswith('oblivion.runtime-live=')]
    if live_flags and (live_flags != ['oblivion.runtime-live=1'] or backend != 'qemu-kvm'):
        raise RuntimeError('invalid_live_profile')
    live = bool(live_flags)
    if command is not None and (live or command not in BACKING_COMMANDS):
        raise RuntimeError('invalid_backing_command')
    system, size = select_disk(backend, identity, allow_readonly=not live)
    device = Path('/dev') / system.name
    metadata = device_metadata(device, system)
    fd = os.open(device, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISBLK(opened.st_mode) or opened.st_rdev != metadata.st_rdev
                or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)):
            raise RuntimeError('runtime_block_device_mismatch')
        check_not_swap(fd)
        if command is None:
            prepare(fd, backend, identity, size, live=live)
            return
        backing = Backing(fd, identity, DESTINATION, RUNTIME / 'backing-state')
        if command == 'backing-status':
            print(backing.status())
        elif command == 'backing-fence':
            print(backing.fence())
        else:
            print(backing.change(repair=command == 'backing-repair'))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        if len(sys.argv) > 2:
            raise RuntimeError('invalid_backing_command')
        main(sys.argv[1] if len(sys.argv) == 2 else None)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError):
        print('native_runtime_prepare_failed', file=sys.stderr)
        sys.exit(1)
