#!/usr/bin/python3
"""Prepare the dedicated data disk of the native launcher's Debian runtime."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def run(*arguments):
    return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout


def prepare():
    if os.geteuid() != 0 or 'oblivion.runtime=1' not in Path('/proc/cmdline').read_text().split():
        raise RuntimeError('native_runtime_required')
    device = Path('/dev/vdb')
    metadata = device.lstat()
    if not stat.S_ISBLK(metadata.st_mode):
        raise RuntimeError('runtime_block_device_required')
    system = Path('/sys/class/block/vdb')
    if 'virtio' not in str((system / 'device').resolve()) or (system / 'ro').read_text().strip() != '0':
        raise RuntimeError('runtime_virtio_disk_required')
    size = int((system / 'size').read_text()) * 512
    if not 4 * 1024**3 <= size <= 1024**4 or list(system.glob('vdb*')):
        raise RuntimeError('invalid_runtime_disk')
    # Compare device numbers, not path spellings, so an alias cannot conceal an
    # existing mount or swap area. A runtime disk is dedicated to this service.
    major_minor = f'{os.major(metadata.st_rdev)}:{os.minor(metadata.st_rdev)}'
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        if line.split()[2] == major_minor:
            raise RuntimeError('runtime_disk_already_mounted')
    for line in Path('/proc/swaps').read_text().splitlines()[1:]:
        if os.stat(line.split()[0]).st_rdev == metadata.st_rdev:
            raise RuntimeError('runtime_disk_is_swap')
    probe = subprocess.run(['/usr/sbin/blkid', '-p', '-o', 'export', str(device)],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, check=False)
    if probe.returncode == 2:
        # A missing signature alone is insufficient authorization to format.
        # Newly created sparse RAW disks read as zero across their full size.
        with device.open('rb', buffering=0) as disk:
            observed = 0
            while block := disk.read(4 * 1024**2):
                if block.count(0) != len(block):
                    raise RuntimeError('runtime_disk_is_not_empty')
                os.posix_fadvise(disk.fileno(), observed, len(block), os.POSIX_FADV_DONTNEED)
                observed += len(block)
        if observed != size:
            raise RuntimeError('runtime_disk_size_changed')
        run('/usr/sbin/mkfs.ext4', '-q', '-m', '0', '-L', 'OBLIVION-RUNTIME', str(device))
    elif probe.returncode == 0:
        values = dict(line.split('=', 1) for line in probe.stdout.decode().splitlines() if '=' in line)
        if values.get('TYPE') != 'ext4' or values.get('LABEL') != 'OBLIVION-RUNTIME':
            raise RuntimeError('runtime_disk_identity_mismatch')
        checked = subprocess.run(['/usr/sbin/e2fsck', '-p', str(device)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, check=False)
        if checked.returncode not in (0, 1):
            raise RuntimeError('runtime_filesystem_recovery_required')
    else:
        raise RuntimeError('runtime_disk_probe_failed')
    destination = Path('/var/lib/oblivion')
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    run('/usr/bin/mount', '-t', 'ext4', '-o', 'nodev,nosuid,noexec', str(device), str(destination))
    destination.chmod(0o700)
    config = json.loads(Path('/etc/oblivion/controller.json').read_text())
    config.update(usb_persistence=False, network_profiles=False,
                  manage_os_preferences=False, general_image=str(destination / 'general.luks'))
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
