#!/usr/bin/python3
"""Real Linux procfd I/O, not a VM or block-device boot qualification."""
import fcntl
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid


spec = importlib.util.spec_from_file_location(
    'runtime_prepare', Path(__file__).resolve().parents[1] / 'host/runtime-prepare.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
TOOLS = ('/usr/sbin/mkfs.ext4', '/usr/sbin/blkid', '/usr/sbin/e2fsck', '/usr/bin/mount')
LINUX_TOOLS = sys.platform == 'linux' and all(Path(tool).is_file() for tool in TOOLS)


def can_mount():
    if not LINUX_TOOLS or not Path('/dev/loop-control').exists():
        return False
    status = Path('/proc/self/status').read_text().splitlines()
    effective = next(line.split()[1] for line in status if line.startswith('CapEff:'))
    return bool(int(effective, 16) & (1 << 21))


@unittest.skipUnless(LINUX_TOOLS, 'Requires Linux procfs and real util-linux/e2fsprogs tools')
class RuntimeDiskFd(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='oblivion-runtime-fd-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'runtime.raw'
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.addCleanup(lambda: os.close(self.fd))
        self.size = 64 * 1024 * 1024
        os.ftruncate(self.fd, self.size)
        self.identity = uuid.uuid4()

    def replace_name(self):
        original = self.root / 'original.raw'
        self.path.rename(original)
        self.path.write_bytes(b'UNRELATED_DESTINATION_CANARY\n')
        return original

    def observation(self):
        result = subprocess.run(['/usr/sbin/blkid', '-p', '-o', 'export', f'/proc/self/fd/{self.fd}'],
                                pass_fds=(self.fd,), check=True, capture_output=True)
        return dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)

    def test_format_probe_and_fsck_keep_the_open_inode_after_its_name_is_replaced(self):
        os.pwrite(self.fd, prepare.disk_marker(self.identity), 0)
        original = self.replace_name()
        pinned = os.fstat(self.fd)
        prepare.format_check(self.fd, 'hcs-hyperv', self.identity, self.size, self.root / 'missing-authority')
        observed = self.observation()
        self.assertEqual(observed['TYPE'], 'ext4')
        self.assertEqual(observed['LABEL'], 'OBLIVION-RUNTIME')
        self.assertEqual(observed['UUID'], str(self.identity))
        prepare.format_check(self.fd, 'hcs-hyperv', self.identity, self.size, self.root / 'missing-authority')
        self.assertEqual(self.path.read_bytes(), b'UNRELATED_DESTINATION_CANARY\n')
        self.assertEqual((os.stat(original).st_dev, os.stat(original).st_ino), (pinned.st_dev, pinned.st_ino))
        self.assertEqual(os.fstat(self.fd).st_size, self.size)

    def test_readonly_handoff_keeps_identity_and_contents_after_name_replacement(self):
        content = b'PINNED_ORIGINAL_CONTENT'
        os.pwrite(self.fd, content, 0)
        original = self.replace_name()
        pinned = os.fstat(self.fd)
        reader = prepare.readonly_disk(self.fd)
        os.close(self.fd)
        self.fd = reader
        self.assertEqual(fcntl.fcntl(reader, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
        self.assertEqual((os.fstat(reader).st_dev, os.fstat(reader).st_ino), (pinned.st_dev, pinned.st_ino))
        self.assertEqual(os.pread(reader, len(content), 0), content)
        self.assertEqual((os.stat(original).st_dev, os.stat(original).st_ino), (pinned.st_dev, pinned.st_ino))
        self.assertEqual(self.path.read_bytes(), b'UNRELATED_DESTINATION_CANARY\n')

    def test_existing_blank_or_nonzero_unknown_disk_is_not_formatted(self):
        for first in (bytes(4096), b'UNRELATED_DISK_CANARY' + bytes(4096 - 21)):
            os.pwrite(self.fd, first, 0)
            with self.assertRaisesRegex(RuntimeError, '^runtime_disk_identity_mismatch$'):
                prepare.format_check(self.fd, 'hcs-hyperv', self.identity, self.size, self.root / 'missing-authority')
            self.assertEqual(os.pread(self.fd, 4096, 0), first)

    @unittest.skipUnless(can_mount(), 'Mount acceptance requires CAP_SYS_ADMIN and loop-control')
    def test_mount_uses_the_pinned_inode_without_canonicalizing_back_to_the_name(self):
        os.pwrite(self.fd, prepare.disk_marker(self.identity), 0)
        self.replace_name()
        prepare.format_check(self.fd, 'hcs-hyperv', self.identity, self.size, self.root / 'missing-authority')
        destination = self.root / 'mount'
        destination.mkdir()
        reader = prepare.readonly_disk(self.fd)
        # Drop the parent's writer exactly as production does before mounting.
        os.close(self.fd)
        self.fd = reader
        prepare.mount_disk(reader, destination)
        try:
            self.assertTrue((destination / 'lost+found').is_dir())
            self.assertEqual(self.path.read_bytes(), b'UNRELATED_DESTINATION_CANARY\n')
        finally:
            subprocess.run(['/usr/bin/umount', str(destination)], check=True, capture_output=True)


if __name__ == '__main__':
    unittest.main()
