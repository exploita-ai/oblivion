#!/usr/bin/python3
"""Real Linux procfd I/O, not a VM or block-device boot qualification."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor


spec = importlib.util.spec_from_file_location(
    'runtime_prepare', Path(__file__).resolve().parents[1] / 'host/runtime-prepare.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
spec = importlib.util.spec_from_file_location(
    'runtime_auth', Path(__file__).resolve().parents[1] / 'host/runtime-auth.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
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

    def provision_new_disk(self, boot, identity=None):
        runtime = self.root / f'run-{boot}'
        runtime.mkdir(mode=0o700)
        identity = identity or self.identity
        authority = runtime / 'new-disk'
        data = json.dumps({'kind': 'new-disk', 'runtime_id': identity.hex,
                           'bytes': self.size}).encode()
        # Exercise the actual private READY/token/SET bootstrap, including its
        # product capacity validation; every token here is a synthetic fixture.
        guest, host = socket.socketpair()
        try:
            with ThreadPoolExecutor(max_workers=1) as worker:
                result = worker.submit(bootstrap.provision, guest.fileno(), runtime / 'token',
                                       os.geteuid(), os.getegid(), authority,
                                       'hcs-hyperv', identity.hex)
                self.assertEqual(bootstrap.receive(host.fileno(), len(bootstrap.READY),
                                                   time.monotonic() + 3), bootstrap.READY)
                host.sendall(b'x' * 32 + struct.pack('>I', len(data)) + data)
                self.assertEqual(bootstrap.receive(host.fileno(), len(bootstrap.SET),
                                                   time.monotonic() + 3), bootstrap.SET)
                result.result(timeout=3)
        finally:
            guest.close()
            host.close()
        return authority

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

    @unittest.skipUnless(Path('/usr/sbin/debugfs').is_file(), 'Requires real ext4 debugfs')
    def test_reissued_new_disk_bootstrap_consumes_authority_and_preserves_formatted_payload(self):
        # Sparse 4 GiB satisfies the real NewDisk wire contract without a VM,
        # mounting a filesystem or allocating a physical 4 GiB image.
        self.size = 4 * 1024**3
        os.ftruncate(self.fd, self.size)
        first = self.provision_new_disk(1)
        prepare.initialize_blank_disk(self.fd, 'hcs-hyperv', self.identity, self.size, first)
        self.assertFalse(first.exists())
        self.assertEqual(os.pread(self.fd, 4096, 0), prepare.disk_marker(self.identity))
        # Crash after fsynced marker, before mkfs. The repeated authenticated
        # authority must be consumed even though the durable marker already owns
        # formatting; Existing without a capability is covered above as well.
        second = self.provision_new_disk(2)
        prepare.format_check(self.fd, 'hcs-hyperv', self.identity, self.size, second)
        self.assertFalse(second.exists())
        self.assertEqual(self.observation()['UUID'], str(self.identity))
        payload = b'SYNTHETIC_PERSISTENT_PAYLOAD\n' * 4096
        source = self.root / 'payload'
        source.write_bytes(payload)
        with source.open('rb') as opened:
            subprocess.run(['/usr/sbin/debugfs', '-w', '-R',
                            f'write /proc/self/fd/{opened.fileno()} /payload.bin',
                            f'/proc/self/fd/{self.fd}'], pass_fds=(self.fd, opened.fileno()),
                           check=True, capture_output=True)

        def stored_payload():
            return subprocess.run(['/usr/sbin/debugfs', '-R', 'cat /payload.bin',
                                   f'/proc/self/fd/{self.fd}'], pass_fds=(self.fd,),
                                  check=True, capture_output=True).stdout

        self.assertEqual(stored_payload(), payload)
        expected = hashlib.sha256(stored_payload()).digest()
        third = self.provision_new_disk(3)
        prepare.format_check(self.fd, 'hcs-hyperv', self.identity, self.size, third)
        self.assertFalse(third.exists())
        self.assertEqual(stored_payload(), payload)
        self.assertEqual(hashlib.sha256(stored_payload()).digest(), expected)
        self.assertEqual(self.observation()['UUID'], str(self.identity))
        # A fresh capability for a different runtime cannot turn that existing
        # ext4 filesystem into a formatting candidate or alter the payload.
        foreign = uuid.uuid4()
        rejected = self.provision_new_disk(4, foreign)
        with self.assertRaisesRegex(RuntimeError, '^runtime_disk_identity_mismatch$'):
            prepare.format_check(self.fd, 'hcs-hyperv', foreign, self.size, rejected)
        self.assertTrue(rejected.exists())
        self.assertEqual(hashlib.sha256(stored_payload()).digest(), expected)
        self.assertEqual(self.observation()['UUID'], str(self.identity))

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
