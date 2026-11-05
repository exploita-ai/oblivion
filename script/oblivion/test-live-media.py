#!/usr/bin/python3
"""Exercise Live USB discovery with proc and sysfs snapshots."""

from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('live_media', Path(__file__).with_name('live-media.py'))
media = importlib.util.module_from_spec(spec)
spec.loader.exec_module(media)


class Discovery(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        self.proc = root / 'proc'
        self.sys = root / 'sys'
        self.dev = root / 'dev'
        self.nodes = {}
        self.put(self.proc / 'cmdline', 'quiet boot=live')
        self.put(self.proc / 'sys/kernel/random/boot_id', 'c8631a2b-3a2e-455d-8b81-2b5889e87850')
        self.put(self.proc / 'swaps', 'Filename Type Size Used Priority')
        (self.sys / 'dev/block').mkdir(parents=True)
        (self.sys / 'bus/usb').mkdir(parents=True)
        boot = self.disk('sda', 0)
        self.part(boot, 1, 1)
        self.part(boot, 2, 2, start=16384)
        self.boot_mount = '1 0 8:1 / /run/live/medium ro - iso9660 /dev/sda1 ro'
        self.put(self.proc / 'self/mountinfo', self.boot_mount)

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f'{value}\n')

    def block(self, path, minor, kind):
        self.put(path / 'dev', f'8:{minor}')
        self.put(path / 'uevent', f'DEVTYPE={kind}')
        self.put(path / 'ro', 0)
        (path / 'holders').mkdir()
        (self.sys / 'dev/block' / f'8:{minor}').symlink_to(path)
        self.nodes[path.name] = SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, minor))

    def disk(self, name, minor, usb=True, base='pci0000:00'):
        path = self.sys / 'devices' / base
        if usb:
            path = path / f'usb1/1-{minor + 1}'
            self.put(path / 'uevent', 'DEVTYPE=usb_device')
            self.put(path / 'busnum', 1)
            self.put(path / 'devnum', minor % 126 + 1)
            self.put(path / 'idVendor', '0781')
            self.put(path / 'idProduct', '5571')
            (path / 'subsystem').symlink_to(self.sys / 'bus/usb')
        path = path / f'host{minor}/block/{name}'
        self.block(path, minor, 'disk')
        self.put(path / 'size', 32768)
        self.put(path / 'diskseq', minor + 1)
        (path / 'slaves').mkdir()
        return path

    def part(self, disk, partition, minor, start=2048):
        path = disk / f'{disk.name}{partition}'
        self.block(path, minor, 'partition')
        self.put(path / 'partition', partition)
        self.put(path / 'start', start)
        self.put(path / 'size', 8192)
        return path

    def stat_path(self, path, *, follow_symlinks=True):
        # Only the kernel's block-node metadata is substituted. All proc/sysfs
        # parsing, links, and directory enumeration use the production code.
        if path.parent in (self.dev, Path('/dev')) and path.name in self.nodes:
            return self.nodes[path.name]
        return path.stat(follow_symlinks=follow_symlinks)

    def list(self):
        return media.list_media(self.proc, self.sys, self.dev, self.stat_path)

    def test_lists_partitions_and_unpartitioned_usb_but_excludes_boot_and_nonphysical(self):
        disk = self.disk('sdb', 16)
        self.part(disk, 1, 17)
        second = self.part(disk, 2, 18, start=16384)
        self.put(second / 'ro', 1)
        self.disk('sdc', 32)
        self.disk('sdd', 48, usb=False)
        self.disk('loop0', 64, base='virtual')

        devices = self.list()
        self.assertEqual([(entry['name'], entry['bytes'], entry['read_only']) for entry in devices],
                         [('sdb1', 4194304, False), ('sdb2', 4194304, True), ('sdc', 16777216, False)])
        for entry in devices:
            self.assertRegex(entry['id'], r'^[0-9a-f]{64}$')
        self.assertEqual(self.list(), devices)

    def test_excludes_all_siblings_if_one_is_mounted_swapping_or_held(self):
        disk = self.disk('sdb', 16)
        self.part(disk, 1, 17)
        second = self.part(disk, 2, 18, start=16384)
        self.disk('sdc', 32)
        self.put(self.proc / 'self/mountinfo',
                 self.boot_mount + '\n2 1 0:9 / /media/mounted rw - fuseblk /dev/sdb2 rw')
        self.assertEqual([entry['name'] for entry in self.list()], ['sdc'])

        self.put(self.proc / 'self/mountinfo', self.boot_mount)
        self.put(self.proc / 'swaps', 'Filename Type Size Used Priority\n/dev/sdb2 partition 1024 0 -2')
        self.assertEqual([entry['name'] for entry in self.list()], ['sdc'])

        self.put(self.proc / 'swaps', 'Filename Type Size Used Priority')
        (second / 'holders/dm-0').mkdir()
        self.assertEqual([entry['name'] for entry in self.list()], ['sdc'])

    def test_excludes_secondary_btrfs_member(self):
        disk = self.disk('sdb', 16)
        first = self.part(disk, 1, 17)
        self.part(disk, 2, 18, start=16384)
        self.disk('sdc', 32)
        devices = self.sys / 'fs/btrfs/a3514860-2586-451c-87ce-7a98c9ac44e7/devices'
        devices.mkdir(parents=True)
        (devices / 'sdb1').symlink_to(first)
        self.assertEqual([entry['name'] for entry in self.list()], ['sdc'])

    def test_rekeys_when_device_number_reused_or_partition_geometry_changes(self):
        disk = self.disk('sdb', 16)
        partition = self.part(disk, 1, 17)
        original = self.list()[0]['id']
        self.put(disk / 'diskseq', 500)
        replugged = self.list()[0]['id']
        self.assertNotEqual(replugged, original)
        self.put(partition / 'start', 4096)
        self.assertNotEqual(self.list()[0]['id'], replugged)
        (disk / 'diskseq').unlink()
        self.assertEqual(self.list(), [])

    def test_refuses_ambiguous_unresolved_or_non_live_boot(self):
        self.disk('sdb', 16)
        self.put(self.proc / 'self/mountinfo', self.boot_mount + '\n' + self.boot_mount)
        with self.assertRaisesRegex(ValueError, 'one_live_boot_medium_required'):
            self.list()
        self.put(self.proc / 'self/mountinfo', self.boot_mount.replace('8:1', '8:9'))
        with self.assertRaises(FileNotFoundError):
            self.list()
        self.put(self.proc / 'cmdline', 'quiet')
        with self.assertRaisesRegex(ValueError, 'debian_live_boot_required'):
            self.list()

    def test_bounds_output_and_ignores_wrong_node_metadata(self):
        for index in range(65):
            self.disk(f'usb{index:02}', index + 16)
        self.assertEqual(len(self.list()), 64)
        self.nodes['usb00'] = SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 9))
        self.assertEqual([entry['name'] for entry in self.list()], [f'usb{index:02}' for index in range(1, 65)])

    @contextmanager
    def block_descriptor(self, *, major_minor=17, bytes_count=4194304, diskseq=17, after_open=None):
        opened = []
        requests = []
        with (self.proc / 'cmdline').open('rb') as source:
            def open_block(path, flags):
                self.assertEqual(path, self.dev / 'sdb1')
                self.assertEqual(flags, os.O_RDONLY | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC)
                if after_open is not None:
                    after_open()
                fd = os.dup(source.fileno())
                opened.append(fd)
                return fd

            def ioctl(fd, request, buffer):
                self.assertEqual(fd, opened[0])
                self.assertEqual(len(buffer), 8)
                requests.append(request)
                return struct.pack('=Q', {0x80081272: bytes_count, 0x80081280: diskseq}[request])

            block_info = SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, major_minor))
            with (patch.object(media.os, 'open', side_effect=open_block),
                  patch.object(media.os, 'fstat', return_value=block_info),
                  patch.object(media.fcntl, 'ioctl', side_effect=ioctl)):
                yield opened, requests

    def pin(self, device_id):
        return media.open_media(device_id, self.proc, self.sys, self.dev, self.stat_path)

    def test_pins_the_exact_visible_partition_and_transfers_fd_ownership(self):
        disk = self.disk('sdb', 16)
        self.part(disk, 1, 17)
        selected = self.list()[0]
        with self.block_descriptor() as (opened, requests):
            fd, metadata = self.pin(selected['id'])
        try:
            self.assertEqual(opened, [fd])
            self.assertEqual(requests, [0x80081272, 0x80081280])
            self.assertEqual(metadata, selected)
            self.assertFalse(os.get_inheritable(fd))
            self.assertEqual(os.read(fd, 5), b'quiet')
        finally:
            os.close(fd)

    def test_refuses_a_stale_or_invalid_selection_before_opening(self):
        disk = self.disk('sdb', 16)
        self.part(disk, 1, 17)
        selected = self.list()[0]
        self.put(disk / 'diskseq', 500)
        with self.block_descriptor() as (opened, requests):
            with self.assertRaisesRegex(ValueError, 'invalid_live_media_id'):
                self.pin('/dev/sdb1')
            with self.assertRaisesRegex(ValueError, 'live_media_unavailable'):
                self.pin(selected['id'])
        self.assertEqual(opened, [])
        self.assertEqual(requests, [])

    def test_closes_fd_if_its_identity_or_post_open_observation_differs(self):
        disk = self.disk('sdb', 16)
        self.part(disk, 1, 17)
        sibling = self.part(disk, 2, 18, start=16384)
        selected = self.list()[0]
        for options in ({'major_minor': 18}, {'bytes_count': 4096}, {'diskseq': 500},
                        {'after_open': lambda: (sibling / 'holders/dm-0').mkdir()}):
            with self.subTest(options=options), self.block_descriptor(**options) as (opened, requests):
                with self.assertRaisesRegex(ValueError, 'live_media_device_changed'):
                    self.pin(selected['id'])
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])

    def test_cannot_follow_a_replaced_device_node(self):
        disk = self.disk('sdb', 16)
        self.part(disk, 1, 17)
        selected = self.list()[0]
        self.dev.mkdir()
        (self.dev / 'sdb1').symlink_to(self.proc / 'cmdline')
        with self.assertRaises(OSError):
            self.pin(selected['id'])


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'requires an isolated Linux root fixture for SO_PEERCRED and root-owned profiles')
class Lease(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.profile = Path(temp.name) / 'installation.json'
        self.profile.write_text('{"version":1,"mode":"live-launcher"}\n')
        self.helper = Path(sys.executable).resolve()

    def live_pair(self):
        os.seteuid(1000)
        try:
            return socket.socketpair()
        finally:
            os.seteuid(0)

    def test_sends_one_byte_and_one_fd_to_a_live_uid_peer(self):
        sender, receiver = self.live_pair()
        descriptor = os.open(self.profile, os.O_RDONLY | os.O_CLOEXEC)
        with sender, receiver, patch.dict(os.environ, {'SUDO_UID': '1000'}), patch.object(
                media, 'open_media', return_value=(descriptor, {})) as pinned:
            media.lease_media('a' * 64, sender, self.profile, self.helper)
            pinned.assert_called_once_with('a' * 64)
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            receiver.settimeout(1)
            data, rights, flags, _ = receiver.recvmsg(2, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
            self.assertEqual(data, b'M')
            self.assertFalse(flags & socket.MSG_CTRUNC)
            self.assertEqual(len(rights), 1)
            level, kind, payload = rights[0]
            self.assertEqual((level, kind, len(payload)), (socket.SOL_SOCKET, socket.SCM_RIGHTS, 4))
            received, = struct.unpack('=i', payload)
            try:
                self.assertEqual(os.read(received, 1), b'{')
            finally:
                os.close(received)

    def test_requires_exact_sudo_uid_and_real_peer_before_opening(self):
        sender, receiver = socket.socketpair()
        with sender, receiver, patch.object(media, 'open_media') as pinned:
            with patch.dict(os.environ, {'SUDO_UID': '01000'}):
                with self.assertRaisesRegex(ValueError, 'live_media_lease_requires_live_sudo'):
                    media.lease_media('a' * 64, sender, self.profile)
            with patch.dict(os.environ, {'SUDO_UID': '1000'}):
                with self.assertRaisesRegex(ValueError, 'invalid_live_media_lease_peer'):
                    media.lease_media('a' * 64, sender, self.profile)
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as datagram:
                    with self.assertRaisesRegex(ValueError, 'invalid_live_media_lease_socket'):
                        media.lease_media('a' * 64, datagram, self.profile)
            pinned.assert_not_called()

    def test_correct_uid_cannot_use_another_executable(self):
        sender, receiver = self.live_pair()
        with sender, receiver, patch.dict(os.environ, {'SUDO_UID': '1000'}), patch.object(media, 'open_media') as pinned:
            with self.assertRaisesRegex(ValueError, 'invalid_live_media_lease_peer'):
                media.lease_media('a' * 64, sender, self.profile, self.profile)
            pinned.assert_not_called()

    def test_refuses_unsafe_or_invalid_installation_profiles(self):
        media.require_live_profile(self.profile)
        second_link = self.profile.with_name('second-link')
        os.link(self.profile, second_link)
        with self.assertRaisesRegex(ValueError, 'unsafe_installation_profile'):
            media.require_live_profile(self.profile)
        second_link.unlink()
        self.profile.chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'unsafe_installation_profile'):
            media.require_live_profile(self.profile)
        self.profile.chmod(0o644)
        for content in ('{"version":true,"mode":"live-launcher"}',
                        '{"version":1,"mode":"live-launcher","mode":"live-launcher"}',
                        '{"version":1,"mode":"controller-runtime"}',
                        self.profile.read_text() + ' ' * 1024):
            with self.subTest(content=content[:50]):
                self.profile.write_text(content)
                with self.assertRaisesRegex(ValueError, 'invalid_installation_profile'):
                    media.require_live_profile(self.profile)

    def test_closes_pinned_descriptor_when_receiver_exits_before_send(self):
        sender, receiver = self.live_pair()
        descriptor = os.open(self.profile, os.O_RDONLY | os.O_CLOEXEC)

        def pin_after_receiver_exits(_):
            receiver.close()
            return descriptor, {}

        with sender, receiver, patch.dict(os.environ, {'SUDO_UID': '1000'}), patch.object(
                media, 'open_media', side_effect=pin_after_receiver_exits):
            with self.assertRaises(BrokenPipeError):
                media.lease_media('a' * 64, sender, self.profile, self.helper)
        with self.assertRaises(OSError):
            os.fstat(descriptor)


if __name__ == '__main__':
    unittest.main()
