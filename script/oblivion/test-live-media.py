#!/usr/bin/python3
"""Exercise Live USB discovery with proc and sysfs snapshots."""

import importlib.util
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest


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


if __name__ == '__main__':
    unittest.main()
