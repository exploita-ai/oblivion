#!/usr/bin/python3
"""Exercise the actual Live partition planner and sfdisk mutation on sparse files."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('live_storage', Path(__file__).with_name('live-storage.py'))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class Planning(unittest.TestCase):
    def table(self):
        return {'label': 'gpt', 'id': 'test', 'sectorsize': 512, 'lastlba': 2097118,
                'partitions': [{'node': '/dev/sdb1', 'start': 2048, 'size': 1048576,
                                'type': '0FC63DAF-8483-4772-8E79-3D69D8477DE4'}]}

    def test_flashing_small_iso_on_larger_usb_reviews_gpt_relocation(self):
        value = storage.plan(self.table(), 8 * 1024**3, '/dev/sdb', '8:16')
        self.assertTrue(value['relocate_gpt_backup'])
        self.assertEqual(value['partitions'][0], self.table()['partitions'][0])
        self.assertGreaterEqual(value['bytes'], storage.MIN_BYTES)
        self.assertEqual(value['start'] % 2048, 0)
        changed = self.table()
        changed['partitions'][0]['size'] += 2048
        self.assertNotEqual(value['plan_sha256'], storage.plan(changed, 8 * 1024**3, '/dev/sdb', '8:16')['plan_sha256'])
        self.assertNotEqual(value['plan_sha256'], storage.plan(self.table(), 8 * 1024**3, '/dev/sdc', '8:32')['plan_sha256'])

    def test_small_and_full_media_are_rejected_without_a_write(self):
        with self.assertRaisesRegex(ValueError, 'insufficient_unallocated_live_space'):
            storage.plan(self.table(), 2 * 1024**3, '/dev/sdb', '8:16')
        table = self.table()
        table['label'] = 'dos'
        table['partitions'] = [{**table['partitions'][0], 'node': '/dev/sdb' + str(number)} for number in range(1, 5)]
        with self.assertRaisesRegex(ValueError, 'insufficient_unallocated_live_space'):
            storage.plan(table, 8 * 1024**3, '/dev/sdb', '8:16')

    def test_identity_is_synced_and_decoded_without_touching_preceding_bytes(self):
        with tempfile.TemporaryDirectory(prefix='oblivion-live-identity-') as directory:
            path = Path(directory) / 'data.raw'
            path.write_bytes(b'keep' * 1024 + bytes(4096))
            with path.open('r+b') as target:
                storage.write_identity(target, 4096, 'a' * 32)
            data = path.read_bytes()
            self.assertEqual(data[:4096], b'keep' * 1024)
            self.assertEqual(storage.decode_identity(data[4096:]), 'a' * 32)
            self.assertIsNone(storage.decode_identity(b'unknown data' + bytes(4084)))

    def test_raw_identity_staging_refuses_a_regular_file_before_writing(self):
        with tempfile.TemporaryDirectory(prefix='oblivion-live-non-device-') as directory:
            path = Path(directory) / 'not-a-device'
            path.write_bytes(b'preserve this file')
            value = storage.plan(self.table(), 8 * 1024**3, str(path), '8:16')
            with self.assertRaisesRegex(ValueError, 'live_boot_device_changed'):
                storage.stage_identity(value, 'a' * 32)
            self.assertEqual(path.read_bytes(), b'preserve this file')

    @unittest.skipUnless(shutil.which('sfdisk'), 'requires util-linux sfdisk')
    def test_actual_gpt_relocation_and_append_preserve_existing_partition(self):
        with tempfile.TemporaryDirectory(prefix='oblivion-live-table-') as directory:
            disk = Path(directory) / 'usb.raw'
            with disk.open('wb') as output:
                output.truncate(1024**3)
            subprocess.run(['sfdisk', str(disk)], input=b'label: gpt\nstart=2048,size=1048576,type=linux\n',
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            original = json.loads(subprocess.check_output(['sfdisk', '--json', str(disk)]))['partitiontable']
            with disk.open('r+b') as output:
                output.truncate(8 * 1024**3)
            reviewed = copy.deepcopy(original)
            reviewed['partitions'][0]['node'] = '/dev/sdb1'
            value = storage.plan(reviewed, disk.stat().st_size, '/dev/sdb', '8:16')
            self.assertTrue(value['relocate_gpt_backup'])
            value['boot_device'] = str(disk)
            value['partitions'] = [{key: part[key] for key in ('node', 'start', 'size', 'type')} for part in original['partitions']]
            # Commit the identity before the table. Stopping immediately after
            # append models the old crash window before partx/udev/node setup.
            offset = value['start'] * value['sector_bytes']
            old_data = original['partitions'][0]['start'] * original['sectorsize']
            with disk.open('r+b') as output:
                output.seek(old_data)
                output.write(b'PREVIOUS_PARTITION_DATA')
                storage.write_identity(output, offset, 'a' * 32)
            added = storage.append_partition(value)
            current = json.loads(subprocess.check_output(['sfdisk', '--json', str(disk)]))['partitiontable']
            self.assertEqual(current['id'], original['id'])
            self.assertEqual(current['partitions'][0], original['partitions'][0])
            self.assertEqual(added['start'], value['start'])
            self.assertEqual(added['size'], value['sectors'])
            self.assertGreater(current['lastlba'], original['lastlba'])
            with disk.open('rb') as source:
                source.seek(offset)
                self.assertEqual(storage.decode_identity(source.read(4096)), 'a' * 32)
                source.seek(old_data)
                self.assertEqual(source.read(23), b'PREVIOUS_PARTITION_DATA')


if __name__ == '__main__':
    unittest.main()
