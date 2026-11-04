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
            added = storage.append_partition(value)
            current = json.loads(subprocess.check_output(['sfdisk', '--json', str(disk)]))['partitiontable']
            self.assertEqual(current['id'], original['id'])
            self.assertEqual(current['partitions'][0], original['partitions'][0])
            self.assertEqual(added['start'], value['start'])
            self.assertEqual(added['size'], value['sectors'])
            self.assertGreater(current['lastlba'], original['lastlba'])


if __name__ == '__main__':
    unittest.main()
