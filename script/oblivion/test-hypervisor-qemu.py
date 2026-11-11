#!/usr/bin/python3
"""Exercise the real outer-hypervisor policy and byte-bound build evidence."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('qemu', Path(__file__).with_name('hypervisor-qemu.py'))
qemu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qemu)


class QemuInventory(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='oblivion-qemu-record-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def record(self, architecture='arm64', reported=(10, 1, 0)):
        package, binary, suite, _ = qemu.policy(architecture)
        executable = self.root / 'usr/bin' / binary
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b'synthetic QEMU inventory fixture, not a hypervisor')
        executable.chmod(0o755)
        record = {'version': 1, 'architecture': architecture, 'package': package,
                  'package_version': '1:' + '.'.join(map(str, reported)) + '+ds-1',
                  'suite': suite, 'repository': qemu.SOURCE,
                  'binary': executable.relative_to(self.root).as_posix(),
                  'binary_sha256': qemu.digest(executable), 'reported_version': list(reported)}
        destination = self.root / qemu.RECORD
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(record))
        return record

    def test_outer_arm_uses_backports_and_amd64_stays_stable(self):
        self.assertEqual(qemu.policy('arm64'), ('qemu-system-arm', 'qemu-system-aarch64', 'trixie-backports', (10, 1, 0)))
        self.assertEqual(qemu.policy('amd64'), ('qemu-system-x86', 'qemu-system-x86_64', 'trixie', None))
        for architecture, release in [('arm64', (10, 1, 0)), ('arm64', (11, 1, 2)), ('amd64', (10, 0, 13))]:
            record = self.record(architecture, release)
            self.assertEqual(qemu.verify(self.root), record)

    def test_stable_arm_qemu_is_refused_even_with_a_recent_kernel(self):
        self.record(reported=(10, 0, 13))
        with self.assertRaisesRegex(ValueError, 'requires_10_1'):
            qemu.verify(self.root)

    def test_actual_cli_checks_the_binary_hash_before_packing(self):
        record = self.record()
        output = subprocess.check_output([sys.executable, '-B', str(Path(__file__).with_name('hypervisor-qemu.py')), 'verify', str(self.root)], text=True)
        self.assertEqual(json.loads(output), record)
        (self.root / record['binary']).write_bytes(b'replaced hypervisor')
        with self.assertRaisesRegex(ValueError, 'inventory_changed'):
            qemu.verify(self.root)

    def test_changed_policy_non_executable_and_symlink_are_refused(self):
        record = self.record()
        destination = self.root / qemu.RECORD
        for change in [{'suite': 'trixie'}, {'binary': 'usr/bin/other'}, {'repository': 'https://example.invalid'}, {'package': 'other'}]:
            destination.write_text(json.dumps({**record, **change}))
            with self.assertRaisesRegex(ValueError, 'policy_changed'):
                qemu.verify(self.root)
        destination.write_text(json.dumps(record))
        executable = self.root / record['binary']
        executable.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'inventory_changed'):
            qemu.verify(self.root)
        executable.rename(executable.with_suffix('.real'))
        executable.symlink_to(executable.with_suffix('.real').name)
        with self.assertRaisesRegex(ValueError, 'inventory_changed'):
            qemu.verify(self.root)

    def test_release_parser_accepts_distro_suffix_and_rejects_unknown_output(self):
        self.assertEqual(qemu.version('QEMU emulator version 11.1.2 (Debian 1:11.1.2+ds-3~bpo13+4)\nCopyright QEMU\n'), (11, 1, 2))
        for output in ['', '10.1.0', 'QEMU emulator version 10.1.0-rc1', 'QEMU emulator version 10.1', 'QEMU emulator version 10.1.0\n' + 'x' * 4096]:
            with self.assertRaisesRegex(ValueError, 'invalid_qemu_version'):
                qemu.version(output)


if __name__ == '__main__':
    unittest.main()
