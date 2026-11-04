#!/usr/bin/python3
"""Verify real boot-file/kernel-inventory checks without installing a kernel."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('kernel', Path(__file__).with_name('hypervisor-kernel.py'))
kernel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kernel)


class KernelInventory(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='oblivion-kernel-record-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def record(self, architecture='arm64', abi='6.16.12+deb13-arm64'):
        boot = self.root / 'boot'
        boot.mkdir(exist_ok=True)
        image = boot / ('vmlinuz-' + abi)
        image.write_bytes(b'synthetic boot image, not executable')
        (boot / ('config-' + abi)).write_text('CONFIG_KVM=y\n')
        value = {'version': 1, 'architecture': architecture, 'abi': abi,
                 'kernel_package': 'linux-image-' + abi, 'kernel_version': '6.16.12-1~bpo13+1',
                 'kernel_sha256': kernel.digest(image),
                 'boot_arguments': {'outer-live': ['kvm-arm.mode=nested'] if architecture == 'arm64' else [], 'controller': []}}
        output = self.root / kernel.RECORD
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value))
        return value

    def test_arm64_minimum_and_amd64_stable_are_valid(self):
        self.assertEqual(self.record(), kernel.verify(self.root))
        for path in (self.root / 'boot').iterdir():
            path.unlink()
        self.assertEqual(self.record('amd64', '6.12.115+deb13-amd64'), kernel.verify(self.root))

    def test_arm64_pre_el2_kernel_is_rejected(self):
        self.record(abi='6.15.12+deb13-arm64')
        with self.assertRaisesRegex(ValueError, 'requires_linux_6_16'):
            kernel.verify(self.root)

    def test_old_kernel_left_behind_is_rejected(self):
        self.record()
        (self.root / 'boot/vmlinuz-6.12-old').write_bytes(b'old kernel')
        with self.assertRaisesRegex(ValueError, 'inventory_changed'):
            kernel.verify(self.root)

    def test_changed_boot_image_is_rejected(self):
        value = self.record()
        (self.root / 'boot' / ('vmlinuz-' + value['abi'])).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'inventory_changed'):
            kernel.verify(self.root)

    def test_kernel_without_kvm_is_rejected(self):
        value = self.record()
        (self.root / 'boot' / ('config-' + value['abi'])).write_text('# CONFIG_KVM is not set\n')
        with self.assertRaisesRegex(ValueError, 'requires_kvm'):
            kernel.verify(self.root)

    def test_outer_and_controller_kernel_identity_must_match(self):
        value = self.record()
        controller = self.root / 'controller.json'
        controller.write_text(json.dumps(value))
        self.assertEqual(kernel.verify(self.root, controller), value)
        controller.write_text(json.dumps({**value, 'kernel_version': 'other'}))
        with self.assertRaisesRegex(ValueError, 'kernel_differ'):
            kernel.verify(self.root, controller)

    def test_arm64_grub_enables_nested_mode_and_amd64_stays_unchanged(self):
        self.record()
        template = self.root / 'grub.cfg'
        source = "menuentry 'Live' {\n linux /live/vmlinuz boot=live components noswap\n}\n"
        template.write_text(source)
        self.assertIn(' boot=live kvm-arm.mode=nested components', kernel.grub(self.root, template, 'outer-live'))
        self.assertEqual(kernel.grub(self.root, template, 'controller'), source)
        for path in (self.root / 'boot').iterdir():
            path.unlink()
        self.record('amd64', '6.12.115+deb13-amd64')
        self.assertEqual(kernel.grub(self.root, template, 'outer-live'), source)


if __name__ == '__main__':
    unittest.main()
