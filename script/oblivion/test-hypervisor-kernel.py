#!/usr/bin/python3
"""Verify real boot-file/kernel-inventory checks without installing a kernel."""
import importlib.util
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
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

    def record(self, architecture='arm64', abi='6.16.12+deb13-arm64', modular=False, role='outer-live', root=None):
        root = root or self.root
        boot = root / 'boot'
        boot.mkdir(parents=True, exist_ok=True)
        image = boot / ('vmlinuz-' + abi)
        image.write_bytes(('non-executable kernel fixture ' + abi).encode())
        config = 'CONFIG_KVM=y\n'
        if architecture == 'amd64':
            config += ''.join(symbol + ('=m\n' if modular else '=y\n') for symbol, _ in kernel.HYPERV_DRIVERS)
            if modular:
                directory = root / 'lib/modules' / abi / 'kernel/drivers/fixture'
                directory.mkdir(parents=True)
                for _, module in kernel.HYPERV_DRIVERS:
                    (directory / (module + '.ko.zst')).write_bytes(b'non-loadable module inventory fixture ' + module.encode())
        (boot / ('config-' + abi)).write_text(config)
        value = {'version': 2, 'architecture': architecture, 'abi': abi, 'role': role,
                 'kernel_package': 'linux-image-' + abi, 'kernel_version': '6.16.12-1~bpo13+1',
                 'kernel_sha256': kernel.digest(image),
                 'hyperv_guest_drivers': kernel.guest_drivers(root, architecture, abi),
                 'boot_arguments': ['kvm-arm.mode=nested'] if role == 'outer-live' and architecture == 'arm64' else []}
        output = root / kernel.RECORD
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value))
        return value

    def test_arm64_minimum_and_amd64_stable_are_valid(self):
        self.assertEqual(self.record(), kernel.verify(self.root, 'outer-live'))
        for path in (self.root / 'boot').iterdir():
            path.unlink()
        self.assertEqual(self.record('amd64', '6.12.115+deb13-amd64'), kernel.verify(self.root, 'outer-live'))

    def test_arm64_outer_live_rejects_pre_el2_kernel_but_controller_accepts_stable(self):
        self.record(abi='6.15.12+deb13-arm64')
        with self.assertRaisesRegex(ValueError, 'requires_linux_6_16'):
            kernel.verify(self.root, 'outer-live')
        controller = self.root / 'controller'
        value = self.record(abi='6.12.115+deb13.1-arm64', role='controller', root=controller)
        self.assertEqual(kernel.verify(controller, 'controller'), value)
        with self.assertRaisesRegex(ValueError, 'role_mismatch'):
            kernel.verify(controller, 'outer-live')
        with self.assertRaisesRegex(ValueError, 'architecture_mismatch'):
            kernel.verify(controller, 'controller', architecture='amd64')

    def test_amd64_builtin_and_modular_hyperv_drivers_are_recorded(self):
        value = self.record('amd64', '6.12.115+deb13-amd64', modular=True)
        self.assertEqual(value, kernel.verify(self.root, 'outer-live'))
        self.assertEqual(len(value['hyperv_guest_drivers']), 10)
        self.assertTrue(all(driver['mode'] == 'm' and driver['sha256'] for driver in value['hyperv_guest_drivers']))
        output = subprocess.check_output([sys.executable, '-B', str(Path(__file__).with_name('hypervisor-kernel.py')),
                                          'initramfs-modules', str(self.root), '--role', 'outer-live'], text=True)
        self.assertEqual(output.splitlines(), [module for _, module in kernel.HYPERV_DRIVERS])

    def test_disabled_hyperv_driver_fails_before_packing(self):
        value = self.record('amd64', '6.12.115+deb13-amd64')
        config = self.root / 'boot' / ('config-' + value['abi'])
        original = config.read_text()
        for symbol in ('CONFIG_HYPERV_VSOCKETS', 'CONFIG_VIRTIO_CONSOLE', 'CONFIG_VIRTIO_MMIO'):
            with self.subTest(symbol=symbol):
                config.write_text(original.replace(symbol + '=y', '# ' + symbol + ' is not set'))
                with self.assertRaisesRegex(ValueError, 'hyperv_guest_driver_required:' + symbol):
                    kernel.verify(self.root, 'outer-live')

    def test_missing_changed_and_duplicate_modular_drivers_are_rejected(self):
        value = self.record('amd64', '6.12.115+deb13-amd64', modular=True)
        path = self.root / value['hyperv_guest_drivers'][0]['path']
        original = path.read_bytes()
        path.write_bytes(b'changed driver')
        with self.assertRaisesRegex(ValueError, 'driver_inventory_changed'):
            kernel.verify(self.root, 'outer-live')
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'guest_module_required:hv_vmbus'):
            kernel.verify(self.root, 'outer-live')
        path.write_bytes(original)
        path.with_suffix('').write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'guest_module_required:hv_vmbus'):
            kernel.verify(self.root, 'outer-live')

    def test_initramfs_requires_every_modular_driver_from_the_exact_abi(self):
        value = self.record('amd64', '6.12.115+deb13-amd64', modular=True)
        required = [driver['path'] for driver in value['hyperv_guest_drivers']]
        self.assertEqual(kernel.initramfs_inventory(value, ['./usr/' + path for path in required]), required)
        for missing in (required[1:], [path.replace(value['abi'], 'wrong-abi') for path in required],
                        ['../../' + path for path in required]):
            with self.assertRaisesRegex(ValueError, 'hyperv_initramfs_module_missing'):
                kernel.initramfs_inventory(value, missing)

    @unittest.skipUnless(shutil.which('cpio') and shutil.which('lsinitramfs'), 'requires Debian initramfs-tools-core')
    def test_real_small_initramfs_archive_is_verified_and_evidenced(self):
        value = self.record('amd64', '6.12.115+deb13-amd64', modular=True)
        paths = [driver['path'] for driver in value['hyperv_guest_drivers']]
        archive = subprocess.check_output(['cpio', '--quiet', '-o', '-H', 'newc'],
                                          input=('\n'.join(paths) + '\n').encode(), cwd=self.root)
        initrd = self.root / ('initrd.img-' + value['abi'])
        initrd.write_bytes(gzip.compress(archive))
        evidence = kernel.verify(self.root, 'outer-live', initrd=initrd)
        self.assertEqual(evidence['initramfs'], {'sha256': kernel.digest(initrd), 'hyperv_modules': paths})
        archive = subprocess.check_output(['cpio', '--quiet', '-o', '-H', 'newc'],
                                          input=('\n'.join(paths[1:]) + '\n').encode(), cwd=self.root)
        initrd.write_bytes(gzip.compress(archive))
        with self.assertRaisesRegex(ValueError, 'hyperv_initramfs_module_missing:hv_vmbus'):
            kernel.verify(self.root, 'outer-live', initrd=initrd)

    def test_old_kernel_left_behind_is_rejected(self):
        self.record()
        (self.root / 'boot/vmlinuz-6.12-old').write_bytes(b'old kernel')
        with self.assertRaisesRegex(ValueError, 'inventory_changed'):
            kernel.verify(self.root, 'outer-live')

    def test_changed_boot_image_is_rejected(self):
        value = self.record()
        (self.root / 'boot' / ('vmlinuz-' + value['abi'])).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'inventory_changed'):
            kernel.verify(self.root, 'outer-live')

    def test_kernel_without_kvm_is_rejected(self):
        value = self.record()
        (self.root / 'boot' / ('config-' + value['abi'])).write_text('# CONFIG_KVM is not set\n')
        with self.assertRaisesRegex(ValueError, 'requires_kvm'):
            kernel.verify(self.root, 'outer-live')

    @unittest.skipUnless(shutil.which('xorriso'), 'requires xorriso to verify the embedded ISO')
    def test_distinct_embedded_controller_is_verified_against_real_iso_and_boot_files(self):
        outer = self.record()
        controller = self.root / 'controller'
        value = self.record(abi='6.12.115+deb13.1-arm64', role='controller', root=controller)
        boot = self.root / 'iso/live'
        boot.mkdir(parents=True)
        shutil.copyfile(controller / 'boot' / ('vmlinuz-' + value['abi']), boot / 'vmlinuz')
        initrd = boot / 'initrd.img'
        initrd.write_bytes(b'non-executable controller initramfs fixture')
        value['initramfs'] = {'sha256': kernel.digest(initrd), 'hyperv_modules': []}
        bundle = self.root / 'bundle'
        runtime = bundle / 'runtime'
        runtime.mkdir(parents=True)
        shutil.copyfile(boot / 'vmlinuz', runtime / 'kernel')
        shutil.copyfile(initrd, runtime / 'initrd')
        record = bundle / 'evidence/runtime/hypervisor-kernel.json'
        record.parent.mkdir(parents=True)
        image = runtime / 'controller.iso'

        def build_iso():
            image.unlink(missing_ok=True)
            subprocess.run(['xorriso', '-as', 'mkisofs', '-quiet', '-o', str(image), str(boot.parent)],
                           check=True, capture_output=True)

        def write_bundle(evidence):
            record.write_text(json.dumps(evidence))
            (bundle / 'bundle.json').write_text(json.dumps({
                'format': 'oblivion-desktop', 'version': 1, 'platform': 'linux-arm64',
                'runtime': {'image': 'runtime/controller.iso', 'kernel': 'runtime/kernel', 'initrd': 'runtime/initrd'},
                'files': [{'path': path.relative_to(bundle).as_posix(), 'sha256': kernel.digest(path)}
                          for path in (record, image, runtime / 'kernel', runtime / 'initrd')]}))

        build_iso()
        write_bundle(value)
        self.assertEqual(kernel.verify(self.root, 'outer-live'), outer)
        self.assertNotEqual(value['kernel_sha256'], outer['kernel_sha256'])
        self.assertEqual(kernel.verify_controller(bundle, 'arm64'),
                         {**value, 'controller_iso_sha256': kernel.digest(image)})
        with self.assertRaisesRegex(ValueError, 'architecture_mismatch'):
            kernel.verify_controller(bundle, 'amd64')
        write_bundle({**value, 'role': 'outer-live'})
        with self.assertRaisesRegex(ValueError, 'role_mismatch'):
            kernel.verify_controller(bundle, 'arm64')
        write_bundle(value)
        (runtime / 'initrd').write_bytes(b'changed detached initrd')
        with self.assertRaisesRegex(ValueError, 'bundle_digest_mismatch:runtime/initrd'):
            kernel.verify_controller(bundle, 'arm64')
        write_bundle(value)
        with self.assertRaisesRegex(ValueError, 'boot_digest_mismatch:initrd.img'):
            kernel.verify_controller(bundle, 'arm64')
        shutil.copyfile(initrd, runtime / 'initrd')
        initrd.write_bytes(b'changed initrd inside ISO')
        build_iso()
        write_bundle(value)
        with self.assertRaisesRegex(ValueError, 'iso_boot_digest_mismatch:initrd.img'):
            kernel.verify_controller(bundle, 'arm64')

    def test_arm64_grub_enables_nested_mode_and_amd64_stays_unchanged(self):
        self.record()
        template = self.root / 'grub.cfg'
        source = "menuentry 'Live' {\n linux /live/vmlinuz boot=live components noswap\n}\n"
        template.write_text(source)
        self.assertIn(' boot=live kvm-arm.mode=nested components', kernel.grub(self.root, template, 'outer-live'))
        controller = self.root / 'controller'
        self.record(abi='6.12.115+deb13.1-arm64', role='controller', root=controller)
        self.assertEqual(kernel.grub(controller, template, 'controller'), source)
        for path in (self.root / 'boot').iterdir():
            path.unlink()
        self.record('amd64', '6.12.115+deb13-amd64')
        self.assertEqual(kernel.grub(self.root, template, 'outer-live'), source)


if __name__ == '__main__':
    unittest.main()
