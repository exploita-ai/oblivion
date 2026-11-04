#!/usr/bin/python3
"""Build-time kernel selection for the outer Live OS and private controller.

ARM64 needs the KVM_CAP_ARM_EL2 UAPI introduced in Linux 6.16. Safe and gateway
images keep the stable kernel; this script is only used in their hypervisors.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


RECORD = Path('usr/share/oblivion/build/hypervisor-kernel.json')
SOURCE = 'https://deb.debian.org/debian'
HYPERV_DRIVERS = (
    ('CONFIG_HYPERV', 'hv_vmbus'),
    ('CONFIG_SCSI', 'scsi_mod'),
    ('CONFIG_HYPERV_STORAGE', 'hv_storvsc'),
    ('CONFIG_BLK_DEV_SD', 'sd_mod'),
    ('CONFIG_BLK_DEV_SR', 'sr_mod'),
    ('CONFIG_HYPERV_NET', 'hv_netvsc'),
    ('CONFIG_VSOCKETS', 'vsock'),
    ('CONFIG_HYPERV_VSOCKETS', 'hv_sock'),
    # The private bootstrap requires named virtio serial ports, not a console.
    ('CONFIG_VIRTIO_CONSOLE', 'virtio_console'),
    # Microsoft's reference WSL x86 config enables MMIO for its HCS virtio
    # devices. Keep this transport in the initrd; do not invent MMIO boot args.
    # https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.y/arch/x86/configs/config-wsl
    ('CONFIG_VIRTIO_MMIO', 'virtio_mmio'),
)


def run(*args):
    return subprocess.check_output(args, stdin=subprocess.DEVNULL, text=True)


def package(name):
    status, version = run('dpkg-query', '-W', '-f=${db:Status-Status}\t${Version}', name).strip().split('\t')
    if status != 'installed':
        raise ValueError('hypervisor_kernel_package_not_installed')
    return version


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def guest_drivers(root, architecture, abi):
    if architecture != 'amd64':
        return []
    config = (root / 'boot' / ('config-' + abi)).read_text()
    directory = root / 'lib/modules' / abi
    result = []
    for symbol, module in HYPERV_DRIVERS:
        selected = re.search(r'^' + symbol + r'=(y|m)$', config, re.M)
        if not selected:
            raise ValueError('hyperv_guest_driver_required:' + symbol)
        path = None
        if selected[1] == 'm':
            matches = [path for path in directory.rglob(module + '.ko*')
                       if path.name in (module + '.ko', module + '.ko.xz', module + '.ko.zst', module + '.ko.gz')]
            if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file() or matches[0].stat().st_size == 0:
                raise ValueError('hyperv_guest_module_required:' + module)
            path = matches[0]
        result.append({'config': symbol, 'mode': selected[1], 'module': module,
                       'path': path.relative_to(root).as_posix() if path else None,
                       'sha256': digest(path) if path else None})
    return result


def initramfs_inventory(record, entries):
    # Debian archives may place modules below /usr/lib on merged-/usr roots.
    paths = {entry.removeprefix('./').removeprefix('/').removeprefix('usr/') for entry in entries}
    required = [driver['path'] for driver in record['hyperv_guest_drivers'] if driver['mode'] == 'm']
    for path in required:
        if path not in paths:
            raise ValueError('hyperv_initramfs_module_missing:' + Path(path).name)
    return required


def verify(root, controller=None, initrd=None):
    record = json.loads((root / RECORD).read_text())
    if record['version'] != 1 or record['architecture'] not in ('amd64', 'arm64'):
        raise ValueError('invalid_hypervisor_kernel_record')
    kernels = list((root / 'boot').glob('vmlinuz-*'))
    if len(kernels) != 1 or kernels[0].name != 'vmlinuz-' + record['abi'] or kernels[0].is_symlink() or digest(kernels[0]) != record['kernel_sha256']:
        raise ValueError('hypervisor_kernel_inventory_changed')
    version = re.match(r'^(\d+)\.(\d+)', record['abi'])
    if not version or record['architecture'] == 'arm64' and tuple(map(int, version.groups())) < (6, 16):
        raise ValueError('arm64_nested_kernel_requires_linux_6_16')
    config = (root / 'boot' / ('config-' + record['abi'])).read_text()
    if not re.search(r'^CONFIG_KVM=(y|m)$', config, re.M):
        raise ValueError('hypervisor_kernel_requires_kvm')
    arguments = {'outer-live': ['kvm-arm.mode=nested'] if record['architecture'] == 'arm64' else [], 'controller': []}
    if record['boot_arguments'] != arguments:
        raise ValueError('hypervisor_kernel_boot_mode_changed')
    if record['hyperv_guest_drivers'] != guest_drivers(root, record['architecture'], record['abi']):
        raise ValueError('hyperv_guest_driver_inventory_changed')
    if controller:
        expected = json.loads(controller.read_text())
        if any(record[key] != expected[key] for key in ('architecture', 'abi', 'kernel_package', 'kernel_version', 'kernel_sha256', 'hyperv_guest_drivers')):
            raise ValueError('live_and_controller_kernel_differ')
    if initrd:
        if initrd.is_symlink() or not initrd.is_file():
            raise ValueError('hypervisor_initramfs_required')
        record['initramfs'] = {'sha256': digest(initrd),
                              'hyperv_modules': initramfs_inventory(record, run('lsinitramfs', str(initrd)).splitlines())}
    return record


def install(architecture, requested):
    if os.geteuid() != 0 or run('dpkg', '--print-architecture').strip() != architecture or architecture not in ('amd64', 'arm64'):
        raise ValueError('matching_debian_build_root_required')
    if requested and (len(requested) > 128 or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*', requested)):
        raise ValueError('invalid_development_kernel_version')
    meta = 'linux-image-' + architecture
    original = [line.split('\t')[0] for line in run('dpkg-query', '-W', '-f=${Package}\t${db:Status-Status}\n', 'linux-image-[0-9]*').splitlines() if line.endswith('\tinstalled')]
    backports = architecture == 'arm64' or bool(requested)
    if backports:
        Path('/etc/apt/sources.list.d/oblivion-kernel.list').write_text('deb ' + SOURCE + ' trixie-backports main\n')
        subprocess.run(['apt-get', 'update'], check=True, stdin=subprocess.DEVNULL)
        subprocess.run(['apt-get', 'install', '-y', '--no-install-recommends', '-t', 'trixie-backports', meta + ('=' + requested if requested else '')], check=True, stdin=subprocess.DEVNULL)
    meta_version = package(meta)
    if requested and meta_version != requested:
        raise ValueError('development_kernel_version_changed')
    # The signed Debian meta-package identifies the one exact ABI to keep.
    dependencies = run('dpkg-query', '-W', '-f=${Depends}', meta)
    images = re.findall(r'(?<![A-Za-z0-9-])(linux-image-[0-9][A-Za-z0-9.+\-]*)(?=\s|,|$)', dependencies)
    if len(images) != 1:
        raise ValueError('one_hypervisor_kernel_dependency_required')
    image = images[0]
    version = package(image)
    files = run('dpkg-query', '-L', image).splitlines()
    boot = [Path(path) for path in files if path.startswith('/boot/vmlinuz-')]
    if len(boot) != 1 or not boot[0].is_file():
        raise ValueError('one_hypervisor_boot_kernel_required')
    abi = boot[0].name.removeprefix('vmlinuz-')
    numerical = re.match(r'^(\d+)\.(\d+)', abi)
    if architecture == 'arm64' and (not numerical or tuple(map(int, numerical.groups())) < (6, 16)):
        raise ValueError('arm64_nested_kernel_requires_linux_6_16')
    obsolete = [name for name in original if name != image]
    if obsolete:
        subprocess.run(['apt-get', 'purge', '-y', '--', *obsolete], check=True, stdin=subprocess.DEVNULL)
    destination = Path('/') / RECORD
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    destination.write_text(json.dumps({'version': 1, 'architecture': architecture,
                                     'suite': 'trixie-backports' if backports else 'trixie',
                                     'repository': SOURCE, 'development_override': requested or None,
                                     'meta_package': meta, 'meta_version': meta_version,
                                     'kernel_package': image, 'kernel_version': version,
                                     'abi': abi, 'kernel_sha256': digest(boot[0]),
                                     'arm64_minimum_kernel': '6.16',
                                     'hyperv_guest_drivers': guest_drivers(Path('/'), architecture, abi),
                                     'boot_arguments': {'outer-live': ['kvm-arm.mode=nested'] if architecture == 'arm64' else [], 'controller': []}}, sort_keys=True, indent=2) + '\n')
    verify(Path('/'))


def grub(root, template, role):
    record = verify(root)
    source = template.read_text()
    if source.count(' boot=live ') != 1 or 'kvm-arm.mode=' in source:
        raise ValueError('one_canonical_live_boot_entry_required')
    arguments = ' '.join(record['boot_arguments'][role])
    return source.replace(' boot=live ', ' boot=live ' + arguments + (' ' if arguments else ''), 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    selection = commands.add_parser('install')
    selection.add_argument('architecture', choices=('amd64', 'arm64'))
    selection.add_argument('--version', default='')
    check = commands.add_parser('verify')
    check.add_argument('root', type=Path)
    check.add_argument('--controller', type=Path)
    check.add_argument('--initrd', type=Path)
    modules = commands.add_parser('initramfs-modules')
    modules.add_argument('root', type=Path)
    boot = commands.add_parser('grub')
    boot.add_argument('root', type=Path)
    boot.add_argument('template', type=Path)
    boot.add_argument('--role', choices=('outer-live', 'controller'), required=True)
    args = parser.parse_args()
    if args.operation == 'install':
        install(args.architecture, args.version)
        return
    if args.operation == 'grub':
        print(grub(args.root, args.template, args.role), end='')
        return
    if args.operation == 'initramfs-modules':
        for driver in verify(args.root)['hyperv_guest_drivers']:
            if driver['mode'] == 'm':
                print(driver['module'])
        return
    print(json.dumps(verify(args.root, args.controller, args.initrd), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
