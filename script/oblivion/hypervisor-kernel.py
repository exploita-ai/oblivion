#!/usr/bin/python3
"""Build-time kernel selection for the outer Live OS and private controller.

The outer ARM64 Live OS needs the KVM_CAP_ARM_EL2 UAPI introduced in Linux
6.16. The controller runs EL1 guests and uses the stable Debian kernel.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


RECORD = Path('usr/share/oblivion/build/hypervisor-kernel.json')
SOURCE = 'https://deb.debian.org/debian'
SECURITY_SOURCE = 'https://deb.debian.org/debian-security'
ARCHITECTURES = ('amd64', 'arm64')
ARM64_MINIMUM = {'controller': (6, 12), 'outer-live': (6, 16)}
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


def package_source(name, version, backports):
    archives = ({'trixie-backports': SOURCE} if backports
                else {'trixie-security': SECURITY_SOURCE, 'trixie-updates': SOURCE, 'trixie': SOURCE})
    candidates = set()
    for line in run('apt-cache', 'madison', name).splitlines():
        _, selected, location = (field.strip() for field in line.split('|', 2))
        if selected == version:
            repository, release, *_ = location.split()
            suite = release.split('/', 1)[0]
            if repository.replace('http://', 'https://', 1) == archives.get(suite):
                candidates.add(suite)
    for suite, repository in archives.items():
        if suite in candidates:
            return suite, repository
    raise ValueError('hypervisor_kernel_package_source_not_verified')


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


def boot_arguments(role, architecture):
    return ['kvm-arm.mode=nested'] if role == 'outer-live' and architecture == 'arm64' else []


def verify_record(record, role, architecture=None):
    if record['version'] != 2 or record['architecture'] not in ARCHITECTURES:
        raise ValueError('invalid_hypervisor_kernel_record')
    if record['role'] != role:
        raise ValueError('hypervisor_kernel_role_mismatch')
    if architecture is not None and record['architecture'] != architecture:
        raise ValueError('hypervisor_kernel_architecture_mismatch')
    if not record['abi'].endswith('-' + record['architecture']):
        raise ValueError('hypervisor_kernel_abi_architecture_mismatch')
    if record['kernel_package'] != 'linux-image-' + record['abi']:
        raise ValueError('hypervisor_kernel_package_abi_mismatch')
    version = re.match(r'^(\d+)\.(\d+)', record['abi'])
    if not version:
        raise ValueError('invalid_hypervisor_kernel_abi')
    minimum = ARM64_MINIMUM[role]
    if record['architecture'] == 'arm64' and tuple(map(int, version.groups())) < minimum:
        raise ValueError('arm64_' + role + '_kernel_requires_linux_%d_%d' % minimum)
    if record['boot_arguments'] != boot_arguments(role, record['architecture']):
        raise ValueError('hypervisor_kernel_boot_mode_changed')


def verify(root, role, initrd=None, architecture=None):
    record = json.loads((root / RECORD).read_text())
    verify_record(record, role, architecture)
    kernels = list((root / 'boot').glob('vmlinuz-*'))
    if len(kernels) != 1 or kernels[0].name != 'vmlinuz-' + record['abi'] or kernels[0].is_symlink() or digest(kernels[0]) != record['kernel_sha256']:
        raise ValueError('hypervisor_kernel_inventory_changed')
    config = (root / 'boot' / ('config-' + record['abi'])).read_text()
    if not re.search(r'^CONFIG_KVM=(y|m)$', config, re.M):
        raise ValueError('hypervisor_kernel_requires_kvm')
    if record['hyperv_guest_drivers'] != guest_drivers(root, record['architecture'], record['abi']):
        raise ValueError('hyperv_guest_driver_inventory_changed')
    if initrd is not None:
        if initrd.name != 'initrd.img-' + record['abi'] or initrd.is_symlink() or not initrd.is_file():
            raise ValueError('hypervisor_initramfs_required')
        record['initramfs'] = {'sha256': digest(initrd),
                              'hyperv_modules': initramfs_inventory(record, run('lsinitramfs', str(initrd)).splitlines())}
    return record


def verify_controller(bundle, architecture):
    record_path = 'evidence/runtime/hypervisor-kernel.json'
    image_path = 'runtime/controller.iso'
    kernel_path = 'runtime/kernel'
    initrd_path = 'runtime/initrd'
    manifest = json.loads((bundle / 'bundle.json').read_text())
    platform = 'linux-arm64' if architecture == 'arm64' else 'linux-x86_64'
    if (manifest['format'] != 'oblivion-desktop' or manifest['version'] != 1 or manifest['platform'] != platform
            or manifest['runtime'] != {'image': image_path, 'kernel': kernel_path, 'initrd': initrd_path}):
        raise ValueError('embedded_controller_bundle_role_or_architecture_mismatch')
    hashes = {}
    for name in (record_path, image_path, kernel_path, initrd_path):
        entries = [item for item in manifest['files'] if item['path'] == name]
        path = bundle / name
        if len(entries) != 1 or path.is_symlink() or not path.is_file():
            raise ValueError('embedded_controller_file_required:' + name)
        actual = digest(path)
        if actual != entries[0]['sha256']:
            raise ValueError('embedded_controller_bundle_digest_mismatch:' + name)
        hashes[name] = actual
    record = json.loads((bundle / record_path).read_text())
    verify_record(record, 'controller', architecture)
    expected = {'vmlinuz': record['kernel_sha256'], 'initrd.img': record['initramfs']['sha256']}
    for name, path in (('vmlinuz', kernel_path), ('initrd.img', initrd_path)):
        if hashes[path] != expected[name]:
            raise ValueError('embedded_controller_boot_digest_mismatch:' + name)
    with tempfile.TemporaryDirectory(prefix='oblivion-controller-boot-') as temporary:
        boot = Path(temporary)
        run('xorriso', '-abort_on', 'FAILURE', '-report_about', 'FAILURE', '-osirrox', 'on',
            '-indev', str(bundle / image_path), '-extract', '/live/vmlinuz', str(boot / 'vmlinuz'),
            '-extract', '/live/initrd.img', str(boot / 'initrd.img'))
        for name, sha256 in expected.items():
            path = boot / name
            if path.is_symlink() or not path.is_file() or digest(path) != sha256:
                raise ValueError('embedded_controller_iso_boot_digest_mismatch:' + name)
    return {**record, 'controller_iso_sha256': hashes[image_path]}


def install(architecture, role, requested):
    if os.geteuid() != 0 or run('dpkg', '--print-architecture').strip() != architecture:
        raise ValueError('matching_debian_build_root_required')
    if requested and (len(requested) > 128 or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*', requested)):
        raise ValueError('invalid_development_kernel_version')
    meta = 'linux-image-' + architecture
    original = [line.split('\t')[0] for line in run('dpkg-query', '-W', '-f=${Package}\t${db:Status-Status}\n', 'linux-image-[0-9]*').splitlines() if line.endswith('\tinstalled')]
    backports = (architecture == 'arm64' and role == 'outer-live') or bool(requested)
    install_options = []
    if backports:
        Path('/etc/apt/sources.list.d/oblivion-kernel.list').write_text('deb ' + SOURCE + ' trixie-backports main\n')
        subprocess.run(['apt-get', 'update'], check=True, stdin=subprocess.DEVNULL)
        install_options = ['-t', 'trixie-backports']
    # The stable sources include trixie-security. Keep their normal equal
    # priority so APT selects the newest signed stable meta-package.
    subprocess.run(['apt-get', 'install', '-y', '--no-install-recommends', *install_options,
                    meta + ('=' + requested if requested else '')], check=True, stdin=subprocess.DEVNULL)
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
    suite, repository = package_source(image, version, backports)
    # Split Debian kernel packages install the boot file through a hook, so
    # the versioned linux-image package may not list it in its payload.
    abi = image.removeprefix('linux-image-')
    boot = Path('/boot') / ('vmlinuz-' + abi)
    if boot.is_symlink() or not boot.is_file():
        raise ValueError('one_hypervisor_boot_kernel_required')
    record = {'version': 2, 'architecture': architecture, 'role': role, 'suite': suite,
              'repository': repository, 'development_override': requested or None,
              'meta_package': meta, 'meta_version': meta_version,
              'kernel_package': image, 'kernel_version': version,
              'abi': abi, 'kernel_sha256': digest(boot),
              'arm64_minimum_kernel': '%d.%d' % ARM64_MINIMUM[role],
              'hyperv_guest_drivers': guest_drivers(Path('/'), architecture, abi),
              'boot_arguments': boot_arguments(role, architecture)}
    verify_record(record, role, architecture)
    obsolete = [name for name in original if name != image]
    if obsolete:
        subprocess.run(['apt-get', 'purge', '-y', '--', *obsolete], check=True, stdin=subprocess.DEVNULL)
    destination = Path('/') / RECORD
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    verify(Path('/'), role, architecture=architecture)


def grub(root, template, role):
    record = verify(root, role)
    source = template.read_text()
    if source.count(' boot=live ') != 1 or 'kvm-arm.mode=' in source:
        raise ValueError('one_canonical_live_boot_entry_required')
    arguments = ' '.join(record['boot_arguments'])
    return source.replace(' boot=live ', ' boot=live ' + arguments + (' ' if arguments else ''), 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    selection = commands.add_parser('install')
    selection.add_argument('architecture', choices=ARCHITECTURES)
    selection.add_argument('--version', default='')
    check = commands.add_parser('verify')
    check.add_argument('root', type=Path)
    check.add_argument('--initrd', type=Path)
    check.add_argument('--architecture', choices=ARCHITECTURES)
    embedded = commands.add_parser('verify-controller')
    embedded.add_argument('bundle', type=Path)
    embedded.add_argument('architecture', choices=ARCHITECTURES)
    modules = commands.add_parser('initramfs-modules')
    modules.add_argument('root', type=Path)
    boot = commands.add_parser('grub')
    boot.add_argument('root', type=Path)
    boot.add_argument('template', type=Path)
    for command in (selection, check, modules, boot):
        command.add_argument('--role', choices=ARM64_MINIMUM, required=True)
    args = parser.parse_args()
    if args.operation == 'install':
        install(args.architecture, args.role, args.version)
        return
    if args.operation == 'grub':
        print(grub(args.root, args.template, args.role), end='')
        return
    if args.operation == 'initramfs-modules':
        for driver in verify(args.root, args.role)['hyperv_guest_drivers']:
            if driver['mode'] == 'm':
                print(driver['module'])
        return
    if args.operation == 'verify-controller':
        print(json.dumps(verify_controller(args.bundle, args.architecture), sort_keys=True))
        return
    print(json.dumps(verify(args.root, args.role, args.initrd, args.architecture), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
