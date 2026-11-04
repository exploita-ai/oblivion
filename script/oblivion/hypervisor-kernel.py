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


def verify(root, controller=None):
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
    if controller:
        expected = json.loads(controller.read_text())
        if any(record[key] != expected[key] for key in ('architecture', 'abi', 'kernel_package', 'kernel_version', 'kernel_sha256')):
            raise ValueError('live_and_controller_kernel_differ')
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
    print(json.dumps(verify(args.root, args.controller), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
