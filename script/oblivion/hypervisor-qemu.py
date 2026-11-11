#!/usr/bin/python3
"""Select and evidence QEMU for the outer Live hypervisor, not its EL1 guests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


RECORD = Path('usr/share/oblivion/build/hypervisor-qemu.json')
SOURCE = 'https://deb.debian.org/debian'


def policy(architecture):
    if architecture == 'arm64':
        # KVM_ARM_VCPU_HAS_EL2 initialization first ships in QEMU 10.1.
        return ('qemu-system-arm', 'qemu-system-aarch64', 'trixie-backports', (10, 1, 0))
    if architecture == 'amd64':
        return ('qemu-system-x86', 'qemu-system-x86_64', 'trixie', None)
    raise ValueError('unsupported_hypervisor_architecture')


def version(output):
    if not output or len(output.encode()) > 4096:
        raise ValueError('invalid_qemu_version')
    first = output.splitlines()[0]
    match = re.fullmatch(r'QEMU emulator version ([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})(?: \([^\r\n]*\))?', first)
    if not match:
        raise ValueError('invalid_qemu_version')
    return tuple(map(int, match.groups()))


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def verify(root):
    record = json.loads((root / RECORD).read_text())
    if not isinstance(record, dict) or set(record) != {'version', 'architecture', 'package', 'package_version', 'suite', 'repository', 'binary', 'binary_sha256', 'reported_version'} or type(record['version']) is not int or record['version'] != 1:
        raise ValueError('invalid_hypervisor_qemu_record')
    package, binary, suite, minimum = policy(record['architecture'])
    if (record['package'], record['binary'], record['suite'], record['repository']) != (package, 'usr/bin/' + binary, suite, SOURCE):
        raise ValueError('hypervisor_qemu_policy_changed')
    reported = record['reported_version']
    if not isinstance(reported, list) or len(reported) != 3 or any(type(part) is not int or not 0 <= part <= 9999 for part in reported):
        raise ValueError('invalid_qemu_version')
    if minimum and tuple(reported) < minimum:
        raise ValueError('arm64_nested_qemu_requires_10_1')
    if not isinstance(record['package_version'], str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]{0,127}', record['package_version']):
        raise ValueError('invalid_qemu_package_version')
    executable = root / record['binary']
    if executable.is_symlink() or not executable.is_file() or not executable.stat().st_mode & 0o111 or digest(executable) != record['binary_sha256']:
        raise ValueError('hypervisor_qemu_inventory_changed')
    return record


def install(architecture):
    if os.geteuid() != 0 or subprocess.check_output(['dpkg', '--print-architecture'], text=True, stdin=subprocess.DEVNULL).strip() != architecture:
        raise ValueError('matching_debian_build_root_required')
    package, binary, suite, minimum = policy(architecture)
    if architecture == 'arm64':
        # The kernel installer owns this same signed Debian backports source.
        Path('/etc/apt/sources.list.d/oblivion-kernel.list').write_text('deb ' + SOURCE + ' trixie-backports main\n')
        subprocess.run(['apt-get', 'update'], check=True, stdin=subprocess.DEVNULL)
    # amd64 keeps normal stable/security candidate priority. A target release
    # there could prefer an older stable build over its security update.
    subprocess.run(['apt-get', 'install', '-y', '--no-install-recommends',
                    *(['-t', suite] if architecture == 'arm64' else []), package],
                   check=True, stdin=subprocess.DEVNULL)
    executable = Path('/usr/bin') / binary
    reported = version(subprocess.check_output([str(executable), '--version'], text=True, stdin=subprocess.DEVNULL, timeout=5))
    if minimum and reported < minimum:
        raise ValueError('arm64_nested_qemu_requires_10_1')
    installed = subprocess.check_output(['dpkg-query', '-W', '-f=${db:Status-Status}\t${Version}', package], text=True, stdin=subprocess.DEVNULL).strip().split('\t')
    if len(installed) != 2 or installed[0] != 'installed':
        raise ValueError('hypervisor_qemu_package_not_installed')
    destination = Path('/') / RECORD
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    destination.write_text(json.dumps({'version': 1, 'architecture': architecture,
                                     'package': package, 'package_version': installed[1],
                                     'suite': suite, 'repository': SOURCE,
                                     'binary': executable.relative_to('/').as_posix(),
                                     'binary_sha256': digest(executable),
                                     'reported_version': reported}, sort_keys=True, indent=2) + '\n')
    verify(Path('/'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    selection = commands.add_parser('install')
    selection.add_argument('architecture', choices=('amd64', 'arm64'))
    check = commands.add_parser('verify')
    check.add_argument('root', type=Path)
    args = parser.parse_args()
    if args.operation == 'install':
        install(args.architecture)
        return
    print(json.dumps(verify(args.root), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
