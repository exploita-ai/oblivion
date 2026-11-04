#!/usr/bin/python3
"""Per-boot IPv4 for the owned HCS controller; no persistent OS preferences."""
import ipaddress
import os
from pathlib import Path
import re
import uuid

DIRECTORY = Path('/run/NetworkManager/system-connections')
PROFILE = 'oblivion-runtime.nmconnection'
FIELDS = ('oblivion.runtime-ipv4=', 'oblivion.runtime-gateway=', 'oblivion.runtime-mac=')
PRIVATE = tuple(ipaddress.IPv4Network(prefix) for prefix in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def configuration(arguments):
    if arguments.count('oblivion.runtime=1') != 1 or [argument for argument in arguments if argument.startswith('oblivion.runtime-backend=')] != ['oblivion.runtime-backend=hcs-hyperv']:
        raise RuntimeError('hcs_runtime_profile_required')
    identities = [argument.removeprefix('oblivion.runtime-id=') for argument in arguments if argument.startswith('oblivion.runtime-id=')]
    if len(identities) != 1 or not re.fullmatch(r'[0-9a-f]{32}', identities[0]) or int(identities[0], 16) == 0:
        raise RuntimeError('runtime_identity_required')
    selected = [[argument.removeprefix(field) for argument in arguments if argument.startswith(field)] for field in FIELDS]
    if not any(selected):
        return None
    if any(len(values) != 1 for values in selected):
        raise RuntimeError('runtime_network_configuration_invalid')
    address, gateway, mac = [values[0] for values in selected]
    try:
        interface = ipaddress.IPv4Interface(address)
        router = ipaddress.IPv4Address(gateway)
    except ValueError:
        raise RuntimeError('runtime_network_configuration_invalid') from None
    network = interface.network
    if address != str(interface) or gateway != str(router) or network.prefixlen != 28 or not any(network.subnet_of(prefix) for prefix in PRIVATE) or interface.ip != network.network_address + 2 or router != network.network_address + 1 or not re.fullmatch(r'02(?::[0-9a-f]{2}){5}', mac):
        raise RuntimeError('runtime_network_configuration_invalid')
    return '\n'.join((
        '[connection]', 'id=Oblivion runtime', f'uuid={uuid.UUID(hex=identities[0])}',
        'type=ethernet', 'autoconnect=true', 'autoconnect-priority=999',
        '', '[ethernet]', f'mac-address={mac}',
        '', '[ipv4]', 'method=manual', f'address1={address},{gateway}',
        'ignore-auto-dns=true', 'may-fail=false',
        '', '[ipv6]', 'method=disabled', '',
    )).encode('ascii')


def publish(directory, data):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = '.oblivion-runtime-' + os.urandom(16).hex()
    created = False
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise RuntimeError('private_runtime_network_directory_required')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=descriptor)
        created = True
        with os.fdopen(fd, 'wb') as target:
            target.write(data)
        os.replace(temporary, PROFILE, src_dir_fd=descriptor, dst_dir_fd=descriptor)
    finally:
        if created:
            try:
                os.unlink(temporary, dir_fd=descriptor)
            except FileNotFoundError:
                pass
        os.close(descriptor)


def main():
    if os.geteuid() != 0:
        raise RuntimeError('root_required')
    data = configuration(Path('/proc/cmdline').read_text().split())
    if data is None:
        # An offline HCS VM must have no synthetic Ethernet device. Do not let
        # NetworkManager invent a DHCP profile if the boot metadata is missing.
        for device in Path('/sys/class/net').iterdir():
            driver = device / 'device/driver'
            if driver.exists() and driver.resolve().name == 'hv_netvsc':
                raise RuntimeError('runtime_network_configuration_required')
        return
    publish(DIRECTORY, data)


if __name__ == '__main__':
    main()
