"""Actual HCS per-boot NetworkManager profile and private publication."""
import configparser
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('runtime_network', Path(__file__).resolve().parents[1] / 'host/runtime-network.py')
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
IDENTITY = '00112233445566778899aabbccddeeff'


class RuntimeNetwork(unittest.TestCase):
    def arguments(self):
        return ['oblivion.runtime=1', 'oblivion.runtime-backend=hcs-hyperv',
                f'oblivion.runtime-id={IDENTITY}']

    def addresses(self):
        return ['oblivion.runtime-ipv4=172.30.14.18/28',
                'oblivion.runtime-gateway=172.30.14.17',
                'oblivion.runtime-mac=02:01:23:45:67:89']

    def test_static_keyfile_is_bound_to_ethernet_with_no_dns_or_ipv6(self):
        data = network.configuration(self.arguments() + self.addresses())
        keyfile = configparser.ConfigParser()
        keyfile.read_string(data.decode('ascii'))
        self.assertEqual(keyfile['connection']['uuid'], '00112233-4455-6677-8899-aabbccddeeff')
        self.assertEqual(keyfile['ethernet']['mac-address'], '02:01:23:45:67:89')
        self.assertEqual(keyfile['ipv4']['method'], 'manual')
        self.assertEqual(keyfile['ipv4']['address1'], '172.30.14.18/28,172.30.14.17')
        self.assertEqual(keyfile['ipv4']['ignore-auto-dns'], 'true')
        self.assertEqual(keyfile['ipv6']['method'], 'disabled')
        self.assertNotIn('dns', keyfile['ipv4'])
        self.assertNotIn('interface-name', keyfile['connection'])

    def test_offline_and_partial_or_repeated_boot_metadata_are_distinct(self):
        self.assertIsNone(network.configuration(self.arguments()))
        for fields in [self.addresses()[:1], self.addresses()[:2], self.addresses() + self.addresses()[:1]]:
            with self.assertRaisesRegex(RuntimeError, '^runtime_network_configuration_invalid$'):
                network.configuration(self.arguments() + fields)
        for backend in ['qemu-kvm', 'apple-vz', 'unknown']:
            with self.assertRaisesRegex(RuntimeError, '^hcs_runtime_profile_required$'):
                network.configuration([argument.replace('hcs-hyperv', backend) for argument in self.arguments()])

    def test_invalid_addresses_and_control_characters_never_enter_the_keyfile(self):
        for invalid in [
            'oblivion.runtime-ipv4=172.30.14.19/28',
            'oblivion.runtime-ipv4=172.30.14.18/24',
            'oblivion.runtime-ipv4=8.8.8.2/28',
            'oblivion.runtime-ipv4=::1/128',
            'oblivion.runtime-ipv4=172.30.14.18/28\n[secret]',
            'oblivion.runtime-gateway=172.30.14.16',
            'oblivion.runtime-gateway=172.30.15.17',
            'oblivion.runtime-mac=00:01:23:45:67:89',
            'oblivion.runtime-mac=02:01:23:45:67:89\nip=PRIVATE_CANARY',
        ]:
            name = invalid.split('=', 1)[0]
            arguments = self.arguments() + [invalid if field.startswith(name + '=') else field for field in self.addresses()]
            with self.assertRaisesRegex(RuntimeError, '^runtime_network_configuration_invalid$'):
                network.configuration(arguments)

    def test_profile_publication_is_private_atomic_and_ignores_a_replaced_leaf_link(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            foreign = directory / 'foreign'
            foreign.write_bytes(b'untouched')
            (directory / network.PROFILE).symlink_to(foreign)
            data = network.configuration(self.arguments() + self.addresses())
            network.publish(directory, data)
            published = directory / network.PROFILE
            self.assertFalse(published.is_symlink())
            self.assertEqual(published.read_bytes(), data)
            self.assertEqual(published.stat().st_mode & 0o777, 0o600)
            self.assertEqual(foreign.read_bytes(), b'untouched')
            self.assertFalse(list(directory.glob('.oblivion-runtime-*')))
            directory.chmod(0o777)
            with self.assertRaisesRegex(RuntimeError, '^private_runtime_network_directory_required$'):
                network.publish(directory, data)
            directory.chmod(0o700)


if __name__ == '__main__':
    unittest.main()
