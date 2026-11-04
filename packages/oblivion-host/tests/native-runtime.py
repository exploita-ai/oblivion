"""Production native-runtime selection against actual temporary sysfs trees."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import uuid

HOST = Path(__file__).resolve().parents[1] / "host"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HOST / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = load("runtime_prepare", "runtime-prepare.py")
bootstrap = load("runtime_bootstrap", "runtime-auth.py")
relay = load("runtime_relay", "control-relay.py")
IDENTITY = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")


class Sysfs:
    def __init__(self, root):
        self.root = root
        self.blocks = root / "class/block"
        self.blocks.mkdir(parents=True)
        self.controller = root / "devices/platform/VMBUS:00" / str(IDENTITY)
        self.controller.mkdir(parents=True)
        drivers = root / "bus/vmbus/drivers/hv_storvsc"
        drivers.mkdir(parents=True)
        devices = root / "bus/vmbus/devices"
        devices.mkdir()
        (devices / str(IDENTITY)).symlink_to(self.controller, target_is_directory=True)
        (self.controller / "driver").symlink_to(drivers, target_is_directory=True)
        (self.controller / "class_id").write_text(prepare.SCSI_CLASS + "\n")
        (self.controller / "device_id").write_text("{" + str(IDENTITY) + "}\n")

    def disk(self, name="sdb", host=7, lun=1, controller=None, kind="0"):
        controller = controller or self.controller
        scsi = controller / f"host{host}/target{host}:0:0/{host}:0:0:{lun}"
        block = scsi / "block" / name
        block.mkdir(parents=True)
        (scsi / "type").write_text(kind + "\n")
        (block / "device").symlink_to(scsi, target_is_directory=True)
        (block / "ro").write_text("0\n")
        (block / "size").write_text(str(8 * 1024**3 // 512) + "\n")
        (block / "dev").write_text("8:16\n")
        (block / "holders").mkdir()
        (self.blocks / name).symlink_to(block, target_is_directory=True)
        return block


class NativeRuntime(unittest.TestCase):
    def test_hcs_profile_uses_the_same_private_token_path_as_qemu(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_bytes(bytes(range(32)))
            token.chmod(0o600)
            for backend in ["apple-vz", "qemu-kvm", "hcs-hyperv"]:
                arguments = ["oblivion.runtime=1", f"oblivion.runtime-backend={backend}", f"oblivion.runtime-id={IDENTITY.hex}"]
                self.assertEqual(bootstrap.profile(arguments), backend)
                self.assertEqual(prepare.profile(arguments), (backend, IDENTITY))
                value = relay.runtime_token(arguments, token)
                if backend == "apple-vz":
                    self.assertIsNone(value)
                else:
                    self.assertEqual(value, bytearray(range(32)))
                    value[:] = bytes(32)
            token.unlink()
            for backend in ["qemu-kvm", "hcs-hyperv"]:
                with self.assertRaises(FileNotFoundError):
                    relay.runtime_token(["oblivion.runtime=1", f"oblivion.runtime-backend={backend}"], token)

    def test_unknown_or_ambiguous_backend_is_rejected(self):
        for arguments in [
            [], ["oblivion.runtime=1"],
            ["oblivion.runtime=1", "oblivion.runtime-backend=unknown"],
            ["oblivion.runtime=1", "oblivion.runtime-backend=hcs-hyperv", "oblivion.runtime-backend=qemu-kvm"],
        ]:
            with self.assertRaises(ValueError):
                bootstrap.profile(arguments)
            with self.assertRaises((ValueError, RuntimeError)):
                prepare.profile(arguments)
            with self.assertRaises(ValueError):
                relay.runtime_token(arguments)

    def test_hcs_selects_only_the_configured_controller_data_lun_independent_of_sd_name(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Sysfs(Path(directory))
            tree.disk("sda", lun=0, kind="5")  # Read-only live ISO, not data.
            expected = tree.disk("sdaz")
            foreign = tree.root / "devices/platform/VMBUS:00/foreign"
            tree.disk("sdc", controller=foreign)
            selected, size = prepare.select_disk("hcs-hyperv", IDENTITY, tree.root)
            self.assertEqual(selected.resolve(), expected.resolve())
            self.assertEqual(size, 8 * 1024**3)
            # A regular file or char node is never allowed to become an mkfs target.
            fake = tree.root / "sdaz"
            fake.write_text("foreign bytes")
            with self.assertRaisesRegex(RuntimeError, "runtime_block_device_required"):
                prepare.device_metadata(fake, selected)

    def test_no_or_multiple_configured_data_luns_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Sysfs(Path(directory))
            tree.disk("sda", lun=0)
            with self.assertRaisesRegex(RuntimeError, "runtime_scsi_disk_required"):
                prepare.select_disk("hcs-hyperv", IDENTITY, tree.root)
            tree.disk("sdb")
            tree.disk("sdc", host=8)
            with self.assertRaisesRegex(RuntimeError, "runtime_scsi_disk_required"):
                prepare.select_disk("hcs-hyperv", IDENTITY, tree.root)

    def test_wrong_controller_identity_class_or_driver_cannot_select_a_disk(self):
        for field in ["device_id", "class_id", "driver"]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                tree = Sysfs(Path(directory))
                tree.disk()
                path = tree.controller / field
                if field == "driver":
                    path.unlink()
                    foreign = tree.root / "bus/vmbus/drivers/other"
                    foreign.mkdir()
                    path.symlink_to(foreign, target_is_directory=True)
                else:
                    path.write_text("{00000000-0000-0000-0000-000000000001}\n")
                with self.assertRaisesRegex(RuntimeError, "runtime_scsi_controller_required"):
                    prepare.select_disk("hcs-hyperv", IDENTITY, tree.root)

    def test_readonly_partition_holder_and_invalid_size_fail_before_device_access(self):
        for invalid in ["readonly", "partition", "child-partition", "holder", "small", "large"]:
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory:
                tree = Sysfs(Path(directory))
                block = tree.disk()
                if invalid == "readonly":
                    (block / "ro").write_text("1\n")
                elif invalid == "partition":
                    (block / "partition").write_text("1\n")
                elif invalid == "child-partition":
                    (block / "sdb1").mkdir()
                    (block / "sdb1/partition").write_text("1\n")
                elif invalid == "holder":
                    (block / "holders/dm-0").write_text("")
                else:
                    (block / "size").write_text(str((1 if invalid == "small" else 2048) * 1024**3 // 512))
                with self.assertRaises(RuntimeError):
                    prepare.select_disk("hcs-hyperv", IDENTITY, tree.root)

    def test_existing_virtio_profiles_keep_vdb_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Sysfs(Path(directory))
            block = tree.root / "devices/pci/virtio2/block/vdb"
            block.mkdir(parents=True)
            (block / "device").symlink_to(block.parent.parent, target_is_directory=True)
            (block / "ro").write_text("0\n")
            (block / "size").write_text(str(8 * 1024**3 // 512))
            (block / "holders").mkdir()
            (tree.blocks / "vdb").symlink_to(block, target_is_directory=True)
            for backend in ["apple-vz", "qemu-kvm"]:
                selected, size = prepare.select_disk(backend, IDENTITY, tree.root)
                self.assertEqual(selected.name, "vdb")
                self.assertEqual(size, 8 * 1024**3)


if __name__ == "__main__":
    unittest.main()
