import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

from native_fixture import vault, opencode
from oblivion_history.portable import export_histories, import_histories

spec = importlib.util.spec_from_file_location("prepare", Path(__file__).resolve().parents[1] / "prepare.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NativePrepareTests(unittest.TestCase):
    def test_no_pending_transfer_does_not_execute_a_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            module.prepare(vault(tmp), "/does-not-exist")

    def test_isolated_installed_entrypoint_finds_its_own_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve().parents[1] / "prepare.py"),
                                     "--vault", str(vault(tmp)), "--agent", "opencode2", "--binary", "/does-not-exist"],
                                    capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_native_import_preserves_transfer_for_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            opencode(source)
            archive = root / "native.jsonl"
            export_histories(source, None, archive)
            destination = vault(root / "target")
            import_histories(archive, destination)
            pending = next((destination / "state/oblivion/native-imports/opencode2").glob("*.json"))
            original = pending.read_bytes()
            with self.assertRaisesRegex(ValueError, "native_import_failed"):
                module.prepare(destination, "/usr/bin/false")
            self.assertEqual(pending.read_bytes(), original)
            self.assertFalse((destination / "state/opencode").exists())

    def test_present_matching_native_import_is_acknowledged_without_running_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            opencode(source)
            archive = root / "native.jsonl"
            export_histories(source, None, archive)
            destination = vault(root / "target")
            import_histories(archive, destination)
            _, imported_db = opencode(destination)
            pending = next((destination / "state/oblivion/native-imports/opencode2").glob("*.json"))
            module.prepare(destination, "/does-not-exist")
            self.assertFalse(pending.exists())
            self.assertTrue(imported_db.exists())

    def test_parent_cycles_are_rejected_before_running_an_importer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            opencode(source)
            archive = root / "native.jsonl"
            export_histories(source, None, archive)
            destination = vault(root / "target")
            import_histories(archive, destination)
            pending = next((destination / "state/oblivion/native-imports/opencode2").glob("*.json"))
            value = json.loads(pending.read_text())
            value["info"]["parentID"] = value["info"]["id"]
            pending.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "native_import_parent_cycle"):
                module.prepare(destination, "/does-not-exist")
            self.assertTrue(pending.exists())

    def test_existing_different_chat_is_not_overwritten_or_acknowledged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            opencode(source)
            archive = root / "native.jsonl"
            export_histories(source, None, archive)
            destination = vault(root / "target")
            import_histories(archive, destination)
            pending = next((destination / "state/oblivion/native-imports/opencode2").glob("*.json"))
            value = json.loads(pending.read_text())
            value["messages"][0]["text"] = "different history"
            pending.write_text(json.dumps(value))
            opencode(destination)
            with self.assertRaisesRegex(ValueError, "native_import_identity_conflict"):
                module.prepare(destination, "/does-not-exist")
            self.assertTrue(pending.exists())
