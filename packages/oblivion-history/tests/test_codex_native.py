import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid

from native_fixture import vault, codex, codex_index
from oblivion_history.artifacts import files
from oblivion_history.portable import export_histories, import_histories, native_histories


class CodexNativeTests(unittest.TestCase):
    def test_revert_generations_and_fork_prefixes_keep_exact_paths_and_byte_offsets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            _, parent, parent_rows = codex(source)
            parent_rows[-1]["payload"]["output"] = "UNSELECTED-PARENT-FUTURE-CONTENT"
            parent_bytes = b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode() for row in parent_rows)
            parent.write_bytes(parent_bytes)
            prefix = b"".join(parent_bytes.splitlines(keepends=True)[:3])
            child_ref, child, child_rows = codex(source)
            child_rows[0]["payload"]["history_base"] = {"thread_id": parent_rows[0]["payload"]["id"], "end_ordinal_exclusive": 3, "end_byte_offset": len(prefix)}
            child_bytes = b"".join((json.dumps(row) + "\n").encode() for row in child_rows)
            child.write_bytes(child_bytes)
            logical_id = child_rows[0]["payload"]["id"]
            physical_id = str(uuid.uuid4())
            reverted = child.parent / ("rollout-2026-11-04T13-00-00-" + physical_id + ".jsonl")
            reverted_rows = json.loads(json.dumps(child_rows))
            reverted_rows[0]["payload"]["history_base"] = {"thread_id": logical_id, "end_ordinal_exclusive": 5, "end_byte_offset": len(child_bytes)}
            reverted_bytes = b"".join((json.dumps(row) + "\n").encode() for row in reverted_rows)
            reverted.write_bytes(reverted_bytes)
            codex_index(source, logical_id, reverted)
            entry = next(row for row in native_histories(source) if row["id"] == child_ref)
            self.assertEqual(len(files([row for row in entry["records"] if row.get("type") != "codex-index"])), 3)
            self.assertEqual(entry["required_prefixes"], 2)
            archive = root / "native.jsonl"
            export_histories(source, [child_ref], archive)
            destination = vault(root / "target")
            import_histories(archive, destination)
            for original, expected in ((parent, prefix), (child, child_bytes), (reverted, reverted_bytes)):
                path = destination / "home/.codex" / original.relative_to(source / "home/.codex")
                self.assertEqual(path.read_bytes(), expected)
            self.assertNotIn(b"UNSELECTED-PARENT-FUTURE-CONTENT", (destination / "home/.codex" / parent.relative_to(source / "home/.codex")).read_bytes())

    def test_current_native_legacy_mode_is_supported_without_conversion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            selected, path, rows = codex(source)
            rows[0]["payload"]["history_mode"] = "legacy"
            data = b"".join((json.dumps(row) + "\n").encode() for row in rows)
            path.write_bytes(data)
            archive = root / "native.jsonl"
            export_histories(source, [selected], archive)
            destination = vault(root / "target")
            import_histories(archive, destination)
            self.assertEqual(next((destination / "home/.codex/sessions").rglob("*.jsonl")).read_bytes(), data)

    def test_missing_or_unknown_history_mode_refuses_the_export(self):
        for mode in (None, "obsolete"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                source = vault(root / "source")
                selected, path, rows = codex(source)
                rows[0]["payload"].pop("history_mode")
                if mode is not None:
                    rows[0]["payload"]["history_mode"] = mode
                path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                archive = root / "native.jsonl"
                with self.assertRaisesRegex(ValueError, "unsupported_codex_format"):
                    export_histories(source, [selected], archive)
                self.assertFalse(archive.exists())

    def test_missing_history_prefix_refuses_the_whole_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            selected, path, rows = codex(source)
            rows[0]["payload"]["history_base"] = {"thread_id": str(uuid.uuid4()), "end_ordinal_exclusive": 1, "end_byte_offset": 42}
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            archive = root / "native.jsonl"
            with self.assertRaisesRegex(ValueError, "codex_history_dependency_missing"):
                export_histories(source, [selected], archive)
            self.assertFalse(archive.exists())

    @unittest.skipUnless(shutil.which("zstd"), "requires immutable zstd decompressor")
    def test_cold_compressed_rollout_restores_exact_plain_native_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            selected, path, _ = codex(source)
            original = path.read_bytes()
            subprocess.run([shutil.which("zstd"), "--quiet", str(path)], check=True)
            path.unlink()
            archive = root / "native.jsonl"
            export_histories(source, [selected], archive)
            destination = vault(root / "target")
            import_histories(archive, destination)
            self.assertEqual(next((destination / "home/.codex/sessions").rglob("*.jsonl")).read_bytes(), original)
