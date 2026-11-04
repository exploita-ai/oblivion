import json
from pathlib import Path
import tempfile
import sqlite3
import unittest
import uuid

from native_fixture import vault, codex, claude, opencode
from oblivion_history.portable import export_histories, import_histories, native_histories, records, encode, reference


class NativePortableTests(unittest.TestCase):
    def test_own_native_transcripts_roundtrip_without_credentials_or_cross_agent_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            identity = str(uuid.uuid4())
            codex_ref, _, codex_rows = codex(source, identity=identity)
            claude_ref, _, claude_rows = claude(source, identity=identity)
            opencode_ref, _ = opencode(source)
            (source / "home/.codex/auth.json").write_text("PROFILE-CREDENTIAL-CANARY")
            (source / "home/.claude/settings.json").write_text("PROFILE-HOOK-CANARY")
            archive = root / "native.jsonl"
            self.assertEqual(export_histories(source, None, archive)["chats"], 3)
            serialized = archive.read_text()
            self.assertNotIn("PROFILE-CREDENTIAL-CANARY", serialized)
            self.assertNotIn("PROFILE-HOOK-CANARY", serialized)
            self.assertNotEqual(codex_ref, claude_ref)
            destination = vault(root / "destination")
            self.assertEqual(import_histories(archive, destination), {"chats": 3, "agents": ["claude", "codex", "opencode2"]})
            transcripts = list((destination / "home/.codex/sessions").rglob("*.jsonl"))
            self.assertEqual(len(transcripts), 1)
            restored = records(transcripts[0])
            self.assertEqual(restored, codex_rows)
            transcripts = list((destination / "home/.claude/projects").rglob("*.jsonl"))
            self.assertEqual(len(transcripts), 1)
            restored = records(transcripts[0])
            self.assertEqual(restored, claude_rows)
            self.assertFalse((destination / "home/.oblivion-history").exists())
            self.assertFalse((destination / "home/.codex/auth.json").exists())
            self.assertFalse((destination / "state/opencode/opencode.db").exists())
            pending = list((destination / "state/oblivion/native-imports/opencode2").glob("*.json"))
            self.assertEqual(len(pending), 1)
            self.assertEqual(json.loads(pending[0].read_text())["messages"][0]["text"], "Native OpenCode question")
            self.assertEqual({entry["id"] for entry in native_histories(destination)}, {codex_ref, claude_ref, opencode_ref})
            with self.assertRaisesRegex(ValueError, "native_history_destination_exists"):
                import_histories(archive, destination)

    def test_native_titles_and_supported_opencode_records_survive_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            codex_ref, _, rows = codex(source)
            identity = rows[0]["payload"]["id"]
            (source / "home/.codex/session_index.jsonl").write_text(encode({"id": identity, "thread_name": "My renamed native chat", "updated_at": "2026-11-04T12:01:03Z"}) + "\n")
            _, database = opencode(source)
            connection = sqlite3.connect(database)
            for seq, kind in enumerate(("system", "skill", "shell", "agent-switched", "model-switched", "location-switched"), 2):
                connection.execute("INSERT INTO session_message VALUES(?,?,?,?,?)", ("msg_" + str(seq), "ses_nativeExample123", kind, seq, encode({"time": {"created": 1}, "status": "completed", "text": "native data"})))
            connection.execute("INSERT INTO session_message VALUES(?,?,?,?,?)", ("msg_incomplete", "ses_nativeExample123", "assistant", 99, encode({"time": {"created": 1}, "content": []})))
            connection.commit(); connection.close()
            archive = root / "native.jsonl"
            report = export_histories(source, None, archive)
            self.assertEqual(report["omitted"]["opencode_unsettled_messages"], 1)
            destination = vault(root / "target")
            import_histories(archive, destination)
            index = records(destination / "home/.codex/session_index.jsonl")
            self.assertEqual(index[0]["thread_name"], "My renamed native chat")
            pending = next((destination / "state/oblivion/native-imports/opencode2").glob("*.json"))
            value = json.loads(pending.read_text())
            self.assertEqual(len(value["messages"]), 7)
            self.assertNotIn("msg_incomplete", pending.read_text())

    def test_claude_native_sidecars_and_undo_backups_restore_without_profile_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            selected, transcript, rows = claude(source)
            sidecar = transcript.parent / transcript.stem / "subagents/agent-example.jsonl"
            sidecar.parent.mkdir(parents=True)
            sidecar.write_text(encode(rows[0]) + "\n")
            backup = source / "home/.claude/file-history" / transcript.stem / "original@v1"
            backup.parent.mkdir(parents=True)
            backup.write_text("original document before native edit")
            rows.append({"type": "file-history-snapshot", "snapshot": {"trackedFileBackups": {"document.txt": {"backupFileName": backup.name}}}})
            transcript.write_text("".join(encode(row) + "\n" for row in rows))
            archive = root / "native.jsonl"
            export_histories(source, [selected], archive)
            destination = vault(root / "target")
            import_histories(archive, destination)
            for original in (transcript, sidecar, backup):
                copied = destination / "home/.claude" / original.relative_to(source / "home/.claude")
                self.assertEqual(copied.read_bytes(), original.read_bytes())
            self.assertFalse((destination / "home/.claude/settings.json").exists())

    def test_selecting_codex_does_not_create_claude_or_opencode_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            selected, _, _ = codex(source)
            claude(source)
            archive = root / "selected.jsonl"
            export_histories(source, [selected], archive)
            destination = vault(root / "target")
            import_histories(archive, destination)
            self.assertTrue((destination / "home/.codex").is_dir())
            self.assertFalse((destination / "home/.claude").exists())
            self.assertFalse((destination / "state/oblivion/native-imports").exists())

    def test_unknown_versions_partial_transcripts_and_symlinks_fail_without_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            _, path, rows = codex(source)
            rows[0]["payload"]["cli_version"] = "unknown"
            path.write_text("".join(encode(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "unsupported_codex_format"):
                export_histories(source, None, root / "invalid.jsonl")
            self.assertFalse((root / "invalid.jsonl").exists())
            path.write_text('{"type":"session_meta"}')
            with self.assertRaisesRegex(ValueError, "incomplete"):
                native_histories(source)
            path.unlink(); path.symlink_to(root / "missing")
            with self.assertRaises(OSError):
                native_histories(source)

    def test_archive_tampering_cannot_publish_profiles_or_escape_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = vault(root / "source")
            codex(source)
            archive = root / "native.jsonl"
            export_histories(source, None, archive)
            rows = records(archive)
            rows[1]["cwd"] = {"root": "workspace", "path": "../../escape"}
            archive.write_text("".join(encode(row) + "\n" for row in rows))
            destination = vault(root / "target")
            with self.assertRaisesRegex(ValueError, "invalid_native_workspace"):
                import_histories(archive, destination)
            self.assertEqual(list((destination / "home").iterdir()), [])
            rows[1]["cwd"] = {"root": "workspace", "path": "project"}
            rows[2]["data"]["sha256"] = "0" * 64
            archive.write_text("".join(encode(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "invalid_native_artifact_hash"):
                import_histories(archive, destination)
            self.assertEqual(list((destination / "home").iterdir()), [])
