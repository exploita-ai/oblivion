"""Exercise the production exporter with a compiled OpenCode and no provider."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import sqlite3
import tempfile
import unittest

source = Path(os.environ["OBLIVION_TEST_EXPORT_HELPER"]) if "OBLIVION_TEST_EXPORT_HELPER" in os.environ else Path(__file__).resolve().parents[2] / "packages/oblivion-host/guest/chat-export.py"
spec = importlib.util.spec_from_file_location("chat_export", source)
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)
binary = os.environ.get("OBLIVION_TEST_CLIENT", "/usr/bin/oblivion")


class ChatExportTest(unittest.TestCase):
    def test_restore_inspection_uses_a_private_engine_snapshot_and_preserves_pending_chats(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = Path(directory)
            data = vault / "state/opencode"
            data.mkdir(parents=True); (vault / "runtime").mkdir()
            with exporter.chat.server(binary, data / "oblivion.db", vault / "runtime") as call:
                session = call("/api/session", {"title": "Restored pending chat"})
                call("/api/session/" + session["id"] + "/prompt", {"text": "preserve restored queue", "resume": False})
                metadata = {"format": "oblivion-session", "version": 1, "original_id": "a" * 32, "title": "Restored workspace"}
                self.assertEqual(exporter.execute({"action": "checkpoint", "metadata": metadata}, vault, binary)["result"], "metadata")
                original = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (data / "oblivion.db", data / "oblivion.db-wal")}
                self.assertEqual(exporter.execute({"action": "inspect"}, vault, binary), {"result": "metadata", "metadata": metadata})
                # A SQLite-only check is insufficient when the engine cannot
                # read the copy. This failure must never publish a restore.
                self.assertEqual(exporter.execute({"action": "inspect"}, vault, "/nonexistent-oblivion-client"), {"result": "rejected", "error": "invalid-database"})
                self.assertEqual({path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (data / "oblivion.db", data / "oblivion.db-wal")}, original)
                self.assertEqual(call("/api/session/" + session["id"] + "/inbox")[0]["payload"]["text"], "preserve restored queue")
                self.assertEqual(list(data.glob(".chat-export-*")), [])

    def test_chat_inventory_is_paginated_and_excludes_subagent_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = Path(directory)
            data = vault / "state/opencode"
            data.mkdir(parents=True); (vault / "runtime").mkdir()
            with exporter.chat.server(binary, data / "oblivion.db", vault / "runtime") as call:
                ids = {call("/api/session", {"title": "Inventory " + str(index)})["id"] for index in range(51)}
                child = call("/api/session", {"title": "Subagent fixture", "parentID": next(iter(ids))})
                first = exporter.execute({"action": "list"}, vault, binary)
                self.assertEqual(len(first["entries"]), 50)
                self.assertIsInstance(first["next"], str)
                second = exporter.execute({"action": "list", "cursor": first["next"]}, vault, binary)
                seen = [entry["id"] for entry in first["entries"] + second["entries"]]
                self.assertEqual(len(seen), 51)
                self.assertEqual(set(seen), ids)
                self.assertNotIn(child["id"], seen)
                self.assertIsNone(second["next"])
                self.assertEqual(list(data.glob(".chat-export-*")), [])

    def test_legacy_profile_exports_without_migrating_its_original(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = Path(directory)
            data = vault / "state/opencode"
            data.mkdir(parents=True); (vault / "workspace").mkdir(); (vault / "runtime").mkdir()
            legacy = data / "opencode-oblivion-beta.db"
            with exporter.chat.server(binary, legacy, vault / "runtime") as call:
                session = call("/api/session", {"title": "Legacy offline chat"})
                call("/api/session/" + session["id"] + "/prompt", {"text": "preserve legacy queue", "resume": False})
                original = call("/api/experimental/session/" + session["id"] + "/export")
            digest = hashlib.sha256(legacy.read_bytes()).hexdigest()
            result = exporter.execute({"action": "export", "id": session["id"], "format": "json"}, vault, binary)
            self.assertEqual(json.loads((vault / result["path"]).read_text()), original)
            self.assertEqual(hashlib.sha256(legacy.read_bytes()).hexdigest(), digest)
            self.assertFalse((data / "oblivion.db").exists())
            self.assertEqual(list(data.glob(".chat-export-*")), [])

    def test_live_database_json_markdown_and_pending_input(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = Path(directory)
            data = vault / "state/opencode"
            data.mkdir(parents=True)
            (vault / "workspace").mkdir()
            (vault / "runtime").mkdir()
            with exporter.chat.server(binary, data / "oblivion.db", vault / "runtime") as call:
                session = call("/api/session", {"title": "Export fixture", "location": {"directory": str(vault / "workspace")}})
                message = {"id": "msg_export_fixture", "type": "user", "text": "Saved Italian: è à €\n```test```",
                           "time": {"created": 1700000000000}, "files": [], "agents": [], "skills": []}
                assistant = {"id": "msg_export_assistant", "type": "assistant", "agent": "default",
                             "model": {"id": "fixture", "providerID": "fixture"},
                             "time": {"created": 1700000000001, "completed": 1700000000002},
                             "content": [{"type": "text", "text": "Settled assistant answer"},
                                         {"type": "reasoning", "text": "Fixture reasoning"},
                                         {"type": "tool", "id": "tool_fixture", "name": "shell",
                                          "time": {"created": 1700000000001, "completed": 1700000000002},
                                          "state": {"status": "completed", "input": {"command": "printf test"},
                                                    "content": [{"type": "text", "text": "Tool output with ````` fence"}]}}]}
                transcript = {"info": {**session, "id": "ses_export_fixture"}, "messages": [message, assistant]}
                call("/api/experimental/session/import", {**transcript, "location": session["location"]})
                # Seed a partially streamed projection, as the execution layer
                # would leave it while awaiting a model. The real export API
                # must omit it without changing the source or pending inbox.
                with sqlite3.connect(data / "oblivion.db") as db:
                    partial = {key: value for key, value in assistant.items() if key not in ("id", "type")}
                    partial["time"] = {"created": 1700000000003}
                    partial["content"] = [{"type": "text", "text": "INCOMPLETE_RESPONSE"}]
                    db.execute("insert into session_message (id, session_id, type, seq, time_created, time_updated, data) values (?, ?, ?, ?, ?, ?, ?)",
                               ("msg_export_partial", "ses_export_fixture", "assistant", 100, 1700000000003, 1700000000003, json.dumps(partial)))
                call("/api/session/ses_export_fixture/prompt", {"text": "Queued, not executed", "resume": False})
                before = call("/api/experimental/session/ses_export_fixture/export")
                self.assertEqual(len(before["messages"]), 2)
                inventory = exporter.execute({"action": "list"}, vault, binary)
                self.assertIn({"id": "ses_export_fixture", "title": "Export fixture"}, inventory["entries"])
                for format in ("json", "markdown"):
                    result = exporter.execute({"action": "export", "id": "ses_export_fixture", "format": format}, vault, binary)
                    path = vault / result["path"]
                    self.assertEqual(path.stat().st_size, result["bytes"])
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    if format == "json":
                        self.assertEqual(json.loads(path.read_text()), before)
                    else:
                        self.assertIn("Saved Italian: è à €", path.read_text())
                        for text in ("Settled assistant answer", "Fixture reasoning", "Tool: shell", "Tool output with ````` fence"):
                            self.assertIn(text, path.read_text())
                        self.assertIn("not executed", call("/api/session/ses_export_fixture/inbox")[0]["payload"]["text"])
                        self.assertNotIn("Queued, not executed", path.read_text())
                        self.assertNotIn("INCOMPLETE_RESPONSE", path.read_text())
                self.assertEqual(call("/api/experimental/session/ses_export_fixture/export"), before)
                self.assertEqual(list(data.glob(".chat-export-*")), [])
                with sqlite3.connect(data / "oblivion.db") as db:
                    self.assertEqual(db.execute("select count(*) from session_message where id = 'msg_export_partial'").fetchone(), (1,))
                # A hostile workspace cannot redirect the export to another root.
                for path in (vault / "workspace/chat-exports").iterdir():
                    path.unlink()
                (vault / "workspace/chat-exports").rmdir()
                (vault / "outside").mkdir()
                (vault / "workspace/chat-exports").symlink_to(vault / "outside", target_is_directory=True)
                with self.assertRaises(OSError):
                    exporter.execute({"action": "export", "id": "ses_export_fixture", "format": "json"}, vault, binary)
                self.assertEqual(list((vault / "outside").iterdir()), [])
                self.assertEqual(list(data.glob(".chat-export-*")), [])

    def test_empty_and_invalid_requests_do_not_create_state(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = Path(directory)
            self.assertEqual(exporter.execute({"action": "list"}, vault, binary), {"result": "chats", "entries": [], "next": None})
            for value in ({"action": "export", "id": "ses_../../outside", "format": "json"},
                          {"action": "list", "path": "/outside"},
                          {"action": "export", "id": "ses_valid", "format": "html"}):
                with self.assertRaises(ValueError):
                    exporter.execute(value, vault, binary)
            self.assertEqual(list(vault.iterdir()), [])

    def test_diagnostics_allowlist_without_database_or_engine(self):
        report = {"version": 1, "controller_version": "0.1.0", "architecture": "aarch64", "cpu_cores": 4, "memory_mib": 4096,
                  "ephemeral": False, "general_open": True, "session": "documents", "transport": "offline",
                  "direct_access_blocked": True, "observation_age_ms": 0, "tor_bootstrap": None, "laboratory": False}
        with tempfile.TemporaryDirectory() as directory:
            vault = Path(directory)
            (vault / "workspace").mkdir()
            result = exporter.execute({"action": "diagnostics", "report": report}, vault, "/engine-not-needed")
            self.assertEqual(json.loads((vault / result["path"]).read_text()), report)
            self.assertFalse((vault / "state").exists())
            for key in ("api_key", "session_title", "onion_url", "filename", "error", "logs"):
                with self.assertRaises(ValueError):
                    exporter.execute({"action": "diagnostics", "report": {**report, key: "private data"}}, vault, binary)
            self.assertEqual(len(list((vault / "workspace/diagnostics").iterdir())), 1)

    def test_cleanup_is_owned_and_preserves_published_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = Path(directory)
            state = vault / "state/opencode"
            target = vault / "workspace/chat-exports"
            state.mkdir(parents=True); target.mkdir(parents=True)
            for owner in ("vport0p4", "vport0p5"):
                stage = state / (".chat-export-" + owner + "-fixture")
                stage.mkdir(); (stage / "snapshot.db").write_bytes(b"private snapshot")
                (target / (".pending-" + owner + "-fixture.json")).write_bytes(b"partial")
            (state / "oblivion.db").write_bytes(b"original")
            (target / "published.json").write_bytes(b"complete")
            outside = vault / "outside"
            outside.mkdir(); (outside / "preserved").write_bytes(b"original")
            (state / ".chat-export-vport0p4-link").symlink_to(outside, target_is_directory=True)
            exporter.cleanup(vault, "vport0p4")
            self.assertEqual([path.name for path in state.glob(".chat-export-*")], [".chat-export-vport0p5-fixture"])
            self.assertTrue((target / ".pending-vport0p5-fixture.json").exists())
            self.assertFalse((target / ".pending-vport0p4-fixture.json").exists())
            exporter.cleanup(vault)
            self.assertEqual(list(state.glob(".chat-export-*")), [])
            self.assertEqual((state / "oblivion.db").read_bytes(), b"original")
            self.assertEqual((target / "published.json").read_bytes(), b"complete")
            self.assertEqual((outside / "preserved").read_bytes(), b"original")
            with self.assertRaises(ValueError):
                exporter.cleanup(vault, "../escape")


if __name__ == "__main__":
    unittest.main()
