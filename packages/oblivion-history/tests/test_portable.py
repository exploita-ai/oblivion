import fcntl
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from oblivion_history.catalog import Catalog
from oblivion_history.model import Item, Snapshot, encode
from oblivion_history.portable import export_catalog, import_catalog
from oblivion_history.sync import allowed_cwd


class PortableTests(unittest.TestCase):
    def fixture(self, root):
        state = root / "state"
        chat, call, result = [str(uuid.uuid4()) for _ in range(3)]
        catalog = Catalog(state)
        with catalog.db:
            catalog.db.execute("INSERT INTO chat VALUES(?,?,?,?,?)", (chat, "/vault/workspace/project", "Selected chat", 1, 3))
            catalog.db.execute("INSERT INTO item VALUES(?,?,?,?,?,?,?)", (call, chat, 1, "tool_call", "assistant", encode({"id": "call-1", "name": "exec_command", "input": {"cmd": "printf hi"}}), 2))
            catalog.db.execute("INSERT INTO item VALUES(?,?,?,?,?,?,?)", (result, chat, 2, "tool_result", "user", encode({"id": "call-1", "content": "hi", "is_error": False}), 3))
            catalog.db.execute("INSERT INTO native VALUES(?,?,?,?,?,?)", ("codex", "SOURCE-NATIVE-IDENTITY", chat, "SOURCE-FINGERPRINT", "/vault/home/.codex/sessions/source", "Selected chat"))
            catalog.db.execute("INSERT INTO native_fact VALUES(?,?,?,?,?,?,?,?)", (chat, "codex", "SOURCE-NATIVE-IDENTITY", "fact", "provider_reasoning", encode({"token": "SOURCE-FACT-SECRET"}), 2, 1))
            catalog.db.execute("INSERT INTO source_chunk VALUES(?,?)", ("source", b"SOURCE-CREDENTIAL-CANARY"))
        catalog.close()
        (state / "history.sqlite").chmod(0o600)
        return state, chat

    def test_selected_catalog_roundtrip_omits_native_sources_and_rebinds_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state, chat = self.fixture(root)
            output = root / "chats.jsonl"
            report = export_catalog(state, "/vault/workspace", [chat], output)
            self.assertEqual(report["chats"], 1)
            self.assertEqual(report["items"], 2)
            self.assertEqual(report["omitted"], {"provider_reasoning": 1})
            data = output.read_text()
            for omitted in ("SOURCE-NATIVE-IDENTITY", "SOURCE-FINGERPRINT", "SOURCE-FACT-SECRET", "SOURCE-CREDENTIAL-CANARY", "/vault/home"):
                self.assertNotIn(omitted, data)
            destination = root / "new-catalog"
            workspace = root / "new-workspace"
            workspace.mkdir()
            self.assertEqual(import_catalog(output, destination, workspace), {"chats": 1, "items": 2})
            database = sqlite3.connect(destination / "history.sqlite")
            self.assertEqual(database.execute("SELECT id,cwd FROM chat").fetchone(), (chat, str(workspace / "project")))
            self.assertTrue((workspace / "project").is_dir())
            self.assertEqual(database.execute("SELECT count(*) FROM native").fetchone()[0], 0)
            self.assertEqual(database.execute("SELECT count(*) FROM source_chunk").fetchone()[0], 0)
            bodies = [json.loads(row[0]) for row in database.execute("SELECT body FROM item ORDER BY ordinal")]
            self.assertEqual(bodies[0]["id"], bodies[1]["id"])
            database.close()
            with self.assertRaisesRegex(ValueError, "portable_catalog_destination_exists"):
                import_catalog(output, destination, workspace)
            catalog = Catalog(destination)
            native = catalog.native_id(chat, "codex")
            cwd = str(workspace / "project")
            self.assertTrue(allowed_cwd(cwd, workspace))
            observed, _ = catalog.ingest(Snapshot("codex", native, cwd, "Selected chat", 1, 4,
                [Item("follow-up", "text", "assistant", {"text": "Continued"}, 4)], fingerprint="follow-up"))
            self.assertEqual(observed, chat)
            self.assertEqual(catalog.db.execute("SELECT count(*) FROM chat").fetchone()[0], 1)
            catalog.close()

    def test_missing_selection_and_busy_profile_leave_existing_destination_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state, chat = self.fixture(root)
            existing = root / "existing"
            existing.write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                export_catalog(state, "/vault/workspace", [chat], existing)
            self.assertEqual(existing.read_bytes(), b"keep")
            missing = root / "missing"
            with self.assertRaisesRegex(ValueError, "portable_chat_missing"):
                export_catalog(state, "/vault/workspace", [str(uuid.uuid4())], missing)
            self.assertFalse(missing.exists())
            lease = state / "codex.active"
            with open(lease, "a+b") as held:
                lease.chmod(0o600)
                fcntl.flock(held, fcntl.LOCK_SH)
                with self.assertRaisesRegex(ValueError, "history_client_active"):
                    export_catalog(state, "/vault/workspace", [chat], root / "busy")

    def test_malformed_portable_history_cannot_escape_or_partially_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state, chat = self.fixture(root)
            output = root / "chats.jsonl"
            export_catalog(state, "/vault/workspace", [chat], output)
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            rows[1]["cwd"] = {"scope": "workspace", "path": "../../home/.ssh"}
            output.write_text("".join(encode(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "invalid_portable_workspace"):
                import_catalog(output, root / "invalid", "/new/workspace")
            database = sqlite3.connect(root / "invalid/history.sqlite")
            self.assertEqual(database.execute("SELECT count(*) FROM chat").fetchone()[0], 0)
            database.close()
            rows[1]["cwd"] = {"scope": "workspace", "path": "project"}
            rows[-1]["body"]["id"] = "wrong-tool-call"
            output.write_text("".join(encode(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "invalid_portable_tool_pair"):
                import_catalog(output, root / "invalid-pair", "/new/workspace")

    def test_imports_scope_and_nested_cwd_are_data_only_and_stay_in_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state, chat = self.fixture(root)
            database = sqlite3.connect(state / "history.sqlite")
            database.execute("UPDATE chat SET cwd='/vault/imports/research' WHERE id=?", (chat,))
            database.commit(); database.close()
            source = root / "selected.jsonl"
            export_catalog(state, "/vault/workspace", [chat], source, imports="/vault/imports")
            workspace, imports = root / "workspace", root / "imports"
            workspace.mkdir(); imports.mkdir()
            import_catalog(source, root / "target", workspace, imports=imports)
            self.assertTrue((imports / "research").is_dir())
            for cwd in ("/vault/workspace/project", "/vault/imports/research", "/vault/workspace"):
                self.assertTrue(allowed_cwd(cwd, "/vault/workspace"))
            for cwd in ("/vault/home", "/vault/workspace/../home", "/vault/imports/../../home", "/vault/workspace-other", "/vault/workspace/\x00"):
                self.assertFalse(allowed_cwd(cwd, "/vault/workspace"))


if __name__ == "__main__":
    unittest.main()
