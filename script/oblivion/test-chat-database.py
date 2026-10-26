"""Run with the compiled Linux client and network disabled; no model calls."""

import hashlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

source = Path(__file__).resolve().parents[2] / "packages/oblivion-host/guest/chat-database.py"
spec = importlib.util.spec_from_file_location("chat_database", source)
chat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chat)
binary = os.environ.get("OBLIVION_TEST_CLIENT", "/usr/local/bin/opencode")


class ChatDatabaseTest(unittest.TestCase):
    def test_channel_migration_and_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data"
            data.mkdir()
            workspace = root / "workspace"
            workspace.mkdir()
            before = {}
            originals = {}
            for channel in ("beta", "dev"):
                path = data / ("opencode-oblivion-" + channel + ".db")
                runtime = root / channel
                runtime.mkdir()
                with chat.server(binary, path, runtime) as request:
                    session = request("/api/session", {
                        "title": channel + " history", "location": {"directory": str(workspace)},
                    })
                    session = request("/api/experimental/session/import", {
                        "info": {**session, "id": "ses_storage_" + channel},
                        "messages": [{
                            "id": "msg_storage_" + channel, "type": "user", "text": "preserved-history",
                            "time": {"created": 1700000000000}, "files": [], "agents": [], "skills": [],
                        }],
                        "location": {"directory": str(workspace)},
                    })
                    before[session["id"]] = request("/api/experimental/session/" + session["id"] + "/export")
                    if channel == "dev":
                        child = request("/api/session", {"title": "child history", "parentID": session["id"]})
                        before[child["id"]] = request("/api/experimental/session/" + child["id"] + "/export")
                originals[path] = hashlib.sha256(path.read_bytes()).hexdigest()
            target = chat.prepare(data, binary)
            self.assertEqual(target.name, "oblivion.db")
            self.assertEqual(list(data.glob(".chat-migration-*")), [])
            for path, digest in originals.items():
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            runtime = root / "reopened"
            runtime.mkdir()
            with chat.server(binary, target, runtime) as request:
                for key, transcript in before.items():
                    restored = request("/api/experimental/session/" + key + "/export")
                    self.assertEqual(restored["messages"], transcript["messages"])
                    self.assertEqual(restored["info"]["title"], transcript["info"]["title"])
                    self.assertEqual(restored["info"].get("parentID"), transcript["info"].get("parentID"))
            self.assertEqual(chat.prepare(data, "/not-needed"), target)

    def test_single_source_includes_wal(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            source = data / "opencode-oblivion-dev.db"
            with sqlite3.connect(source) as db:
                db.execute("pragma journal_mode=wal")
                db.execute("create table fixture (id text)")
                db.execute("insert into fixture values ('committed-in-wal')")
                db.commit()
                self.assertTrue(Path(str(source) + "-wal").exists())
                target = chat.prepare(data, "/not-needed")
            with chat.database(target) as db:
                self.assertEqual(db.execute("select id from fixture").fetchall(), [("committed-in-wal",)])

    def test_invalid_source_does_not_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            source = data / "opencode-oblivion-beta.db"
            source.write_bytes(b"not a database")
            with self.assertRaises(sqlite3.DatabaseError):
                chat.prepare(data, "/not-needed")
            self.assertFalse((data / "oblivion.db").exists())
            self.assertEqual(source.read_bytes(), b"not a database")
            self.assertEqual(list(data.glob(".chat-migration-*")), [])

    def test_conflicting_histories_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            beta = data / "opencode-oblivion-beta.db"
            dev = data / "opencode-oblivion-dev.db"
            runtime = data / "runtime"
            runtime.mkdir()
            with chat.server(binary, beta, runtime) as request:
                session = request("/api/session", {"title": "original"})
            chat.backup(beta, dev)
            with sqlite3.connect(dev) as db:
                db.execute("update session_v2 set title = ? where id = ?", ("different", session["id"]))
            originals = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (beta, dev)}
            with self.assertRaisesRegex(RuntimeError, "Conflicting chat histories"):
                chat.prepare(data, binary)
            self.assertFalse((data / "oblivion.db").exists())
            for path, digest in originals.items():
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_pending_input_is_preserved_or_blocks_transcript_import(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            beta = data / "opencode-oblivion-beta.db"
            dev = data / "opencode-oblivion-dev.db"
            runtime = data / "runtime"
            runtime.mkdir()
            with chat.server(binary, beta, runtime) as request:
                request("/api/session", {"title": "base"})
            runtime = data / "runtime-dev"
            runtime.mkdir()
            with chat.server(binary, dev, runtime) as request:
                session = request("/api/session", {"title": "queued"})
                request("/api/session/" + session["id"] + "/prompt", {"text": "pending", "resume": False})
            with self.assertRaisesRegex(RuntimeError, "Finish pending chats"):
                chat.prepare(data, binary)
            self.assertFalse((data / "oblivion.db").exists())
            # With just this database, backup preserves queued input verbatim.
            single = data / "single"
            single.mkdir()
            chat.backup(dev, single / dev.name)
            target = chat.prepare(single, binary)
            with chat.database(target) as db:
                self.assertEqual(db.execute("select count(*) from session_inbox").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
