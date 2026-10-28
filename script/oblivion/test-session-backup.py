#!/usr/bin/env python3
"""Exercise private encrypted-session metadata without starting an agent."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
source = Path(os.environ["OBLIVION_TEST_BACKUP_HELPER"]) if "OBLIVION_TEST_BACKUP_HELPER" in os.environ else Path(__file__).resolve().parents[2] / "packages/oblivion-host/guest/session-backup.py"
spec = importlib.util.spec_from_file_location("session_backup", source)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)
METADATA = {"format": "oblivion-session", "version": 1, "original_id": "a" * 32, "title": "Documenti città"}


@contextlib.contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix="oblivion-backup-metadata-") as directory:
        vault = Path(directory)
        (vault / "state").mkdir(mode=0o700)
        (vault / "workspace").mkdir(mode=0o700)
        yield vault


class SessionBackupTest(unittest.TestCase):
    def test_checkpoint_inspect_and_owner_cleanup_keep_completed_metadata(self):
        with fixture() as vault:
            result = backup.execute({"action": "checkpoint", "metadata": METADATA}, vault, "manual")
            self.assertEqual(result, {"result": "metadata", "metadata": METADATA})
            path = vault / "state/oblivion/session.json"
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(backup.execute({"action": "inspect"}, vault, "manual"), result)
            first = path.parent / (".pending-oblivion.archive." + "b" * 32 + "-first")
            second = path.parent / (".pending-oblivion.archive." + "c" * 32 + "-second")
            first.write_text("unfinished")
            second.write_text("another operation")
            backup.cleanup(vault, "oblivion.archive." + "b" * 32)
            self.assertFalse(first.exists())
            self.assertTrue(second.exists())
            backup.cleanup(vault, None)
            self.assertFalse(second.exists())
            self.assertEqual(json.loads(path.read_text()), METADATA)
            changed = METADATA | {"original_id": "d" * 32, "title": "Renamed session"}
            self.assertEqual(backup.execute({"action": "checkpoint", "metadata": changed}, vault, "manual")["metadata"], changed)
            self.assertFalse(list(path.parent.glob(".pending-*")))

    def test_future_versions_and_invalid_metadata_are_rejected_without_replacement(self):
        for changed in (
            METADATA | {"api_key": "never allowed"}, METADATA | {"version": True},
            METADATA | {"original_id": "../escape"}, METADATA | {"title": "\x1b[2J"},
            METADATA | {"title": " x"}, METADATA | {"title": "a" * 81},
        ):
            with self.assertRaises(backup.Rejected):
                backup.metadata(changed)
        with fixture() as vault:
            backup.execute({"action": "checkpoint", "metadata": METADATA}, vault, "manual")
            path = vault / "state/oblivion/session.json"
            future = json.dumps(METADATA | {"version": 2}).encode()
            path.write_bytes(future)
            for request in ({"action": "inspect"}, {"action": "checkpoint", "metadata": METADATA}):
                self.assertEqual(backup.execute(request, vault, "manual"), {"result": "rejected", "error": "unsupported-version"})
                self.assertEqual(path.read_bytes(), future)

    def test_metadata_symlinks_and_hardlinks_cannot_reach_outside_the_state(self):
        with fixture() as vault, tempfile.TemporaryDirectory() as outside:
            destination = Path(outside) / "session.json"
            destination.write_text("OUTSIDE_MUST_NOT_CHANGE")
            (vault / "state/oblivion").symlink_to(outside, target_is_directory=True)
            self.assertEqual(backup.execute({"action": "checkpoint", "metadata": METADATA}, vault, "manual")["result"], "rejected")
            (vault / "state/oblivion").unlink()
            (vault / "state/oblivion").mkdir(mode=0o700)
            path = vault / "state/oblivion/session.json"
            path.symlink_to(destination)
            self.assertEqual(backup.execute({"action": "inspect"}, vault, "manual")["result"], "rejected")
            path.unlink()
            os.link(destination, path)
            self.assertEqual(backup.execute({"action": "inspect"}, vault, "manual")["result"], "rejected")
            self.assertEqual(destination.read_text(), "OUTSIDE_MUST_NOT_CHANGE")

    def test_sqlite_wal_is_readable_and_corrupt_or_truncated_databases_are_rejected(self):
        with fixture() as vault:
            (vault / "state/opencode").mkdir(mode=0o700)
            database = vault / "state/opencode/oblivion.db"
            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("CREATE TABLE transcript (text TEXT)")
                connection.execute("INSERT INTO transcript VALUES ('original chat')")
                connection.commit()
                before = database.read_bytes()
                wal = database.with_name(database.name + "-wal").read_bytes()
                self.assertEqual(backup.execute({"action": "checkpoint", "metadata": METADATA}, vault, "manual")["result"], "metadata")
                self.assertEqual(backup.execute({"action": "inspect"}, vault, "manual")["result"], "metadata")
                self.assertEqual(database.read_bytes(), before)
                self.assertEqual(database.with_name(database.name + "-wal").read_bytes(), wal)
                self.assertEqual(connection.execute("SELECT text FROM transcript").fetchall(), [("original chat",)])
            contents = database.read_bytes()
            for invalid in (b"", contents[:80], b"NOT A SQLITE DB" + contents[15:]):
                database.write_bytes(invalid)
                self.assertEqual(backup.execute({"action": "inspect"}, vault, "manual"), {"result": "rejected", "error": "invalid-database"})
            database.write_bytes(contents)
            self.assertEqual(backup.execute({"action": "inspect"}, vault, "manual")["result"], "metadata")


if __name__ == "__main__":
    unittest.main()
