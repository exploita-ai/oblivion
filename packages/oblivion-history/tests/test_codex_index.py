"""SQLite/stdio fixtures, not qualification of the official Codex executable."""

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import uuid

from native_fixture import vault
from oblivion_history import codex_index

SCHEMA = """
CREATE TABLE _sqlx_migrations(version INTEGER,success INTEGER);
INSERT INTO _sqlx_migrations VALUES(58,1);
CREATE TABLE threads(
 id TEXT PRIMARY KEY,rollout_path TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,
 created_at_ms INTEGER,updated_at_ms INTEGER,recency_at INTEGER NOT NULL,recency_at_ms INTEGER NOT NULL,
 source TEXT NOT NULL,model_provider TEXT NOT NULL,cwd TEXT NOT NULL,title TEXT NOT NULL,cli_version TEXT,
 history_mode TEXT NOT NULL,name TEXT,preview TEXT NOT NULL,first_user_message TEXT NOT NULL,tokens_used INTEGER,
 archived INTEGER,archived_at INTEGER,originator TEXT,thread_source TEXT,agent_nickname TEXT,agent_role TEXT,
 agent_path TEXT,sandbox_policy TEXT NOT NULL,approval_mode TEXT NOT NULL,creator_account_id TEXT);
CREATE TABLE thread_attachments(id TEXT PRIMARY KEY,thread_id TEXT,attachment_type TEXT,identity_key TEXT,payload TEXT,created_at INTEGER);
CREATE TABLE auth(token TEXT);
"""


def row(identity=None):
    identity = identity or str(uuid.uuid4())
    physical = str(uuid.uuid4())
    return {
        "id": identity, "rollout_path": "sessions/2026/11/04/rollout-2026-11-04T12-00-00-" + physical + ".jsonl",
        "created_at": 100, "updated_at": 200, "created_at_ms": 100001, "updated_at_ms": 200001,
        "recency_at": 200, "recency_at_ms": 200001, "source": "cli", "model_provider": "openai",
        "cwd": "/vault/workspace/project", "title": "Native conversation", "cli_version": "0.159.2",
        "history_mode": "paginated", "name": "Renamed native thread", "preview": "Native preview",
        "first_user_message": "Native prompt", "tokens_used": 12, "archived": 0, "archived_at": None,
        "originator": "codex", "thread_source": None, "agent_nickname": None, "agent_role": None, "agent_path": None,
    }


def seed(root, value):
    path = root / "home/.codex/state_5.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.executescript(SCHEMA)
    native = {**value, "rollout_path": "/vault/home/.codex/" + value["rollout_path"],
              "sandbox_policy": "danger-full-access", "approval_mode": "never", "creator_account_id": "SOURCE-ACCOUNT-CANARY"}
    connection.execute("INSERT INTO threads(" + ",".join(native) + ") VALUES(" + ",".join("?" for _ in native) + ")", tuple(native.values()))
    attachment = {"id": "attachment-1", "thread_id": value["id"], "attachment_type": "user-note", "identity_key": "note-1", "payload": {"text": "Native context attachment"}, "created_at": 123}
    connection.execute("INSERT INTO thread_attachments VALUES(?,?,?,?,?,?)", tuple(json.dumps(attachment[key]) if key == "payload" else attachment[key] for key in attachment))
    connection.execute("INSERT INTO auth VALUES('SOURCE-PROVIDER-CREDENTIAL-CANARY')")
    connection.commit()
    connection.close()
    return attachment


class NativeCodexIndex(unittest.TestCase):
    def test_positive_rows_preserve_authoritative_generation_and_exclude_source_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = vault(tmp)
            thread = row()
            attachment = seed(root, thread)
            self.assertEqual(codex_index.read(root)[thread["id"]], thread)
            values = codex_index.collect(root, [thread["id"]])
            self.assertEqual(values, [{"type": "codex-index", "version": 1, "thread": thread, "attachments": [attachment]}])
            serialized = json.dumps(values)
            self.assertNotIn("CANARY", serialized)
            self.assertNotIn("sandbox_policy", serialized)
            self.assertNotIn("approval_mode", serialized)

    def test_restore_stages_index_for_offline_reshare_without_a_native_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = vault(tmp)
            thread = row()
            value = {"type": "codex-index", "version": 1, "thread": thread, "attachments": []}
            codex_index.restore(root, [value])
            self.assertFalse(codex_index.database(root).exists())
            self.assertEqual(codex_index.read(root), {thread["id"]: thread})
            self.assertEqual(codex_index.collect(root, [thread["id"]]), [value])
            with self.assertRaises(FileExistsError):
                codex_index.restore(root, [value])

    def test_explicit_prepare_uses_generated_schema_and_preserves_recipient_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = vault(tmp)
            source = vault(root / "source")
            thread = row()
            seed(source, thread)
            values = codex_index.collect(source, [thread["id"]])
            target = vault(root / "target")
            codex_index.restore(target, values)
            raw = target / "home/.codex" / thread["rollout_path"]
            raw.parent.mkdir(parents=True)
            raw.write_bytes(b"{}\n")
            binary = root / "native-fixture"
            body = (
                "import json,sqlite3,sys\n"
                "from pathlib import Path\n"
                "assert sys.argv[1:] == ['app-server']\n"
                "request=json.loads(sys.stdin.readline())\n"
                "assert request['method'] == 'initialize'\n"
                "db=sqlite3.connect(" + repr(str(codex_index.database(target))) + ")\n"
                "db.executescript(" + repr(SCHEMA) + ")\n"
                "db.execute(\"INSERT INTO auth VALUES('RECIPIENT-CREDENTIAL-CANARY')\")\n"
                "db.commit(); db.close()\n"
                "print(json.dumps({'id':1,'result':{}}),flush=True)\n"
                "sys.stdin.read()\n"
            )
            binary.write_text("#!" + sys.executable + "\n" + body)
            binary.chmod(0o700)
            codex_index.prepare(target, str(binary))
            with sqlite3.connect(codex_index.database(target)) as db:
                actual = db.execute("SELECT rollout_path,name,sandbox_policy,approval_mode,creator_account_id FROM threads WHERE id=?", (thread["id"],)).fetchone()
                self.assertEqual(actual, (str(raw), thread["name"], "read-only", "on-request", None))
                self.assertEqual(db.execute("SELECT token FROM auth").fetchall(), [("RECIPIENT-CREDENTIAL-CANARY",)])
                self.assertEqual(json.loads(db.execute("SELECT payload FROM thread_attachments").fetchone()[0]), {"text": "Native context attachment"})
            self.assertFalse((target / "state/oblivion/native-imports/codex/index.json").exists())

    def test_unknown_fields_or_schema_are_rejected_without_replacing_transfer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = vault(tmp)
            thread = row()
            value = {"type": "codex-index", "version": 1, "thread": thread, "attachments": []}
            value["thread"]["creator_account_id"] = "must-not-import"
            with self.assertRaisesRegex(ValueError, "invalid_codex_native_index"):
                codex_index.restore(root, [value])
            value["thread"].pop("creator_account_id")
            seed(root, thread)
            with sqlite3.connect(codex_index.database(root)) as db:
                db.execute("UPDATE _sqlx_migrations SET version=59")
            with self.assertRaisesRegex(ValueError, "unsupported_codex_index_schema"):
                codex_index.read(root)


if __name__ == "__main__":
    unittest.main()
