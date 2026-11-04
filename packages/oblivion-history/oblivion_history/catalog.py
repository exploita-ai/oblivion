"""A catalog lives inside one unlocked Safe and never discovers host profiles."""

from contextlib import contextmanager
import fcntl
import difflib
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid
import zlib

from .model import Item, encode, stable

SCHEMA = """
CREATE TABLE IF NOT EXISTS chat (
 id TEXT PRIMARY KEY, cwd TEXT NOT NULL, title TEXT NOT NULL,
 created INTEGER NOT NULL, updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS native (
 agent TEXT NOT NULL, native_id TEXT NOT NULL, chat_id TEXT NOT NULL REFERENCES chat(id),
 fingerprint TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(agent,native_id), UNIQUE(chat_id,agent)
);
CREATE TABLE IF NOT EXISTS item (
 id TEXT PRIMARY KEY, chat_id TEXT NOT NULL REFERENCES chat(id), ordinal INTEGER NOT NULL,
 kind TEXT NOT NULL, role TEXT NOT NULL, body TEXT NOT NULL, created INTEGER NOT NULL,
 UNIQUE(chat_id,ordinal)
);
CREATE TABLE IF NOT EXISTS item_map (
 agent TEXT NOT NULL, native_id TEXT NOT NULL, item_id TEXT NOT NULL REFERENCES item(id),
 digest TEXT NOT NULL DEFAULT '', PRIMARY KEY(agent,native_id)
);
CREATE TABLE IF NOT EXISTS projection (
 agent TEXT NOT NULL, native_id TEXT NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(agent,native_id)
);
CREATE TABLE IF NOT EXISTS projection_intent (
 agent TEXT NOT NULL, native_id TEXT NOT NULL, chat_id TEXT NOT NULL REFERENCES chat(id),
 PRIMARY KEY(agent,native_id)
);
CREATE TABLE IF NOT EXISTS source_revision (
 agent TEXT NOT NULL, native_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
 data BLOB NOT NULL, PRIMARY KEY(agent,native_id,fingerprint)
);
CREATE TABLE IF NOT EXISTS source_latest (
 agent TEXT NOT NULL, native_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
 chunks BLOB NOT NULL, PRIMARY KEY(agent,native_id)
);
CREATE TABLE IF NOT EXISTS source_chunk (
 digest TEXT PRIMARY KEY, data BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS native_fact (
 chat_id TEXT NOT NULL REFERENCES chat(id), source_agent TEXT NOT NULL, source_native_id TEXT NOT NULL,
 native_id TEXT NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL, created INTEGER NOT NULL,
 present INTEGER NOT NULL, PRIMARY KEY(source_agent,source_native_id,native_id)
);
CREATE TABLE IF NOT EXISTS deleted_chat (
 chat_id TEXT PRIMARY KEY REFERENCES chat(id), confirmed INTEGER NOT NULL,
 origin TEXT NOT NULL CHECK(origin='explicit_confirmation')
);
CREATE TABLE IF NOT EXISTS deletion_target (
 chat_id TEXT NOT NULL REFERENCES deleted_chat(chat_id), agent TEXT NOT NULL,
 native_id TEXT NOT NULL, path TEXT NOT NULL, completed INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(chat_id,agent)
);
PRAGMA user_version=1;
"""


class Catalog:
    def __init__(self, directory, *, timeout=10):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.directory / "history.sqlite", timeout=timeout)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA secure_delete=ON")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            raise ValueError("unsupported_catalog_format")
        self.db.executescript(SCHEMA)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")

    def close(self):
        self.db.close()

    @contextmanager
    def exclusive(self, *, blocking=True):
        with open(self.directory / "sync.lock", "a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            yield

    def author_identity(self, agent, native_id, cwd, owned):
        """Resolve admission through the canonical mapping, never a caller ID.

        The caller holds the nonblocking catalog lock. An already running
        profile cannot receive a foreign projection; deny its stale context
        rather than silently accepting an older copy of the conversation.
        """
        row = self.db.execute(
            "SELECT chat_id FROM native WHERE agent=? AND native_id=?",
            (agent, native_id),
        ).fetchone()
        if row and self.db.execute(
            "SELECT 1 FROM deleted_chat WHERE chat_id=?", (row[0],)
        ).fetchone():
            raise ValueError("author_chat_deleted")
        if agent in self.pending():
            raise ValueError("author_history_recovery_required")
        if row:
            chat_id = row[0]
            if chat_id not in owned and not self.projection_current(agent, native_id, chat_id):
                raise ValueError("author_history_stale_reopen")
            return chat_id
        chat_id = str(uuid.uuid4())
        now = time.time_ns() // 1_000_000
        with self.db:
            self.db.execute("INSERT INTO chat VALUES(?,?,?,?,?)", (chat_id, cwd, "Untitled", now, now))
            self.db.execute(
                "INSERT INTO native(agent,native_id,chat_id) VALUES(?,?,?)",
                (agent, native_id, chat_id),
            )
        self.mark_projection(agent, native_id, chat_id)
        return chat_id

    def ingest(self, snapshot):
        mapping = self.db.execute(
            "SELECT * FROM native WHERE agent=? AND native_id=?",
            (snapshot.agent, snapshot.native_id),
        ).fetchone()
        if (
            mapping
            and self.db.execute(
                "SELECT 1 FROM deleted_chat WHERE chat_id=?", (mapping["chat_id"],)
            ).fetchone()
        ):
            # A stale native backup must never resurrect a confirmed deletion.
            # File disappearance alone never reaches this path.
            with self.db:
                self.db.execute(
                    "UPDATE deletion_target SET completed=0,path=? WHERE chat_id=? AND agent=?",
                    (snapshot.path, mapping["chat_id"], snapshot.agent),
                )
            return None, False
        if mapping and mapping["fingerprint"] == snapshot.fingerprint:
            return mapping["chat_id"], False
        chat_id = mapping["chat_id"] if mapping else str(uuid.uuid4())
        title = snapshot.title
        if mapping and mapping["title"] == title:
            title = self.db.execute(
                "SELECT title FROM chat WHERE id=?", (chat_id,)
            ).fetchone()[0]
        with self.db:
            self.db.execute(
                "INSERT INTO chat VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,updated=max(chat.updated,excluded.updated)",
                (chat_id, snapshot.cwd, title, snapshot.created, snapshot.updated),
            )
            self.db.execute(
                "INSERT INTO native VALUES (?,?,?,?,?,?) ON CONFLICT(agent,native_id) DO UPDATE SET fingerprint=excluded.fingerprint,path=excluded.path,title=excluded.title",
                (
                    snapshot.agent,
                    snapshot.native_id,
                    chat_id,
                    snapshot.fingerprint,
                    snapshot.path,
                    snapshot.title,
                ),
            )
            ordinal = self.db.execute(
                "SELECT coalesce(max(ordinal),0) FROM item WHERE chat_id=?", (chat_id,)
            ).fetchone()[0]
            for item in snapshot.items:
                native_key = snapshot.native_id + ":" + item.native_id
                digest = item_digest(item)
                recorded = self.db.execute(
                    "SELECT item_id,digest FROM item_map WHERE agent=? AND native_id=?",
                    (snapshot.agent, native_key),
                ).fetchone()
                if recorded:
                    if recorded["digest"] != digest:
                        self.db.execute(
                            "UPDATE item SET kind=?,role=?,body=?,created=? WHERE id=?",
                            (
                                item.kind,
                                item.role,
                                encode(item.body),
                                item.created,
                                recorded["item_id"],
                            ),
                        )
                        self.db.execute(
                            "UPDATE item_map SET digest=? WHERE agent=? AND native_id=?",
                            (digest, snapshot.agent, native_key),
                        )
                    continue
                ordinal += 1
                identifier = str(uuid.uuid4())
                self.db.execute(
                    "INSERT INTO item VALUES (?,?,?,?,?,?,?)",
                    (
                        identifier,
                        chat_id,
                        ordinal,
                        item.kind,
                        item.role,
                        encode(item.body),
                        item.created,
                    ),
                )
                self.db.execute(
                    "INSERT INTO item_map VALUES (?,?,?,?)",
                    (snapshot.agent, native_key, identifier, digest),
                )
            self.store_source(snapshot, chat_id)
        return chat_id, True

    def chats(self):
        result = []
        for row in self.db.execute(
            "SELECT * FROM chat WHERE id NOT IN (SELECT chat_id FROM deleted_chat) AND EXISTS (SELECT 1 FROM item WHERE chat_id=chat.id) ORDER BY created,id"
        ):
            items = [
                Item(
                    "",
                    x["kind"],
                    x["role"],
                    json.loads(x["body"]),
                    x["created"],
                    x["id"],
                )
                for x in self.db.execute(
                    "SELECT * FROM item WHERE chat_id=? ORDER BY ordinal", (row["id"],)
                )
            ]
            result.append((dict(row), items))
        return result

    def version(self, chat_id):
        row = self.db.execute("SELECT * FROM chat WHERE id=?", (chat_id,)).fetchone()
        items = [
            dict(x)
            for x in self.db.execute(
                "SELECT * FROM item WHERE chat_id=? ORDER BY ordinal", (chat_id,)
            )
        ]
        return fingerprint(encode([dict(row), items]).encode())

    def mark_projection(self, agent, native_id, chat_id):
        with self.db:
            self.db.execute(
                "INSERT INTO projection VALUES(?,?,?) ON CONFLICT(agent,native_id) DO UPDATE SET digest=excluded.digest",
                (agent, native_id, self.version(chat_id)),
            )

    def projection_current(self, agent, native_id, chat_id):
        row = self.db.execute(
            "SELECT digest FROM projection WHERE agent=? AND native_id=?",
            (agent, native_id),
        ).fetchone()
        return row is not None and row[0] == self.version(chat_id)

    def source_current(self, snapshot, chat_id):
        chat = self.db.execute(
            "SELECT title FROM chat WHERE id=?", (chat_id,)
        ).fetchone()
        expected = self.db.execute(
            "SELECT * FROM item WHERE chat_id=? ORDER BY ordinal", (chat_id,)
        ).fetchall()
        if snapshot.title != chat["title"] or len(snapshot.items) != len(expected):
            return False
        for native, row in zip(snapshot.items, expected):
            mapped = self.db.execute(
                "SELECT item_id FROM item_map WHERE agent=? AND native_id=?",
                (snapshot.agent, snapshot.native_id + ":" + native.native_id),
            ).fetchone()
            item = Item(
                "",
                row["kind"],
                row["role"],
                json.loads(row["body"]),
                row["created"],
                row["id"],
            )
            if (
                mapped is None
                or mapped[0] != item.id
                or item_digest(native) != item_digest(item)
            ):
                return False
        return True

    def prepare_projection(self, agent, native_id, chat_id, mapping, source=None):
        # Commit identities and intent before touching native storage. A process
        # death leaves a replayable projection, never unmapped native messages.
        with self.db:
            if source is not None:
                self.store_source(source, chat_id)
            self.db.execute(
                "INSERT INTO projection_intent VALUES(?,?,?) ON CONFLICT(agent,native_id) DO NOTHING",
                (agent, native_id, chat_id),
            )
            for key, item_id in mapping.items():
                self.db.execute(
                    "INSERT INTO item_map(agent,native_id,item_id) VALUES(?,?,?) ON CONFLICT(agent,native_id) DO UPDATE SET item_id=excluded.item_id",
                    (agent, native_id + ":" + key, item_id),
                )

    def pending(self):
        return {
            x[0]
            for x in self.db.execute(
                "SELECT agent FROM projection_intent UNION SELECT agent FROM deletion_target WHERE completed=0"
            )
        }

    def confirm_delete(self, chat_id, confirmation):
        if confirmation != chat_id:
            raise ValueError("history_delete_confirmation_mismatch")
        if (
            self.db.execute("SELECT 1 FROM chat WHERE id=?", (chat_id,)).fetchone()
            is None
        ):
            raise ValueError("history_chat_not_found")
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO deleted_chat VALUES(?,?,'explicit_confirmation')",
                (chat_id, time.time_ns() // 1_000_000),
            )
            self.db.execute(
                "INSERT OR IGNORE INTO deletion_target(chat_id,agent,native_id,path) SELECT chat_id,agent,native_id,path FROM native WHERE chat_id=?",
                (chat_id,),
            )
            self.db.execute("DELETE FROM projection_intent WHERE chat_id=?", (chat_id,))

    def deletions(self):
        return [
            dict(row)
            for row in self.db.execute(
                "SELECT deletion_target.*,chat.cwd FROM deletion_target JOIN chat ON chat.id=deletion_target.chat_id WHERE completed=0 ORDER BY chat_id,agent"
            )
        ]

    def complete_delete(self, chat_id, agent):
        with self.db:
            self.db.execute(
                "UPDATE deletion_target SET completed=1 WHERE chat_id=? AND agent=?",
                (chat_id, agent),
            )
            remaining = self.db.execute(
                "SELECT 1 FROM deletion_target WHERE chat_id=? AND completed=0",
                (chat_id,),
            ).fetchone()
            if remaining:
                return
            self.db.execute(
                "DELETE FROM item_map WHERE item_id IN (SELECT id FROM item WHERE chat_id=?)",
                (chat_id,),
            )
            self.db.execute("DELETE FROM item WHERE chat_id=?", (chat_id,))
            self.db.execute("DELETE FROM native_fact WHERE chat_id=?", (chat_id,))
            for table in ("source_revision", "source_latest", "projection"):
                self.db.execute(
                    "DELETE FROM "
                    + table
                    + " WHERE (agent,native_id) IN (SELECT agent,native_id FROM native WHERE chat_id=?)",
                    (chat_id,),
                )
            self.db.execute(
                "UPDATE native SET fingerprint='',title='' WHERE chat_id=?", (chat_id,)
            )
            self.db.execute("UPDATE chat SET title='' WHERE id=?", (chat_id,))
            referenced = set()
            for row in self.db.execute("SELECT data FROM source_revision"):
                for change in json.loads(zlib.decompress(row[0]))["changes"]:
                    referenced.update(change[2])
            for row in self.db.execute("SELECT digest FROM source_chunk"):
                if row[0] not in referenced:
                    self.db.execute(
                        "DELETE FROM source_chunk WHERE digest=?", (row[0],)
                    )

    def native_id(self, chat_id, agent):
        row = self.db.execute(
            "SELECT native_id FROM native WHERE chat_id=? AND agent=?", (chat_id, agent)
        ).fetchone()
        if row:
            return row[0]
        identifier = stable(chat_id, agent)
        if agent == "opencode2":
            identifier = "ses_" + identifier.replace("-", "")
        with self.db:
            self.db.execute(
                "INSERT INTO native(agent,native_id,chat_id) VALUES(?,?,?)",
                (agent, identifier, chat_id),
            )
        return identifier

    def bindings(self, agent, native_id):
        prefix = native_id + ":"
        return {
            row[0][len(prefix) :]: row[1]
            for row in self.db.execute(
                "SELECT native_id,item_id FROM item_map WHERE agent=? AND substr(native_id,1,?)=?",
                (agent, len(prefix), prefix),
            )
        }

    def store_source(self, snapshot, chat_id):
        raw = snapshot.raw_bytes or encode(snapshot.raw).encode()
        self.archive_source(snapshot, raw)
        self.db.execute(
            "UPDATE native_fact SET present=0 WHERE source_agent=? AND source_native_id=?",
            (snapshot.agent, snapshot.native_id),
        )
        facts = list(snapshot.facts)
        if snapshot.interrupted:
            from .model import Fact

            facts.append(
                Fact(
                    "partial_record",
                    "partial_native_record",
                    {"retained_bytes": len(raw)},
                    snapshot.updated,
                )
            )
        for fact in facts:
            self.db.execute(
                "INSERT INTO native_fact VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(source_agent,source_native_id,native_id) DO UPDATE SET kind=excluded.kind,body=excluded.body,created=excluded.created,present=1",
                (
                    chat_id,
                    snapshot.agent,
                    snapshot.native_id,
                    fact.native_id,
                    fact.kind,
                    encode(fact.body),
                    fact.created,
                ),
            )

    def archive_source(self, snapshot, raw):
        latest = self.db.execute(
            "SELECT fingerprint,chunks FROM source_latest WHERE agent=? AND native_id=?",
            (snapshot.agent, snapshot.native_id),
        ).fetchone()
        previous = json.loads(zlib.decompress(latest["chunks"])) if latest else []
        chunks = []
        for record in raw.splitlines(keepends=True):
            digest = fingerprint(record)
            chunks.append(digest)
            self.db.execute(
                "INSERT OR IGNORE INTO source_chunk VALUES(?,?)",
                (digest, zlib.compress(record)),
            )
        changes = [
            [start, end, chunks[new_start:new_end]]
            for tag, start, end, new_start, new_end in difflib.SequenceMatcher(
                a=previous, b=chunks, autojunk=False
            ).get_opcodes()
            if tag != "equal"
        ]
        revision = encode(
            {"base": latest["fingerprint"] if latest else None, "changes": changes}
        ).encode()
        self.db.execute(
            "INSERT OR IGNORE INTO source_revision VALUES(?,?,?,?)",
            (
                snapshot.agent,
                snapshot.native_id,
                snapshot.fingerprint,
                zlib.compress(revision),
            ),
        )
        self.db.execute(
            "INSERT INTO source_latest VALUES(?,?,?,?) ON CONFLICT(agent,native_id) DO UPDATE SET fingerprint=excluded.fingerprint,chunks=excluded.chunks",
            (
                snapshot.agent,
                snapshot.native_id,
                snapshot.fingerprint,
                zlib.compress(encode(chunks).encode()),
            ),
        )

    def raw_revision(self, agent, native_id, revision=None):
        if revision is None:
            latest = self.db.execute(
                "SELECT fingerprint FROM source_latest WHERE agent=? AND native_id=?",
                (agent, native_id),
            ).fetchone()
            if latest is None:
                raise ValueError("source_revision_not_found")
            revision = latest[0]
        chain = []
        while revision is not None:
            row = self.db.execute(
                "SELECT data FROM source_revision WHERE agent=? AND native_id=? AND fingerprint=?",
                (agent, native_id, revision),
            ).fetchone()
            if row is None:
                raise ValueError("source_revision_not_found")
            data = json.loads(zlib.decompress(row[0]))
            chain.append(data["changes"])
            revision = data["base"]
        chunks = []
        for changes in reversed(chain):
            for start, end, replacement in reversed(changes):
                chunks[start:end] = replacement
        return b"".join(
            zlib.decompress(
                self.db.execute(
                    "SELECT data FROM source_chunk WHERE digest=?", (digest,)
                ).fetchone()[0]
            )
            for digest in chunks
        )

    def retention(self, chat_id, target):
        return [
            {
                "chat_id": chat_id,
                "target": target,
                "source": row[0],
                "kind": row[1],
                "count": row[3],
                "storage": "native_and_encrypted_archive"
                if row[0] == target and row[2]
                else "encrypted_archive",
            }
            for row in self.db.execute(
                "SELECT source_agent,kind,present,count(*) FROM native_fact WHERE chat_id=? GROUP BY source_agent,kind,present",
                (chat_id,),
            )
        ]

    def exported(self, chat_id, agent, native_id, path, snapshot, mapping):
        with self.db:
            self.store_source(snapshot, chat_id)
            self.db.execute(
                "UPDATE native SET fingerprint=?,path=?,title=? WHERE agent=? AND native_id=? AND chat_id=?",
                (
                    snapshot.fingerprint,
                    str(path),
                    snapshot.title,
                    agent,
                    native_id,
                    chat_id,
                ),
            )
            for item in snapshot.items:
                self.db.execute(
                    "INSERT INTO item_map VALUES(?,?,?,?) ON CONFLICT(agent,native_id) DO UPDATE SET item_id=excluded.item_id,digest=excluded.digest",
                    (
                        agent,
                        native_id + ":" + item.native_id,
                        mapping[item.native_id],
                        item_digest(item),
                    ),
                )
            self.db.execute(
                "INSERT INTO projection VALUES(?,?,?) ON CONFLICT(agent,native_id) DO UPDATE SET digest=excluded.digest",
                (agent, native_id, self.version(chat_id)),
            )
            self.db.execute(
                "DELETE FROM projection_intent WHERE agent=? AND native_id=?",
                (agent, native_id),
            )


def item_digest(item):
    body = dict(item.body)
    if item.kind == "tool_result" and isinstance(body["content"], str):
        body["content"] = [{"type": "text", "text": body["content"]}]
    return fingerprint(encode([item.kind, item.role, body]).encode())


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".oblivion-" + uuid.uuid4().hex)
    try:
        with open(temporary, "xb") as output:
            os.chmod(temporary, 0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()
