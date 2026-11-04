"""Pure read-only catalog snapshot, reused by SafeAdmin and the local admin RPC."""

import contextlib
import os
from pathlib import Path
import sqlite3
import stat
import time
import uuid

from .model import VERSIONS


def catalog_state(directory, cursor):
    directory = Path(directory)
    empty = {"history_version": 1, "consistency": "catalog-empty", "entries": [], "next": None, "pending": []}
    try:
        owner = directory.lstat()
    except FileNotFoundError:
        return empty
    if not stat.S_ISDIR(owner.st_mode) or owner.st_uid != os.geteuid() or owner.st_mode & 0o077:
        raise ValueError("history_catalog_unavailable")
    path = directory / "history.sqlite"
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return empty
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077 or source.read(16) != b"SQLite format 3\0":
            raise ValueError("history_catalog_unavailable")
        with contextlib.closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=3)) as db:
            db.row_factory = sqlite3.Row
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024)
            db.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
            deadline = time.monotonic() + 10
            db.set_progress_handler(lambda: time.monotonic() >= deadline, 10000)
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            if db.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise ValueError("unsupported_catalog_format")
            if db.execute("PRAGMA quick_check(1)").fetchall()[0][0] != "ok":
                raise ValueError("history_catalog_unavailable")
            rows = db.execute(
                "SELECT id,substr(title,1,240) AS title,updated FROM chat WHERE id>? AND id NOT IN (SELECT chat_id FROM deleted_chat) ORDER BY id LIMIT 51",
                (cursor or "",),
            ).fetchall()
            entries = []
            for row in rows[:50]:
                if str(uuid.UUID(row["id"])) != row["id"]:
                    raise ValueError("history_catalog_unavailable")
                agents = [value[0] for value in db.execute("SELECT substr(agent,1,16) FROM native WHERE chat_id=? ORDER BY agent LIMIT 4", (row["id"],))]
                updated = row["updated"]
                if len(agents) > 3 or any(agent not in VERSIONS for agent in agents) or type(updated) is not int or not 0 <= updated <= 2**64 - 1 or not isinstance(row["title"], str):
                    raise ValueError("history_catalog_unavailable")
                entries.append({
                    "chat_id": row["id"],
                    "title": "".join(char for char in row["title"] if char.isprintable())[:240],
                    "updated": updated,
                    "agents": agents,
                })
            pending = sorted({row[0] for row in db.execute("SELECT substr(agent,1,16) FROM projection_intent UNION SELECT substr(agent,1,16) FROM deletion_target WHERE completed=0 LIMIT 4")})
            if len(pending) > 3 or any(agent not in VERSIONS for agent in pending):
                raise ValueError("history_catalog_unavailable")
            return {
                "history_version": 1,
                "consistency": "catalog-sqlite-ok",
                "entries": entries,
                "next": entries[-1]["chat_id"] if len(rows) > 50 else None,
                "pending": pending,
            }
