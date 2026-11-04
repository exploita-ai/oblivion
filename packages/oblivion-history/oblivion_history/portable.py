"""Selected canonical history, never native profiles, source snapshots or auth."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import time
import uuid

from .catalog import Catalog
from .model import encode

FORMAT = "oblivion-history-portable"
VERSION = 1
MAX_CHATS = 2048
MAX_ITEMS = 100000
MAX_LINE = 16 * 1024 * 1024
MAX_BYTES = 256 * 1024 * 1024
KINDS = {"text", "image", "file", "tool_call", "tool_result"}


def identifier(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("invalid_portable_chat_identity")
    return value


def relative(value):
    if not isinstance(value, str) or len(value.encode()) > 4096 or "\\" in value or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value):
        raise ValueError("invalid_portable_workspace")
    if value and (PurePosixPath(value).is_absolute() or any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError("invalid_portable_workspace")
    return value


def timestamp(value):
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError("invalid_portable_timestamp")
    return value


def text(value, maximum):
    if not isinstance(value, str) or len(value.encode()) > maximum or "\0" in value:
        raise ValueError("invalid_portable_text")
    return value


def body(kind, value):
    fields = {
        "text": ({"text"}, {"text"}), "image": ({"url"}, {"url"}),
        "file": ({"mime", "data"}, {"mime", "data", "name"}),
        "tool_call": ({"id", "name", "input"}, {"id", "name", "input"}),
        "tool_result": ({"id", "content", "is_error"}, {"id", "content", "is_error"}),
    }
    if kind not in fields or not isinstance(value, dict) or not fields[kind][0] <= value.keys() <= fields[kind][1]:
        raise ValueError("invalid_portable_item")
    if kind == "text":
        text(value["text"], MAX_LINE)
    if kind == "image":
        text(value["url"], MAX_LINE)
        # URLs are retained as text. Share never resolves a path or fetches it.
        if not value["url"].startswith(("data:image/", "https://", "http://")):
            raise ValueError("invalid_portable_attachment")
    if kind == "file":
        text(value["mime"], 256)
        text(value["data"], MAX_LINE)
        if value.get("name") is not None:
            text(value["name"], 4096)
    if kind in ("tool_call", "tool_result"):
        text(value["id"], 1024)
    if kind == "tool_call":
        text(value["name"], 256)
    if kind == "tool_result" and (not isinstance(value["content"], (str, list)) or type(value["is_error"]) is not bool):
        raise ValueError("invalid_portable_tool_result")
    # Strict JSON disallows non-finite numbers and bounds nested data on import.
    json.dumps(value, allow_nan=False)
    return value


@contextmanager
def source_catalog(directory):
    directory = Path(directory)
    try:
        info = directory.lstat()
    except FileNotFoundError:
        yield None
        return
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("history_catalog_unavailable")
    held = []
    database = None
    try:
        for name in ("sync.lock", "codex.active", "claude.active", "opencode2.active"):
            try:
                fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except FileNotFoundError:
                continue
            held.append(fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("history_catalog_unavailable")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("history_client_active") from None
        path = directory / "history.sqlite"
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            yield None
            return
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077 or source.read(16) != b"SQLite format 3\0":
                raise ValueError("history_catalog_unavailable")
            database = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=3)
            database.row_factory = sqlite3.Row
            database.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_LINE)
            database.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
            deadline = time.monotonic() + 60
            database.set_progress_handler(lambda: time.monotonic() >= deadline, 10000)
            database.execute("PRAGMA query_only=ON")
            database.execute("PRAGMA trusted_schema=OFF")
            database.execute("BEGIN")
            if database.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise ValueError("unsupported_catalog_format")
            if database.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok":
                raise ValueError("history_catalog_unavailable")
            if database.execute("SELECT 1 FROM projection_intent LIMIT 1").fetchone() or database.execute("SELECT 1 FROM deletion_target WHERE completed=0 LIMIT 1").fetchone():
                raise ValueError("history_recovery_required")
            yield database
    finally:
        if database:
            database.close()
        for fd in held:
            os.close(fd)


def export_catalog(directory, workspace, chat_ids, destination, *, imports=None):
    """Write one filtered JSONL file in private encrypted staging.

    None selects all chats explicitly; [] selects none. No native executable,
    source archive, provider reasoning or native identity is consulted.
    """
    if chat_ids is not None and (not isinstance(chat_ids, list) or len(chat_ids) > MAX_CHATS or len(set(chat_ids)) != len(chat_ids)):
        raise ValueError("invalid_portable_chat_selection")
    for value in chat_ids or []:
        identifier(value)
    roots = {"workspace": Path(workspace)}
    if imports is not None:
        roots["imports"] = Path(imports)
    report = {"chats": 0, "items": 0, "omitted": {}}
    total = 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output, source_catalog(directory) as database:
            def write(record):
                nonlocal total
                data = (encode(record) + "\n").encode()
                total += len(data)
                if len(data) > MAX_LINE or total > MAX_BYTES:
                    raise ValueError("portable_history_limit")
                output.write(data)

            write({"format": FORMAT, "version": VERSION})
            rows = []
            if database is not None and chat_ids is None:
                rows = database.execute("SELECT * FROM chat WHERE id NOT IN (SELECT chat_id FROM deleted_chat) ORDER BY id LIMIT ?", (MAX_CHATS + 1,)).fetchall()
            if database is not None and chat_ids:
                rows = database.execute("SELECT * FROM chat WHERE id IN (" + ",".join("?" for _ in chat_ids) + ") AND id NOT IN (SELECT chat_id FROM deleted_chat) ORDER BY id", chat_ids).fetchall()
            if len(rows) > MAX_CHATS:
                raise ValueError("portable_chat_limit")
            available = {row["id"] for row in rows}
            if chat_ids is not None and not set(chat_ids) <= available:
                raise ValueError("portable_chat_missing")
            for chat in rows:
                if chat_ids is not None and chat["id"] not in chat_ids:
                    continue
                identifier(chat["id"])
                path = Path(chat["cwd"])
                cwd = None
                for scope, root in roots.items():
                    if path == root or path.is_relative_to(root):
                        cwd = {"scope": scope, "path": relative("" if path == root else path.relative_to(root).as_posix())}
                        break
                if cwd is None:
                    raise ValueError("portable_workspace_outside_safe")
                write({"type": "chat", "id": chat["id"], "cwd": cwd, "title": text(chat["title"], 4096),
                       "created": timestamp(chat["created"]), "updated": timestamp(chat["updated"])})
                report["chats"] += 1
                ordinal = 0
                calls, results = set(), set()
                for item in database.execute("SELECT * FROM item WHERE chat_id=? ORDER BY ordinal", (chat["id"],)):
                    if item["kind"] == "reasoning":
                        report["omitted"]["provider_reasoning"] = report["omitted"].get("provider_reasoning", 0) + 1
                        continue
                    identifier(item["id"])
                    value = body(item["kind"], json.loads(item["body"]))
                    if item["role"] not in ("user", "assistant"):
                        raise ValueError("invalid_portable_role")
                    if item["kind"] == "tool_call":
                        if value["id"] in calls:
                            raise ValueError("invalid_portable_tool_pair")
                        calls.add(value["id"])
                    if item["kind"] == "tool_result":
                        if value["id"] not in calls or value["id"] in results:
                            raise ValueError("invalid_portable_tool_pair")
                        results.add(value["id"])
                    ordinal += 1
                    report["items"] += 1
                    if report["items"] > MAX_ITEMS:
                        raise ValueError("portable_item_limit")
                    write({"type": "item", "chat_id": chat["id"], "id": item["id"], "ordinal": ordinal,
                           "kind": item["kind"], "role": item["role"], "body": value, "created": timestamp(item["created"])})
                if calls != results:
                    raise ValueError("invalid_portable_tool_pair")
                for row in database.execute("SELECT kind,count(*) FROM native_fact WHERE chat_id=? GROUP BY kind", (chat["id"],)):
                    kind = row[0] if row[0] in {"provider_reasoning", "compaction", "interrupted_tool", "unsettled_tool", "attachment", "tool_content"} else "native_records"
                    report["omitted"][kind] = report["omitted"].get(kind, 0) + row[1]
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        Path(destination).unlink(missing_ok=True)
        raise
    report["bytes"] = total
    return report


def import_catalog(source, directory, workspace, *, imports=None):
    """Populate a new Safe's empty canonical catalog. Never merge histories."""
    directory = Path(directory)
    if directory.exists() and any(directory.iterdir()):
        raise ValueError("portable_catalog_destination_exists")
    catalog = Catalog(directory)
    roots = {"workspace": Path(workspace)}
    if imports is not None:
        roots["imports"] = Path(imports)
    total = 0
    chats, items, calls, results = {}, set(), {}, {}
    try:
        with catalog.exclusive(), catalog.db, open(source, "rb") as input:
            for line_number, line in enumerate(iter(lambda: input.readline(MAX_LINE + 1), b"")):
                total += len(line)
                if len(line) > MAX_LINE or total > MAX_BYTES or not line.endswith(b"\n"):
                    raise ValueError("portable_history_limit")
                value = json.loads(line, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_portable_json")))
                if line_number == 0:
                    if value != {"format": FORMAT, "version": VERSION} or type(value.get("version")) is not int:
                        raise ValueError("unsupported_portable_history")
                    continue
                if not isinstance(value, dict):
                    raise ValueError("invalid_portable_record")
                if value.get("type") == "chat" and set(value) == {"type", "id", "cwd", "title", "created", "updated"}:
                    chat = identifier(value["id"])
                    if chat in chats or len(chats) >= MAX_CHATS:
                        raise ValueError("duplicate_portable_chat")
                    cwd = value["cwd"]
                    if not isinstance(cwd, dict) or set(cwd) != {"scope", "path"} or cwd["scope"] not in roots:
                        raise ValueError("invalid_portable_workspace")
                    cwd = str(roots[cwd["scope"]] / relative(cwd["path"]))
                    chats[chat] = 0
                    calls[chat], results[chat] = set(), set()
                    catalog.db.execute("INSERT INTO chat VALUES(?,?,?,?,?)", (chat, cwd, text(value["title"], 4096), timestamp(value["created"]), timestamp(value["updated"])))
                    continue
                if value.get("type") != "item" or set(value) != {"type", "chat_id", "id", "ordinal", "kind", "role", "body", "created"}:
                    raise ValueError("invalid_portable_record")
                chat = identifier(value["chat_id"])
                item = identifier(value["id"])
                if chat not in chats or item in items or len(items) >= MAX_ITEMS or type(value["ordinal"]) is not int or value["ordinal"] != chats[chat] + 1 or value["role"] not in ("user", "assistant"):
                    raise ValueError("invalid_portable_item")
                content = body(value["kind"], value["body"])
                if value["kind"] == "tool_call":
                    if content["id"] in calls[chat]:
                        raise ValueError("invalid_portable_tool_pair")
                    calls[chat].add(content["id"])
                if value["kind"] == "tool_result":
                    if content["id"] not in calls[chat] or content["id"] in results[chat]:
                        raise ValueError("invalid_portable_tool_pair")
                    results[chat].add(content["id"])
                items.add(item)
                chats[chat] += 1
                catalog.db.execute("INSERT INTO item VALUES(?,?,?,?,?,?,?)", (item, chat, value["ordinal"], value["kind"], value["role"], encode(content), timestamp(value["created"])))
            if total == 0 or any(calls[chat] != results[chat] for chat in chats):
                raise ValueError("invalid_portable_tool_pair")
            # A chat-only Share still needs its declared working directory.
            # Create data directories from pinned roots; never follow a link.
            for row in catalog.db.execute("SELECT cwd FROM chat"):
                path = Path(row[0])
                for root in roots.values():
                    if not path.is_relative_to(root):
                        continue
                    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        for name in path.relative_to(root).parts:
                            try:
                                os.mkdir(name, mode=0o700, dir_fd=fd)
                            except FileExistsError:
                                pass
                            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                            os.close(fd)
                            fd = child
                    finally:
                        os.close(fd)
                    break
    finally:
        catalog.close()
    return {"chats": len(chats), "items": len(items)}
