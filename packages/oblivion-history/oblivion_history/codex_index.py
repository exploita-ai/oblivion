"""Positive metadata for the pinned native Codex index; never a database copy.

Maintenance only reads selected rows or stages their transfer. Schema creation
belongs to the official binary on an explicit Codex launch in the new Safe.
"""

import fcntl
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import subprocess
import time

VERSION = "0.159.2"
DATABASE = "state_5.sqlite"
MIGRATION = 58
MAX_THREADS = 2048
MAX_ATTACHMENTS = 4096
LIMIT = 16 * 1024 * 1024
COLUMNS = (
    "id", "rollout_path", "created_at", "updated_at", "created_at_ms", "updated_at_ms",
    "recency_at", "recency_at_ms", "source", "model_provider", "cwd", "title", "cli_version",
    "history_mode", "name", "preview", "first_user_message", "tokens_used", "archived", "archived_at",
    "originator", "thread_source", "agent_nickname", "agent_role", "agent_path",
)
INTEGERS = {"created_at", "updated_at", "created_at_ms", "updated_at_ms", "recency_at", "recency_at_ms", "tokens_used", "archived"}
OPTIONAL = {"name", "archived_at", "originator", "thread_source", "agent_nickname", "agent_role", "agent_path"}
ATTACHMENTS = ("id", "thread_id", "attachment_type", "identity_key", "payload", "created_at")


def database(vault):
    return Path(vault) / "home/.codex" / DATABASE


def connection(vault, *, writable=False):
    from .portable import open_file

    path = database(vault)
    with open_file(path):
        pass
    target = sqlite3.connect(path.resolve().as_uri() + ("?mode=rw" if writable else "?mode=ro"), uri=True, timeout=5)
    target.row_factory = sqlite3.Row
    target.execute("PRAGMA trusted_schema=OFF")
    target.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, LIMIT)
    if not writable:
        target.execute("PRAGMA query_only=ON")
    current = target.execute("SELECT MAX(version) FROM _sqlx_migrations WHERE success=1").fetchone()[0]
    if current != MIGRATION:
        target.close()
        raise ValueError("unsupported_codex_index_schema")
    return target


def validate_thread(value):
    from .portable import identifier, scope
    from .codex_native import physical_id
    from .artifacts import file_path

    if not isinstance(value, dict) or set(value) != set(COLUMNS):
        raise ValueError("invalid_codex_native_index")
    identifier(value["id"])
    physical_id(file_path(value["rollout_path"]))
    scope(value["cwd"], "/vault")
    if value["cli_version"] != VERSION or value["history_mode"] not in ("legacy", "paginated") or value["archived"] not in (0, 1):
        raise ValueError("unsupported_codex_native_index")
    for key in COLUMNS:
        item = value[key]
        if key in OPTIONAL and item is None:
            continue
        if key in INTEGERS or key == "archived_at":
            if type(item) is not int or not 0 <= item <= 2**63 - 1:
                raise ValueError("invalid_codex_native_index")
            continue
        if not isinstance(item, str) or len(item.encode()) > 65536 or "\0" in item:
            raise ValueError("invalid_codex_native_index")
    return value


def validate(value):
    if not isinstance(value, dict) or set(value) != {"type", "version", "thread", "attachments"} or value["type"] != "codex-index" or type(value["version"]) is not int or value["version"] != 1 or not isinstance(value["attachments"], list) or len(value["attachments"]) > MAX_ATTACHMENTS:
        raise ValueError("invalid_codex_native_index")
    thread = validate_thread(value["thread"])
    identities = set()
    for item in value["attachments"]:
        if not isinstance(item, dict) or set(item) != set(ATTACHMENTS) or item["thread_id"] != thread["id"] or type(item["created_at"]) is not int or not 0 <= item["created_at"] <= 2**63 - 1:
            raise ValueError("invalid_codex_native_attachment")
        for key in ("id", "thread_id", "attachment_type", "identity_key"):
            if not isinstance(item[key], str) or not item[key] or len(item[key].encode()) > 1024 or "\0" in item[key]:
                raise ValueError("invalid_codex_native_attachment")
        if item["id"] in identities or len(json.dumps(item["payload"]).encode()) > 1024 * 1024:
            raise ValueError("invalid_codex_native_attachment")
        identities.add(item["id"])
    return value


def read(vault):
    staged = pending(vault)
    if staged:
        return {value["thread"]["id"]: value["thread"] for value in staged}
    if not database(vault).exists():
        return {}
    result = {}
    target = connection(vault)
    try:
        target.execute("BEGIN")
        for item in target.execute("SELECT " + ",".join(COLUMNS) + " FROM threads ORDER BY id LIMIT ?", (MAX_THREADS + 1,)):
            value = dict(item)
            path = Path(value["rollout_path"])
            try:
                relative = path.relative_to("/vault/home/.codex").as_posix()
            except ValueError:
                relative = path.relative_to(Path(vault) / "home/.codex").as_posix()
            value["rollout_path"] = relative.removesuffix(".zst")
            validate_thread(value)
            result[value["id"]] = value
            if len(result) > MAX_THREADS:
                raise ValueError("native_chat_limit")
    finally:
        target.close()
    return result


def collect(vault, selected_native_ids):
    wanted = set(selected_native_ids)
    staged = pending(vault)
    if staged:
        return [row for row in staged if row["thread"]["id"] in wanted]
    available = read(vault)
    if not wanted or not available:
        return []
    target = connection(vault)
    try:
        target.execute("BEGIN")
        result = []
        total = 0
        for identity in sorted(wanted & available.keys()):
            attached = []
            for row in target.execute("SELECT " + ",".join(ATTACHMENTS) + " FROM thread_attachments WHERE thread_id=? ORDER BY created_at,id LIMIT ?", (identity, MAX_ATTACHMENTS + 1)):
                item = dict(row)
                item["payload"] = json.loads(item["payload"])
                attached.append(item)
                total += 1
                if total > MAX_ATTACHMENTS:
                    raise ValueError("codex_attachment_limit")
            result.append(validate({"type": "codex-index", "version": 1, "thread": available[identity], "attachments": attached}))
        return result
    finally:
        target.close()


def pending(vault):
    from .portable import open_file

    path = Path(vault) / "state/oblivion/native-imports/codex/index.json"
    if not path.exists():
        return []
    with open_file(path) as source:
        value = json.loads(source.read(LIMIT + 1))
    if not isinstance(value, dict) or set(value) != {"version", "records"} or type(value["version"]) is not int or value["version"] != 1 or not isinstance(value["records"], list) or len(value["records"]) > MAX_THREADS:
        raise ValueError("invalid_codex_native_index")
    rows = [validate(row) for row in value["records"]]
    if len({row["thread"]["id"] for row in rows}) != len(rows):
        raise ValueError("invalid_codex_native_index")
    return rows


def restore(vault, rows):
    if not rows:
        return
    values = [validate(row) for row in rows]
    if len(values) > MAX_THREADS or len({row["thread"]["id"] for row in values}) != len(values):
        raise ValueError("invalid_codex_native_index")
    data = json.dumps({"version": 1, "records": values}, ensure_ascii=False, separators=(",", ":")).encode()
    if len(data) > LIMIT:
        raise ValueError("codex_native_index_limit")
    directory = Path(vault) / "state/oblivion/native-imports/codex"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(directory / "index.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    target = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(target)
    finally:
        os.close(target)


def initialize(binary):
    process = subprocess.Popen([binary, "app-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        request = {"id": 1, "method": "initialize", "params": {"clientInfo": {"name": "oblivion", "version": "1.0"}, "capabilities": {"experimentalApi": True}}}
        process.stdin.write((json.dumps(request) + "\n").encode())
        process.stdin.flush()
        deadline = time.monotonic() + 45
        pending = bytearray()
        while time.monotonic() < deadline:
            if not select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
                break
            part = os.read(process.stdout.fileno(), 65536)
            if not part:
                break
            pending.extend(part)
            if len(pending) > 1024 * 1024:
                raise ValueError("codex_native_initialization_failed")
            while b"\n" in pending:
                line, _, rest = pending.partition(b"\n")
                pending[:] = rest
                response = json.loads(line)
                if response.get("id") == 1:
                    if "result" not in response or "error" in response:
                        raise ValueError("codex_native_initialization_failed")
                    return
        raise ValueError("codex_native_initialization_failed")
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        process.stdout.close()


def prepare(vault, binary):
    from .portable import open_file

    directory = Path(vault) / "state/oblivion/native-imports/codex"
    if not directory.exists():
        return
    lock = os.open(directory / ".lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        staged = directory / "index.json"
        if not staged.exists():
            return
        rows = pending(vault)
        for row in rows:
            with open_file(Path(vault) / "home/.codex" / row["thread"]["rollout_path"]):
                pass
        initialize(binary)
        target = connection(vault, writable=True)
        try:
            target.execute("BEGIN IMMEDIATE")
            for row in rows:
                thread = {**row["thread"], "rollout_path": str(Path(vault) / "home/.codex" / row["thread"]["rollout_path"])}
                # Native builder defaults, without copying source permissions or account IDs.
                thread.update(sandbox_policy="read-only", approval_mode="on-request")
                columns = (*COLUMNS, "sandbox_policy", "approval_mode")
                target.execute("INSERT INTO threads (" + ",".join(columns) + ") VALUES (" + ",".join("?" for _ in columns) + ") ON CONFLICT(id) DO UPDATE SET " + ",".join(key + "=excluded." + key for key in columns if key != "id"), tuple(thread[key] for key in columns))
                for item in row["attachments"]:
                    values = {**item, "payload": json.dumps(item["payload"], ensure_ascii=False, separators=(",", ":"))}
                    target.execute("INSERT INTO thread_attachments (" + ",".join(ATTACHMENTS) + ") VALUES (" + ",".join("?" for _ in ATTACHMENTS) + ") ON CONFLICT(id) DO UPDATE SET " + ",".join(key + "=excluded." + key for key in ATTACHMENTS if key != "id"), tuple(values[key] for key in ATTACHMENTS))
            target.commit()
            target.execute("PRAGMA wal_checkpoint(FULL)")
        finally:
            target.close()
        staged.unlink()
        target = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(target)
        finally:
            os.close(target)
    finally:
        os.close(lock)
