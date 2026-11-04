"""Credential-free transfers of each pinned agent's own native conversations.

Nothing here synchronizes histories, converts tool names or executes a client.
The UUID selection key is derived for this export; it is not a shared catalog.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import uuid

FORMAT = "oblivion-native-histories"
VERSION = 1
VERSIONS = {"codex": "0.159.2", "claude": "2.1.302", "opencode2": "2.0.1"}
MAX_CHATS = 2048
MAX_LINE = 16 * 1024 * 1024
MAX_BYTES = 256 * 1024 * 1024
MAX_RECORDS = 100000
NAMESPACE = uuid.UUID("47a8d7ec-9838-4eac-b2fc-10f4c853822d")
CODEX_TYPES = {"session_meta", "response_item", "turn_context", "event_msg", "compacted", "compaction"}
OPENCODE_TYPES = {"agent-switched", "model-switched", "location-switched", "user", "synthetic", "system", "skill", "shell", "assistant", "compaction"}
CLAUDE_TYPES = {"user", "assistant", "system", "progress", "summary", "custom-title", "agent-name", "agent-color", "file-history-snapshot", "queue-operation", "last-prompt", "pr-link", "saved_hook_context", "attribution-snapshot"}


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def identifier(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("invalid_native_chat_selection")
    return value


def native_id(agent, value):
    if agent not in VERSIONS or not isinstance(value, str):
        raise ValueError("invalid_native_chat_identity")
    if agent == "opencode2":
        if not re.fullmatch(r"ses_[a-zA-Z0-9]{1,128}", value):
            raise ValueError("invalid_native_chat_identity")
        return value
    return identifier(value)


def reference(agent, value):
    return str(uuid.uuid5(NAMESPACE, agent + ":" + native_id(agent, value)))


def scope(value, vault):
    if not isinstance(value, str) or any(ord(char) < 32 for char in value):
        raise ValueError("invalid_native_workspace")
    for root in ("workspace", "imports"):
        try:
            relative = Path(value).relative_to(Path(vault) / root)
        except ValueError:
            continue
        if ".." in relative.parts or len(relative.parts) > 32:
            break
        return {"root": root, "path": relative.as_posix() if relative.parts else ""}
    raise ValueError("invalid_native_workspace")


def workspace(value, vault):
    if not isinstance(value, dict) or set(value) != {"root", "path"} or value["root"] not in ("workspace", "imports") or not isinstance(value["path"], str):
        raise ValueError("invalid_native_workspace")
    parts = value["path"].split("/") if value["path"] else []
    if len(parts) > 32 or any(not part or part in (".", "..") or "\\" in part or len(part.encode()) > 255 or any(ord(char) < 32 for char in part) for part in parts):
        raise ValueError("invalid_native_workspace")
    return str(Path(vault) / value["root"] / value["path"])


def open_file(path):
    path = Path(path)
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError("native_history_symlink")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BYTES:
        os.close(descriptor)
        raise ValueError("invalid_native_history_file")
    return os.fdopen(descriptor, "rb")


def records(path, *, limit=MAX_RECORDS):
    result = []
    total = 0
    with open_file(path) as source:
        while True:
            line = source.readline(MAX_LINE + 1)
            if not line:
                return result
            total += len(line)
            if len(line) > MAX_LINE or total > MAX_BYTES or len(result) >= limit or not line.endswith(b"\n"):
                raise ValueError("native_history_incomplete_or_limit")
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("invalid_native_history_record")
            result.append(value)


def files(root, pattern):
    root = Path(root)
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise ValueError("invalid_native_history_root")
    selected = []
    for parent, directories, names in os.walk(root, followlinks=False):
        if any((Path(parent) / name).is_symlink() for name in directories):
            raise ValueError("native_history_symlink")
        for name in sorted(names):
            if re.fullmatch(pattern, name):
                selected.append(Path(parent) / name)
                if len(selected) > MAX_CHATS:
                    raise ValueError("native_chat_limit")
    return sorted(selected)


def chat(agent, value, cwd, title, payload, vault):
    native_id(agent, value)
    if isinstance(title, str) and len(title.encode()) > 16384:
        raise ValueError("native_title_limit")
    return {"id": reference(agent, value), "agent": agent, "native_id": value,
            "agent_version": VERSIONS[agent], "cwd": scope(cwd, vault),
            "title": title if isinstance(title, str) else "", "records": payload, "omitted": {}, "required_paths": []}


def native_histories(vault):
    """Read only allowed transcript locations; login/config/database blobs stay out."""
    vault = Path(vault)
    selected = []
    total = 0
    count = 0

    def retain(entry):
        nonlocal total, count
        total += sum(len(encode(row).encode()) for row in entry["records"])
        count += len(entry["records"])
        if total > MAX_BYTES or count > MAX_RECORDS or len(selected) >= MAX_CHATS:
            raise ValueError("native_history_limit")
        selected.append(entry)

    titles = {}
    index = vault / "home/.codex/session_index.jsonl"
    if index.exists():
        for row in records(index):
            if isinstance(row.get("id"), str) and isinstance(row.get("thread_name"), str):
                titles[row["id"]] = row["thread_name"]
    from .codex_native import collect
    for entry in collect(vault, titles):
        retain(entry)
    from .claude_native import snapshot
    for path in files(vault / "home/.claude/projects", r"[0-9a-f-]{36}\.jsonl"):
        retain(snapshot(vault, path))
    database = vault / "state/opencode/opencode.db"
    if database.exists():
        with open_file(database):
            pass
        connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_LINE)
            connection.execute("BEGIN")
            for row in connection.execute("SELECT * FROM session_v2 ORDER BY id LIMIT ?", (MAX_CHATS + 1,)):
                value = dict(row)
                if value["version"] != VERSIONS["opencode2"]:
                    raise ValueError("unsupported_opencode_format")
                messages = []
                unsettled = 0
                for message in connection.execute("SELECT id,type,data FROM session_message WHERE session_id=? ORDER BY seq LIMIT ?", (value["id"], MAX_RECORDS + 1)):
                    data = json.loads(message["data"])
                    if not isinstance(data, dict) or "id" in data or "type" in data:
                        raise ValueError("invalid_opencode_message")
                    native = {"id": message["id"], "type": message["type"], **data}
                    if not settled(native):
                        unsettled += 1
                        continue
                    messages.append(native)
                info = {"id": value["id"], "projectID": "global", "title": value["title"] or "",
                        "cost": value["cost"], "tokens": {"input": value["tokens_input"], "output": value["tokens_output"], "reasoning": value["tokens_reasoning"], "cache": {"read": value["tokens_cache_read"], "write": value["tokens_cache_write"]}},
                        "time": {"created": value["time_created"], "updated": value["time_updated"]},
                        "location": {"directory": value["directory"]}}
                for source, target in (("parent_id", "parentID"), ("agent", "agent"), ("idle_outcome", "outcome")):
                    if value.get(source) is not None:
                        info[target] = value[source]
                if value.get("model"):
                    info["model"] = json.loads(value["model"])
                for source, target in (("time_idle", "idle"), ("time_viewed", "viewed"), ("time_archived", "archived")):
                    if value.get(source) is not None:
                        info["time"][target] = value[source]
                entry = chat("opencode2", value["id"], value["directory"], value["title"], [{"info": info}, *messages], vault)
                if unsettled:
                    entry["omitted"]["opencode_unsettled_messages"] = unsettled
                if value.get("fork_session_id"):
                    entry["omitted"]["opencode_fork_provenance"] = 1
                retain(entry)
        finally:
            connection.close()
    for path in files(vault / "state/oblivion/native-imports/opencode2", r"ses_[a-zA-Z0-9]+\.json"):
        with open_file(path) as source:
            value = validate_opencode(json.loads(source.read(MAX_BYTES + 1)), path.stem)
        if any(entry["agent"] == "opencode2" and entry["native_id"] == path.stem for entry in selected):
            continue
        retain(chat("opencode2", path.stem, value["info"]["location"]["directory"], value["info"]["title"], [{"info": value["info"]}, *value["messages"]], vault))
    if len(selected) > MAX_CHATS or len({row["id"] for row in selected}) != len(selected):
        raise ValueError("native_chat_limit_or_duplicate")
    return sorted(selected, key=lambda row: row["id"])


def export_histories(vault, chat_ids, destination):
    if chat_ids is not None and (not isinstance(chat_ids, list) or len(chat_ids) > MAX_CHATS or len(set(chat_ids)) != len(chat_ids)):
        raise ValueError("invalid_native_chat_selection")
    for value in chat_ids or []:
        identifier(value)
    available = native_histories(vault)
    selected = [row for row in available if chat_ids is None or row["id"] in chat_ids]
    if chat_ids is not None and len(selected) != len(chat_ids):
        raise ValueError("native_chat_missing")
    opencode_ids = {entry["native_id"] for entry in selected if entry["agent"] == "opencode2"}
    omitted = {"source_profile_configuration": len({entry["agent"] for entry in selected})}
    for entry in selected:
        for key, count in entry["omitted"].items():
            omitted[key] = omitted.get(key, 0) + count
        if entry["agent"] == "opencode2":
            info = entry["records"][0]["info"]
            if info.get("parentID") is not None and info["parentID"] not in opencode_ids:
                info.pop("parentID")
                omitted["opencode_unselected_parent"] = omitted.get("opencode_unselected_parent", 0) + 1
    total = 0
    count = 0
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            def write(value):
                nonlocal total
                data = (encode(value) + "\n").encode()
                total += len(data)
                if len(data) > MAX_LINE or total > MAX_BYTES:
                    raise ValueError("native_history_limit")
                output.write(data)
            write({"format": FORMAT, "version": VERSION, "agents": VERSIONS})
            for entry in selected:
                write({"kind": "chat", **{key: value for key, value in entry.items() if key not in ("records", "omitted", "required_prefixes")}})
                for record in entry["records"]:
                    count += 1
                    if count > MAX_RECORDS:
                        raise ValueError("native_history_limit")
                    write({"kind": "record", "chat_id": entry["id"], "data": record})
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        Path(destination).unlink(missing_ok=True)
        raise
    return {"chats": len(selected), "records": count, "bytes": total, "omitted": omitted}


def read_archive(source, vault):
    rows = records(source, limit=MAX_RECORDS + MAX_CHATS + 1)
    if not rows or type(rows[0].get("version")) is not int or rows[0] != {"format": FORMAT, "version": VERSION, "agents": VERSIONS}:
        raise ValueError("unsupported_native_archive")
    chats = []
    current = None
    for row in rows[1:]:
        if row.get("kind") == "chat":
            if set(row) != {"kind", "id", "agent", "native_id", "agent_version", "cwd", "title", "required_paths"} or not isinstance(row["agent"], str) or row["agent"] not in VERSIONS or row["agent_version"] != VERSIONS[row["agent"]] or not isinstance(row["title"], str) or len(row["title"].encode()) > 16384:
                raise ValueError("invalid_native_archive")
            if row["id"] != reference(row["agent"], row["native_id"]) or any(value["id"] == row["id"] for value in chats):
                raise ValueError("invalid_native_archive")
            if not isinstance(row["required_paths"], list) or len(row["required_paths"]) > 4096:
                raise ValueError("invalid_native_dependencies")
            for required in row["required_paths"]:
                if not isinstance(required, str) or "/" not in required:
                    raise ValueError("invalid_native_dependencies")
                root, relative = required.split("/", 1)
                destination = Path(workspace({"root": root, "path": relative}, vault))
                with open_file(destination):
                    pass
            current = {**row, "directory": workspace(row["cwd"], vault), "records": []}
            chats.append(current)
            if len(chats) > MAX_CHATS:
                raise ValueError("native_chat_limit")
            continue
        if current is None or set(row) != {"kind", "chat_id", "data"} or row["kind"] != "record" or row["chat_id"] != current["id"] or not isinstance(row["data"], dict):
            raise ValueError("invalid_native_archive")
        current["records"].append(row["data"])
    for entry in chats:
        validate_chat(entry)
    return chats


def validate_chat(entry):
    rows = entry["records"]
    if not rows:
        raise ValueError("empty_native_chat")
    agent = entry["agent"]
    value = entry["native_id"]
    if agent == "codex":
        from .artifacts import files
        from .codex_native import validate
        indexes = [row for row in rows if row.get("type") == "codex-index"]
        if len(indexes) > 1:
            raise ValueError("invalid_codex_index")
        artifacts = files([row for row in rows if row.get("type") != "codex-index"])
        available = validate(artifacts, value)
        if indexes:
            from . import codex_index
            codex_index.validate(indexes[0])
            selected = indexes[0]["thread"]
            if selected["id"] != value or selected["rollout_path"] not in artifacts:
                raise ValueError("invalid_codex_index")
            physical = next((meta for artifact, _, meta in available.values() if artifact["path"] == selected["rollout_path"]), None)
            if physical is None or physical["id"] != value:
                raise ValueError("invalid_codex_index")
        return
    if agent == "claude":
        from .artifacts import files
        from .claude_native import validate
        validate(files(rows), value)
        return
    transfer = {"info": rows[0].get("info"), "messages": rows[1:]}
    validate_opencode(transfer, value)


def settled(message):
    if message["type"] == "assistant":
        return isinstance(message.get("time"), dict) and "completed" in message["time"]
    if message["type"] in ("shell", "compaction"):
        return message.get("status") != "running"
    return True


def validate_opencode(value, expected=None):
    if not isinstance(value, dict) or set(value) != {"info", "messages"} or not isinstance(value["info"], dict) or not isinstance(value["messages"], list) or len(value["messages"]) > MAX_RECORDS:
        raise ValueError("invalid_opencode_transfer")
    info = value["info"]
    allowed = {"id", "projectID", "title", "cost", "tokens", "time", "location", "parentID", "agent", "model", "outcome"}
    if not set(info) <= allowed or not {"id", "projectID", "title", "cost", "tokens", "time", "location"} <= set(info) or info["id"] != native_id("opencode2", info["id"]) or expected is not None and info["id"] != expected:
        raise ValueError("invalid_opencode_transfer")
    if not isinstance(info["location"], dict) or set(info["location"]) != {"directory"} or not isinstance(info["location"]["directory"], str):
        raise ValueError("invalid_opencode_transfer")
    identities = set()
    for message in value["messages"]:
        if not isinstance(message, dict) or not re.fullmatch(r"msg_[a-zA-Z0-9]{1,128}", message.get("id", "")) or message["id"] in identities or message.get("type") not in OPENCODE_TYPES:
            raise ValueError("invalid_opencode_transfer")
        identities.add(message["id"])
    return value


def write_private(path, data):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def import_histories(source, vault):
    """Validate everything before publishing to a new Safe; never merge profiles."""
    vault = Path(vault)
    chats = read_archive(source, vault)
    targets = [vault / "home/.codex", vault / "home/.claude", vault / "state/oblivion/native-imports"]
    if any(path.exists() or path.is_symlink() for path in targets) or (vault / "state/opencode").exists():
        raise ValueError("native_history_destination_exists")
    stage = vault / "state/.oblivion-native-import"
    stage.mkdir(mode=0o700)
    try:
        indexes = []
        codex_indexes = []
        for entry in chats:
            cwd = entry["directory"]
            Path(cwd).mkdir(mode=0o700, parents=True, exist_ok=True)
            rows = entry["records"]
            if entry["agent"] == "codex":
                from .artifacts import files
                codex_indexes.extend(row for row in rows if row.get("type") == "codex-index")
                restored = files([row for row in rows if row.get("type") != "codex-index"])
                for relative, artifact in restored.items():
                    target = stage / "codex" / relative
                    if target.exists():
                        previous = target.read_bytes()
                        if previous.startswith(artifact["data"]):
                            continue
                        if not artifact["data"].startswith(previous):
                            raise ValueError("native_artifact_conflict")
                        target.unlink()
                    write_private(target, artifact["data"])
                    os.utime(target, ns=(artifact["mtime_ns"], artifact["mtime_ns"]))
                indexes.append({"id": entry["native_id"], "thread_name": entry["title"], "updated_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")})
            if entry["agent"] == "claude":
                from .artifacts import files
                for relative, artifact in files(rows).items():
                    target = stage / "claude" / relative
                    write_private(target, artifact["data"])
                    os.utime(target, ns=(artifact["mtime_ns"], artifact["mtime_ns"]))
            if entry["agent"] == "opencode2":
                transfer = {"info": rows[0]["info"], "messages": rows[1:]}
                transfer["info"]["location"] = {"directory": cwd}
                write_private(stage / "native-imports/opencode2" / (entry["native_id"] + ".json"), encode(transfer).encode())
        if codex_indexes:
            from .codex_index import restore
            # Restore into the unpublished staging Safe, then publish its pending native index.
            (stage / "state").mkdir(mode=0o700)
            restore(stage, codex_indexes)
            pending = stage / "state/oblivion/native-imports/codex"
            destination = stage / "native-imports/codex"
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.rename(pending, destination)
        if indexes:
            write_private(stage / "codex/session_index.jsonl", "".join(encode(row) + "\n" for row in indexes).encode())
        for name, destination in (("codex", targets[0]), ("claude", targets[1]), ("native-imports", targets[2])):
            if (stage / name).exists():
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.rename(stage / name, destination)
        os.sync()
    finally:
        shutil.rmtree(stage)
    return {"chats": len(chats), "agents": sorted({entry["agent"] for entry in chats})}
