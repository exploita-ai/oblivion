"""Read a SQLite snapshot through OpenCode's export API, never the live server."""

import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import sys
import tempfile
import urllib.parse

spec = importlib.util.spec_from_file_location("chat_database", Path(__file__).with_name("chat-database.py"))
chat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chat)
spec = importlib.util.spec_from_file_location("session_backup", Path(__file__).with_name("session-backup.py"))
session_backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session_backup)

LIMIT = 64 * 1024 * 1024


def request(value):
    if not isinstance(value, dict):
        raise ValueError("invalid_chat_export_request")
    if value.get("action") == "list" and set(value) <= {"action", "cursor"}:
        cursor = value.get("cursor")
        if cursor is None or isinstance(cursor, str) and len(cursor.encode()) <= 1024:
            return value
    if value.get("action") == "export" and set(value) == {"action", "id", "format"}:
        if isinstance(value["id"], str) and re.fullmatch(r"ses_[A-Za-z0-9_-]{1,128}", value["id"]) and value["format"] in ("markdown", "json"):
            return value
    if value.get("action") == "diagnostics" and set(value) == {"action", "report"}:
        report(value["report"])
        return value
    if value.get("action") == "checkpoint" and set(value) == {"action", "metadata"}:
        session_backup.metadata(value["metadata"])
        return value
    if value == {"action": "inspect"}:
        return value
    raise ValueError("invalid_chat_export_request")


def report(value):
    fields = {"version", "controller_version", "architecture", "cpu_cores", "memory_mib", "ephemeral", "general_open",
              "session", "transport", "direct_access_blocked", "observation_age_ms", "tor_bootstrap", "laboratory"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("invalid_diagnostics")
    if value["version"] != 1 or type(value["version"]) is not int:
        raise ValueError("invalid_diagnostics")
    if not isinstance(value["controller_version"], str) or not re.fullmatch(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}", value["controller_version"]):
        raise ValueError("invalid_diagnostics")
    if value["architecture"] not in ("aarch64", "x86_64", "unknown") or value["session"] not in ("locked", "documents", "chat", "starting", "recovery") or value["transport"] not in ("not_started", "connecting", "tor", "socks5", "offline", "unknown"):
        raise ValueError("invalid_diagnostics")
    for key in ("ephemeral", "general_open", "direct_access_blocked", "laboratory"):
        if type(value[key]) is not bool:
            raise ValueError("invalid_diagnostics")
    for key, minimum, maximum in (("cpu_cores", 1, 4096), ("memory_mib", 0, 1024 ** 3), ("observation_age_ms", 0, 2 ** 64 - 1)):
        if type(value[key]) is not int or not minimum <= value[key] <= maximum:
            raise ValueError("invalid_diagnostics")
    if value["tor_bootstrap"] is not None and (type(value["tor_bootstrap"]) is not int or not 0 <= value["tor_bootstrap"] <= 100):
        raise ValueError("invalid_diagnostics")
    return value


def markdown(transcript):
    def block(value):
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
        fence = "`" * max(3, max((len(run) + 1 for run in re.findall(r"`+", text)), default=3))
        return fence + "\n" + text + "\n" + fence

    lines = ["# " + (transcript["info"].get("title") or "Untitled chat").replace("\n", " "),
             "", "Chat: " + transcript["info"]["id"], "",
             "Settled messages only. An in-progress response is omitted; export again after it completes.", ""]
    for message in transcript["messages"]:
        lines += ["## " + message["type"].replace("-", " ").title(), ""]
        if message["type"] in ("user", "synthetic", "system", "skill"):
            lines += [message["text"], ""]
            if message.get("files"):
                lines += ["Attached files (metadata and inline data):", block(message["files"]), ""]
            continue
        if message["type"] == "assistant":
            for content in message["content"]:
                if content["type"] == "text":
                    lines += [content["text"], ""]
                    continue
                if content["type"] == "reasoning":
                    lines += ["### Reasoning", "", content["text"], ""]
                    continue
                lines += ["### Tool: " + content["name"], "", block(content["state"]), ""]
            if message.get("error"):
                lines += ["Error:", block(message["error"]), ""]
            continue
        # Preserve shell output, compaction and other transcript records without
        # maintaining a second copy of OpenCode's evolving message schema.
        lines += [block(message), ""]
    return "\n".join(lines)


def execute(value, vault=Path("/vault"), binary="/usr/bin/oblivion", owner="manual"):
    if not re.fullmatch(r"manual|vport[0-9]{1,5}p[0-9]{1,5}|oblivion\.archive\.[a-f0-9]{32}", owner):
        raise ValueError("invalid_export_owner")
    value = request(value)
    if value["action"] in ("checkpoint", "inspect"):
        result = session_backup.execute(value, vault, owner)
        if value["action"] == "inspect" and result["result"] == "metadata":
            try:
                # Validate engine compatibility on a private SQLite snapshot,
                # without mutating the restored DB or resuming pending work.
                execute({"action": "list", "cursor": None}, vault, binary, owner)
            except Exception:
                return {"result": "rejected", "error": "invalid-database"}
        return result
    if value["action"] == "diagnostics":
        return write(vault, (json.dumps(value["report"], indent=2) + "\n").encode(), "diagnostics", ".json", owner)
    data = vault / "state/opencode"
    canonical = data / "oblivion.db"
    legacy = [path for path in (data / "opencode-oblivion-beta.db", data / "opencode-oblivion-dev.db", data / "opencode.db") if path.is_file()]
    if not canonical.is_file() and not legacy:
        if value["action"] == "list":
            return {"result": "chats", "entries": [], "next": None}
        raise ValueError("chat_not_found")
    # SQLite backup includes committed WAL frames. The private copy and the
    # server's runtime both stay inside this session's encrypted filesystem.
    with tempfile.TemporaryDirectory(prefix=".chat-export-" + owner + "-", dir=data) as directory:
        stage = Path(directory)
        snapshot = stage / "snapshot.db"
        if canonical.is_file():
            chat.backup(canonical, snapshot)
        else:
            # Older profiles can export offline too. Migrate only private
            # snapshots; never change the original databases as a side effect.
            for path in legacy:
                chat.backup(path, stage / path.name)
            snapshot = chat.prepare(stage, binary)
        runtime = stage / "runtime"
        runtime.mkdir(mode=0o700)
        with chat.server(binary, snapshot, runtime) as call:
            if value["action"] == "list":
                query = {"limit": 50, "order": "desc", "parentID": "null"}
                if value.get("cursor") is not None:
                    query["cursor"] = value["cursor"]
                result = call("/api/session?" + urllib.parse.urlencode(query), envelope=True)
                following = result.get("cursor", {}).get("next")
                # OpenCode cursors identify an anchor, even at the end. Avoid
                # offering an empty next page as though no chats existed yet.
                if following and not call("/api/session?" + urllib.parse.urlencode({**query, "cursor": following, "limit": 1})):
                    following = None
                return {"result": "chats", "entries": [{
                    "id": entry["id"],
                    "title": "".join(char for char in (entry.get("title") or "Untitled chat") if char.isprintable())[:200],
                } for entry in result["data"]], "next": following}
            transcript = call("/api/experimental/session/" + value["id"] + "/export")
        content = (json.dumps(transcript, ensure_ascii=False, indent=2) + "\n" if value["format"] == "json" else markdown(transcript)).encode()
        if len(content) > LIMIT:
            raise ValueError("chat_export_too_large")
        return write(vault, content, "chat-exports", ".json" if value["format"] == "json" else ".md", owner)


def write(vault, content, folder, extension, owner):
    name = secrets.token_hex(16) + extension
    pending = ".pending-" + owner + "-" + name
    # Never follow a workspace symlink or overwrite an existing document.
    workspace = os.open(vault / "workspace", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            os.mkdir(folder, mode=0o700, dir_fd=workspace)
        except FileExistsError:
            pass
        target = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=workspace)
        try:
            descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
            try:
                with os.fdopen(descriptor, "wb") as file:
                    file.write(content)
                    file.flush()
                    os.fsync(file.fileno())
                # Publish a complete file without replacing an existing name.
                os.link(pending, name, src_dir_fd=target, dst_dir_fd=target, follow_symlinks=False)
                os.fsync(target)
            finally:
                os.unlink(pending, dir_fd=target)
                os.fsync(target)
        finally:
            os.close(target)
        os.fsync(workspace)
    finally:
        os.close(workspace)
    return {"result": "exported", "path": "workspace/" + folder + "/" + name, "bytes": len(content)}


def cleanup(vault=Path("/vault"), owner=None):
    if owner is not None and not re.fullmatch(r"manual|vport[0-9]{1,5}p[0-9]{1,5}|oblivion\.archive\.[a-f0-9]{32}", owner):
        raise ValueError("invalid_export_owner")
    session_backup.cleanup(vault, owner)
    # Per-port cleanup runs after the service's entire process group stops.
    # Boot cleanup runs before any session process can start, for power loss.
    for path in (vault / "state/opencode").glob(".chat-export-" + (owner + "-" if owner else "") + "*"):
        if path.is_symlink():
            path.unlink()
            continue
        if path.is_dir() and path.stat().st_uid == os.geteuid():
            shutil.rmtree(path)
    for folder in ("chat-exports", "diagnostics"):
        path = vault / "workspace" / folder
        if not path.is_dir() or path.is_symlink():
            continue
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            prefix = ".pending-" + (owner + "-" if owner else "")
            for name in os.listdir(descriptor):
                if name.startswith(prefix):
                    os.unlink(name, dir_fd=descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def main():
    os.umask(0o077)
    if len(sys.argv) == 2 and sys.argv[1] == "--cleanup-all":
        cleanup()
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--cleanup":
        cleanup(owner=sys.argv[2])
        return
    with os.fdopen(3, "r+b", buffering=0) as channel:
        def read(size):
            result = b""
            while len(result) < size:
                part = channel.read(size - len(result))
                if not part:
                    raise ValueError("incomplete_request")
                result += part
            return result

        try:
            size = struct.unpack(">I", read(4))[0]
            if not 0 < size <= 4096:
                raise ValueError("invalid_request")
            result = execute(json.loads(read(size)), owner=Path(sys.argv[1]).name)
        except Exception:
            # Errors and paths from the engine never cross into diagnostics.
            result = {"result": "unavailable"}
        payload = json.dumps(result, ensure_ascii=False).encode()
        if len(payload) > 64 * 1024:
            payload = b'{"result":"unavailable"}'
        channel.write(struct.pack(">I", len(payload)) + payload)


if __name__ == "__main__":
    main()
