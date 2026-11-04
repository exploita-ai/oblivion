"""Safe-local prompt admission, with Linux process pins and a crash fence.

Only Claude's mandatory native hook is integrated. Other native clients need
their own supported control-protocol admission seam before claiming coverage.
"""

from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import sqlite3
import stat
import struct
import sys
import uuid

from .catalog import Catalog
from .rpc import notify_ready, receive, send
from .sync import allowed_cwd

LIMIT = 4096
AGENTS = ("codex", "claude", "opencode2")
TOKEN = re.compile(r"[0-9a-f]{32}\Z")


def process_identity(pid):
    # comm may contain spaces or parentheses. Fields after the final ')' begin
    # at state (3); PPID and starttime are fields 4 and 22 respectively.
    fields = Path("/proc", str(pid), "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "parent": int(fields[1]), "start": int(fields[19])}


def alive(descriptor):
    return not select.select([descriptor], [], [], 0)[0]


def peer_process(stream):
    pid, uid, _ = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != os.getuid():
        raise ValueError("author_untrusted_peer")
    # SO_PEERPIDFD pins the socket's actual process, avoiding a numeric PID
    # lookup after process exit/reuse. Unsupported kernels fail closed.
    descriptor = stream.getsockopt(socket.SOL_SOCKET, 77)
    os.set_inheritable(descriptor, False)
    try:
        identity = process_identity(pid)
        if not alive(descriptor):
            raise ValueError("author_owner_exited")
        return {**identity, "fd": descriptor}
    except BaseException:
        os.close(descriptor)
        raise


def pin_child(pid, parent):
    before = process_identity(pid)
    if before["parent"] != parent["pid"] or not alive(parent["fd"]):
        raise ValueError("author_invalid_child")
    descriptor = os.pidfd_open(pid, 0)
    os.set_inheritable(descriptor, False)
    try:
        if process_identity(pid) != before or not alive(descriptor):
            raise ValueError("author_invalid_child")
        return {**before, "fd": descriptor}
    except BaseException:
        os.close(descriptor)
        raise


def descendant(pid, child):
    for _ in range(64):
        current = process_identity(pid)
        if pid == child["pid"]:
            return current["start"] == child["start"] and alive(child["fd"])
        if current["parent"] <= 1 or current["parent"] == pid:
            return False
        pid = current["parent"]
    return False


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("author_private_directory_required")
    return path


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Registry:
    def __init__(self, state, workspace):
        if not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open"):
            raise ValueError("author_process_pinning_unavailable")
        self.state = private_directory(state)
        self.directory = private_directory(self.state / "authors")
        self.workspace = str(Path(workspace).resolve())
        self.boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        uuid.UUID(self.boot)
        descriptor = os.open(self.directory / "service.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self.service = os.fdopen(descriptor, "a+b")
        fcntl.flock(self.service, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.owners = {}
        self.leases = {}
        self.fenced = False
        for path in self.directory.glob("*.active"):
            try:
                with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "r") as source:
                    record = json.loads(source.read(LIMIT + 1))
                if record["version"] != 1 or not isinstance(record["boot_id"], str):
                    raise ValueError("invalid_author_marker")
                uuid.UUID(record["boot_id"])
                if record["boot_id"] == self.boot:
                    self.fenced = True
                    continue
                # A new guest boot cannot still contain an old boot's writer.
                path.unlink()
                sync_directory(self.directory)
            except (OSError, ValueError, KeyError, TypeError):
                self.fenced = True

    def close(self):
        # Live markers deliberately survive service failure. A replacement
        # daemon must not infer writer death from a dropped flock.
        for lease in self.leases.values():
            lease.close()
        for owner in self.owners.values():
            os.close(owner["wrapper"]["fd"])
            if owner["child"]:
                os.close(owner["child"]["fd"])
        self.service.close()

    def reap(self):
        for token, owner in list(self.owners.items()):
            wrapper_alive = alive(owner["wrapper"]["fd"])
            child_alive = owner["child"] and alive(owner["child"]["fd"])
            if not wrapper_alive and child_alive:
                # Kill exactly the pinned native child, never a recycled PID
                # or another chat's process group. Keep its leases until exit.
                try:
                    signal.pidfd_send_signal(owner["child"]["fd"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if wrapper_alive or child_alive:
                continue
            for chat in owner["chats"]:
                try:
                    (self.directory / (chat + ".active")).unlink()
                    sync_directory(self.directory)
                except OSError:
                    self.fenced = True
                self.leases.pop(chat).close()
            os.close(owner["wrapper"]["fd"])
            if owner["child"]:
                os.close(owner["child"]["fd"])
            del self.owners[token]

    def handle(self, message, peer):
        if not isinstance(message, dict) or type(message.get("version")) is not int or message.get("version") != 1:
            raise ValueError("author_invalid_request")
        self.reap()
        if self.fenced:
            raise ValueError("author_recovery_required_reopen_safe")
        operation = message.get("operation")
        if operation == "register" and set(message) == {"version", "operation", "agent"}:
            if message["agent"] not in AGENTS or len(self.owners) >= 64:
                raise ValueError("author_admission_unavailable")
            token = uuid.uuid4().hex
            self.owners[token] = {"agent": message["agent"], "wrapper": {**peer, "fd": os.dup(peer["fd"])}, "child": None, "chats": set()}
            return {"owner": token}
        token = message.get("owner")
        if not isinstance(token, str) or not TOKEN.fullmatch(token) or token not in self.owners:
            raise ValueError("author_owner_not_registered")
        owner = self.owners[token]
        if operation == "bind-child" and set(message) == {"version", "operation", "owner", "pid"}:
            if owner["child"] is not None or owner["wrapper"]["pid"] != peer["pid"] or owner["wrapper"]["start"] != peer["start"] or type(message["pid"]) is not int or message["pid"] <= 1:
                raise ValueError("author_invalid_child")
            owner["child"] = pin_child(message["pid"], owner["wrapper"])
            return {"bound": True}
        if operation != "claim" or set(message) != {"version", "operation", "owner", "native_id", "cwd"}:
            raise ValueError("author_invalid_request")
        native_id = message["native_id"]
        if not isinstance(native_id, str) or not 1 <= len(native_id) <= 128 or not re.fullmatch(r"[A-Za-z0-9_-]+", native_id) or not allowed_cwd(message["cwd"], self.workspace):
            raise ValueError("author_invalid_request")
        if owner["child"] is None or not alive(owner["wrapper"]["fd"]) or not alive(peer["fd"]) or process_identity(peer["pid"])["start"] != peer["start"] or not descendant(peer["pid"], owner["child"]) or not alive(peer["fd"]):
            raise ValueError("author_invalid_owner")
        catalog = Catalog(self.state, timeout=0.1)
        try:
            with catalog.exclusive(blocking=False):
                chat = catalog.author_identity(owner["agent"], native_id, message["cwd"], owner["chats"])
        finally:
            catalog.close()
        if chat in owner["chats"]:
            return {"allowed": True}
        if chat in self.leases:
            raise ValueError("author_conversation_busy")
        if len(self.leases) >= 128:
            raise ValueError("author_admission_unavailable")
        descriptor = os.open(self.directory / (chat + ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        lease = os.fdopen(descriptor, "a+b")
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            record = {"version": 1, "boot_id": self.boot, "chat_id": chat, "agent": owner["agent"], "native_id": native_id,
                      "wrapper": {key: owner["wrapper"][key] for key in ("pid", "start")},
                      "child": {key: owner["child"][key] for key in ("pid", "start")}}
            path = self.directory / (chat + ".active")
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w") as output:
                json.dump(record, output, separators=(",", ":"))
                output.flush()
                os.fsync(output.fileno())
            sync_directory(self.directory)
        except BaseException:
            lease.close()
            # A partially persisted marker must remain a restart fence.
            if (self.directory / (chat + ".active")).exists():
                self.fenced = True
            raise
        self.leases[chat] = lease
        owner["chats"].add(chat)
        return {"allowed": True}


def call(path, message):
    metadata = Path(path).lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("author_untrusted_socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(3)
        stream.connect(str(path))
        peer = peer_process(stream)
        try:
            send(stream, message, LIMIT)
            result = receive(stream, LIMIT)
        finally:
            os.close(peer["fd"])
    if not isinstance(result, dict) or result.get("version") != 1:
        raise ValueError("author_invalid_response")
    if result.get("error"):
        code = result["error"]
        raise ValueError(code if isinstance(code, str) and re.fullmatch("author_[a-z_]{1,80}", code) else "author_unavailable")
    if not isinstance(result.get("result"), dict):
        raise ValueError("author_invalid_response")
    return result["result"]


def serve(path, state, workspace):
    path = Path(path)
    private_directory(path.parent)
    registry = Registry(state, workspace)
    with ExitStack() as stack:
        stack.callback(registry.close)
        listener = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        # The singleton state lock was acquired first, so an old socket here
        # cannot still belong to another admitted author daemon.
        path.unlink(missing_ok=True)
        listener.bind(str(path))
        os.chmod(path, 0o600)
        listener.listen(32)
        listener.settimeout(0.1)
        stack.callback(lambda: path.unlink(missing_ok=True))
        notify_ready()
        while True:
            registry.reap()
            try:
                stream, _ = listener.accept()
            except TimeoutError:
                continue
            with stream:
                peer = None
                try:
                    stream.settimeout(1)
                    peer = peer_process(stream)
                    result = registry.handle(receive(stream, LIMIT), peer)
                    send(stream, {"version": 1, "result": result}, LIMIT)
                except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, struct.error) as error:
                    code = str(error)
                    code = code if re.fullmatch(r"author_[a-z_]{1,80}", code) else "author_unavailable"
                    try:
                        send(stream, {"version": 1, "error": code}, LIMIT)
                    except OSError:
                        pass
                finally:
                    if peer:
                        os.close(peer["fd"])


def child(command, descriptor):
    # The actual native PID is pinned before it can execute a hook or write.
    try:
        ready = os.read(descriptor, 1)
    finally:
        os.close(descriptor)
    if ready != b"1":
        return 125
    os.execvpe(command[0], command, os.environ)


def hook(path):
    try:
        data = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024:
            raise ValueError("author_invalid_request")
        message = json.loads(data)
        if not isinstance(message, dict) or message.get("hook_event_name") != "UserPromptSubmit":
            raise ValueError("author_invalid_request")
        result = call(path, {"version": 1, "operation": "claim", "owner": os.environ.get("OBLIVION_AUTHOR_OWNER"),
                             "native_id": message.get("session_id"), "cwd": message.get("cwd")})
        if result != {"allowed": True}:
            raise ValueError("author_unavailable")
        print("{}")
        return 0
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, struct.error) as error:
        # Native queue metadata may still exist, but the denied text must not
        # become a canonical user message. No prompt bytes leave this process.
        reason = {
            "author_conversation_busy": "This conversation is already in use. Close its other client before submitting here.",
            "author_history_stale_reopen": "This client's conversation is stale. Close and reopen the agent to load its updated history.",
            "author_recovery_required_reopen_safe": "Conversation admission needs recovery. Close and reopen this Safe before continuing.",
            "author_chat_deleted": "This conversation was deleted and cannot accept another prompt.",
        }.get(str(error), "Conversation admission is unavailable. Close the other client or reopen this Safe before retrying.")
        print(json.dumps({"decision": "block", "reason": reason,
                          "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}))
        return 0
