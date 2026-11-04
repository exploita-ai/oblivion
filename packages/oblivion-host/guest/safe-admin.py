"""SafeAdmin v1. Fixed Safe-local roots and private credential-only handoff.

Credential bodies travel only on this root-opened private channel. Ordinary
metadata operations never start a native agent or read a credential store.
"""

import contextlib
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import select
import stat
import sqlite3
import struct
import sys
import time
import uuid

sys.path.insert(0, "/usr/lib/oblivion/history")
from oblivion_history.admin import catalog_state

READY = b"OBSA1\n"
REQUEST_LIMIT = 32768
RESPONSE_LIMIT = 65536
AGENTS = {"codex", "claude", "opencode2"}


def credential_adapter():
    spec = importlib.util.spec_from_file_location("oblivion_credential_delegation", Path(__file__).with_name("credential-delegation.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Rejected(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("invalid_safe_admin_request")
        value[key] = item
    return value


def safe_id(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{32}", value) is not None


def chat_id(value):
    return isinstance(value, str) and len(value) == 36 and str(uuid.UUID(value)) == value


def safe_text(value, maximum):
    return isinstance(value, str) and len(value) <= maximum and all(char.isprintable() for char in value)


def metadata(value):
    if not isinstance(value, dict) or set(value) != {"format", "version", "safe_id", "title", "history_version", "origin"}:
        raise Rejected("invalid-metadata")
    if type(value["version"]) is not int or type(value["history_version"]) is not int:
        raise Rejected("invalid-metadata")
    if value["version"] != 1 or value["history_version"] != 1:
        raise Rejected("unsupported-version")
    if value["format"] != "oblivion-safe" or not safe_id(value["safe_id"]):
        raise Rejected("invalid-metadata")
    title = value["title"]
    if title is not None and (not safe_text(title, 80) or not title.strip() or title != title.strip() or len(title.encode()) > 256):
        raise Rejected("invalid-metadata")
    origin(value["origin"], value["safe_id"])
    return value


def origin(value, identifier):
    if value == {"kind": "local"}:
        return
    if not isinstance(value, dict):
        raise Rejected("invalid-metadata")
    if value.get("kind") == "agent-created" and set(value) == {"kind", "record"}:
        record = value["record"]
        fields = {"safe_id", "parent_id", "request_id", "agent", "creator_chat_id", "sealed_task", "attempts"}
        if not isinstance(record, dict) or set(record) != fields or record["safe_id"] != identifier or not safe_id(record["parent_id"]) or record["parent_id"] == identifier or not safe_id(record["request_id"]) or record["agent"] not in AGENTS:
            raise Rejected("invalid-metadata")
        creator = record["creator_chat_id"]
        if creator is not None and (not isinstance(creator, str) or not 0 < len(creator.encode()) <= 256 or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in creator)):
            raise Rejected("invalid-metadata")
        attempts = record["attempts"]
        if not isinstance(attempts, list) or len(attempts) > 16 or any(not safe_id(item) for item in attempts) or len(set(attempts)) != len(attempts) or attempts and attempts[0] != record["request_id"]:
            raise Rejected("invalid-metadata")
        sealed = record["sealed_task"]
        if not isinstance(sealed, dict) or set(sealed) != {"version", "family_id", "nonce", "ciphertext"} or type(sealed["version"]) is not int or sealed["version"] != 1 or not safe_id(sealed["family_id"]) or not isinstance(sealed["nonce"], list) or len(sealed["nonce"]) != 24 or any(type(byte) is not int or not 0 <= byte <= 255 for byte in sealed["nonce"]) or not isinstance(sealed["ciphertext"], str) or len(sealed["ciphertext"]) > 21868:
            raise Rejected("invalid-metadata")
        try:
            ciphertext = base64.b64decode(sealed["ciphertext"], validate=True)
        except (ValueError, TypeError):
            raise Rejected("invalid-metadata") from None
        if not 17 <= len(ciphertext) <= 16400 or base64.b64encode(ciphertext).decode() != sealed["ciphertext"]:
            raise Rejected("invalid-metadata")
        return
    if value.get("kind") == "shared" and set(value) == {"kind", "parent_id", "provenance", "source_policy", "required_proxy"}:
        if value["parent_id"] is not None and (not safe_id(value["parent_id"]) or value["parent_id"] == identifier) or value["source_policy"] not in ("offline", "strict", "open-internet"):
            raise Rejected("invalid-metadata")
        provenance = value["provenance"]
        if provenance is not None and (not isinstance(provenance, dict) or set(provenance) != {"created_by_agent", "requested_agent", "parent_not_included"} or type(provenance["created_by_agent"]) is not bool or type(provenance["parent_not_included"]) is not bool or provenance["requested_agent"] is not None and provenance["requested_agent"] not in AGENTS or not provenance["created_by_agent"] and provenance["requested_agent"] is not None):
            raise Rejected("invalid-metadata")
        proxy = value["required_proxy"]
        if proxy is not None and (not isinstance(proxy, str) or not proxy.strip() or len(proxy.encode()) > 240 or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in proxy)):
            raise Rejected("invalid-metadata")
        return
    raise Rejected("invalid-metadata")


def report(value):
    fields = {"version", "controller_version", "architecture", "cpu_cores", "memory_mib", "ephemeral", "general_open",
              "session", "transport", "direct_access_blocked", "observation_age_ms", "tor_bootstrap", "laboratory"}
    if not isinstance(value, dict) or set(value) != fields or type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("invalid_diagnostics")
    if not isinstance(value["controller_version"], str) or not re.fullmatch(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}", value["controller_version"]):
        raise ValueError("invalid_diagnostics")
    if value["architecture"] not in ("aarch64", "x86_64", "unknown") or value["session"] not in ("locked", "documents", "agent", "starting", "recovery") or value["transport"] not in ("not_started", "connecting", "tor", "socks5", "offline", "unknown"):
        raise ValueError("invalid_diagnostics")
    for key in ("ephemeral", "general_open", "direct_access_blocked", "laboratory"):
        if type(value[key]) is not bool:
            raise ValueError("invalid_diagnostics")
    for key, minimum, maximum in (("cpu_cores", 1, 4096), ("memory_mib", 0, 1024**3), ("observation_age_ms", 0, 2**64 - 1)):
        if type(value[key]) is not int or not minimum <= value[key] <= maximum:
            raise ValueError("invalid_diagnostics")
    if value["tor_bootstrap"] is not None and (type(value["tor_bootstrap"]) is not int or not 0 <= value["tor_bootstrap"] <= 100):
        raise ValueError("invalid_diagnostics")
    return value


def request(value):
    if not isinstance(value, dict) or set(value) != {"version", "command"} or type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("invalid_safe_admin_request")
    command = value["command"]
    if not isinstance(command, dict):
        raise ValueError("invalid_safe_admin_request")
    if command in ({"operation": "usage"}, {"operation": "inspect"}):
        return command
    if command.get("operation") == "job" and set(command) == {"operation", "job_id"} and safe_id(command["job_id"]):
        return command
    if command.get("operation") == "credential-export" and set(command) == {"operation", "agent"} and command["agent"] in AGENTS:
        return command
    if command.get("operation") == "credential-install" and set(command) == {"operation", "credential"}:
        credential_adapter().credential(command["credential"])
        return command
    if command.get("operation") == "diagnostics" and set(command) == {"operation", "report"}:
        report(command["report"])
        return command
    if command.get("operation") == "checkpoint" and set(command) == {"operation", "metadata"}:
        metadata(command["metadata"])
        return command
    if command.get("operation") == "archive-state" and set(command) <= {"operation", "cursor"}:
        if command.get("cursor") is None or chat_id(command["cursor"]):
            return {"operation": "archive-state", "cursor": command.get("cursor")}
    raise ValueError("invalid_safe_admin_request")


def archive_state(directory, cursor):
    try:
        value = catalog_state(directory, cursor)
    except (OSError, ValueError, sqlite3.Error):
        raise Rejected("invalid-catalog") from None
    if not isinstance(value, dict) or set(value) != {"history_version", "consistency", "entries", "next", "pending"}:
        raise Rejected("invalid-catalog")
    if type(value["history_version"]) is not int or value["history_version"] != 1 or value["consistency"] not in ("catalog-sqlite-ok", "catalog-empty"):
        raise Rejected("invalid-catalog")
    if not isinstance(value["entries"], list) or len(value["entries"]) > 50:
        raise Rejected("invalid-catalog")
    def agents(items):
        return isinstance(items, list) and len(items) <= 3 and all(isinstance(item, str) and item in AGENTS for item in items) and len(set(items)) == len(items)
    if not agents(value["pending"]):
        raise Rejected("invalid-catalog")
    previous = cursor or ""
    for entry in value["entries"]:
        if not isinstance(entry, dict) or set(entry) != {"chat_id", "title", "updated", "agents"}:
            raise Rejected("invalid-catalog")
        if not chat_id(entry["chat_id"]) or entry["chat_id"] <= previous or not safe_text(entry["title"], 240) or type(entry["updated"]) is not int or not 0 <= entry["updated"] <= 2**64 - 1 or not agents(entry["agents"]):
            raise Rejected("invalid-catalog")
        previous = entry["chat_id"]
    if value["next"] is not None and (len(value["entries"]) != 50 or value["next"] != previous):
        raise Rejected("invalid-catalog")
    if value["consistency"] == "catalog-empty" and (value["entries"] or value["next"] is not None or value["pending"]):
        raise Rejected("invalid-catalog")
    return value


@contextlib.contextmanager
def metadata_directory(vault, create=False):
    descriptor = os.open(vault / "state", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if create:
            try:
                os.mkdir("oblivion", mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
        target = os.open("oblivion", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
        try:
            info = os.fstat(target)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise Rejected("invalid-metadata")
            yield target
            os.fsync(target)
            os.fsync(descriptor)
        finally:
            os.close(target)
    finally:
        os.close(descriptor)


def read_metadata(target):
    descriptor = os.open("safe.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=target)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077 or not 0 < info.st_size <= REQUEST_LIMIT:
            raise Rejected("invalid-metadata")
        return metadata(json.loads(source.read(REQUEST_LIMIT + 1), object_pairs_hook=unique))


def write_metadata(vault, value, owner):
    with metadata_directory(vault, True) as target:
        # An unsupported current header must not be overwritten by this writer.
        try:
            read_metadata(target)
        except FileNotFoundError:
            pass
        name = ".pending-admin-" + owner + "-" + secrets.token_hex(16)
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
        try:
            with os.fdopen(descriptor, "wb") as destination:
                destination.write((json.dumps(value, ensure_ascii=False) + "\n").encode())
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(name, "safe.json", src_dir_fd=target, dst_dir_fd=target)
            os.fsync(target)
        finally:
            try:
                os.unlink(name, dir_fd=target)
            except FileNotFoundError:
                pass


def write_diagnostics(vault, value, owner):
    content = (json.dumps(value, sort_keys=True, ensure_ascii=True) + "\n").encode()
    if not 0 < len(content) <= 4096:
        raise ValueError("invalid_diagnostics")
    workspace = os.open(vault / "workspace", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            os.mkdir("diagnostics", mode=0o700, dir_fd=workspace)
        except FileExistsError:
            pass
        target = os.open("diagnostics", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=workspace)
        try:
            name = secrets.token_hex(16) + ".json"
            pending = ".pending-admin-" + owner + "-" + name
            descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
            try:
                with os.fdopen(descriptor, "wb") as destination:
                    destination.write(content)
                    destination.flush()
                    os.fsync(destination.fileno())
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
    return {"result": "exported", "path": "workspace/diagnostics/" + name, "bytes": len(content)}


def execute(value, *, vault=Path("/vault"), owner):
    if not re.fullmatch(r"oblivion\.admin\.[a-f0-9]{32}", owner):
        raise ValueError("invalid_safe_admin_owner")
    command = request(value)
    operation = command["operation"]
    if operation in ("credential-export", "credential-install"):
        adapter = credential_adapter()
        try:
            if operation == "credential-export":
                return {"result": "credential", "credential": adapter.export(vault, command["agent"]), "reason": None}
            adapter.install(vault, command["credential"])
            return {"result": "credential-installed"}
        except adapter.Rejected as error:
            reason = error.code
        except (OSError, ValueError, sqlite3.Error):
            reason = "needs-auth" if operation == "credential-export" else "install-failed"
        if operation == "credential-export":
            return {"result": "credential", "credential": None, "reason": reason}
        return {"result": "credential-not-installed", "reason": reason}
    if operation == "job":
        home = os.open(vault / "home", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                directory = os.open(".oblivion-jobs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
            except FileNotFoundError:
                return {"result": "job", "info": None}
            try:
                info = os.fstat(directory)
                if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise ValueError("invalid_job_storage")
                spec = importlib.util.spec_from_file_location("oblivion_managed_job", Path(__file__).with_name("managed-job.py"))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                try:
                    result = module.inspect(directory, command["job_id"])
                except module.Rejected as error:
                    if error.code != "not-found":
                        raise ValueError("invalid_job_storage") from None
                    result = None
                return {"result": "job", "info": result}
            finally:
                os.close(directory)
        finally:
            os.close(home)
    if operation == "usage":
        space = os.statvfs(vault)
        return {"result": "storage", "usage": {
            "capacity": space.f_blocks * space.f_frsize,
            "used": (space.f_blocks - space.f_bfree) * space.f_frsize,
            "available": space.f_bavail * space.f_frsize,
        }}
    if operation == "diagnostics":
        return write_diagnostics(vault, command["report"], owner)
    try:
        current = archive_state(vault / "home/.oblivion-history", command.get("cursor"))
        if operation == "archive-state":
            return {"result": "archive-state", "state": current}
        if operation == "inspect":
            with metadata_directory(vault) as target:
                return {"result": "metadata", "metadata": read_metadata(target)}
        write_metadata(vault, command["metadata"], owner)
        return {"result": "metadata", "metadata": command["metadata"]}
    except Rejected as error:
        return {"result": "rejected", "error": error.code}
    except (OSError, ValueError):
        return {"result": "unavailable"}


def cleanup(vault, owner):
    if not re.fullmatch(r"oblivion\.admin\.[a-f0-9]{32}", owner):
        raise ValueError("invalid_safe_admin_owner")
    for parent, child in ((vault / "state", "oblivion"), (vault / "workspace", "diagnostics")):
        try:
            source = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        try:
            try:
                target = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source)
            except FileNotFoundError:
                continue
            try:
                for name in os.listdir(target):
                    if name.startswith(".pending-admin-" + owner + "-"):
                        os.unlink(name, dir_fd=target)
                os.fsync(target)
            finally:
                os.close(target)
        finally:
            os.close(source)


def serve_channel(channel, *, vault=Path("/vault"), owner):
    deadline = time.monotonic() + 45
    def exact(length):
        data = bytearray()
        while len(data) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([channel], [], [], remaining)[0]:
                raise ValueError("safe_admin_timeout")
            part = channel.read(length - len(data))
            if not part:
                raise ValueError("safe_admin_disconnected")
            data.extend(part)
        return data
    def write(data):
        remaining = memoryview(data)
        while remaining:
            count = channel.write(remaining)
            if not count:
                raise ValueError("safe_admin_disconnected")
            remaining = remaining[count:]
    write(READY)
    try:
        if exact(1) != b"G":
            raise ValueError("invalid_safe_admin_handshake")
        length = struct.unpack("!I", exact(4))[0]
        if not 0 < length <= REQUEST_LIMIT:
            raise ValueError("invalid_safe_admin_frame")
        body = exact(length)
        try:
            value = json.loads(body, object_pairs_hook=unique)
            if length > 4096 and request(value)["operation"] not in ("checkpoint", "credential-install"):
                raise ValueError("invalid_safe_admin_frame")
            result = execute(value, vault=vault, owner=owner)
        finally:
            body[:] = b"\0" * len(body)
    except Exception:
        # No filename, user text, credential or raw exception crosses this channel.
        result = {"result": "unavailable"}
    payload = bytearray(json.dumps({"version": 1, "response": result}, separators=(",", ":"), ensure_ascii=True).encode())
    if len(payload) > RESPONSE_LIMIT:
        payload = b'{"version":1,"response":{"result":"unavailable"}}'
    try:
        write(struct.pack("!I", len(payload)))
        write(payload)
    finally:
        if isinstance(payload, bytearray):
            payload[:] = b"\0" * len(payload)


def drop_privileges():
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(1000)
        os.setuid(1000)


def main():
    os.umask(0o077)
    if len(sys.argv) == 3 and sys.argv[1] == "--cleanup":
        drop_privileges()
        cleanup(Path("/vault"), sys.argv[2])
        return
    if len(sys.argv) != 2:
        raise ValueError("invalid_safe_admin_port")
    path = Path(sys.argv[1])
    if path.parent != Path("/dev/virtio-ports") or not re.fullmatch(r"oblivion\.admin\.[a-f0-9]{32}", path.name):
        raise ValueError("invalid_safe_admin_port")
    descriptor = os.open(path, os.O_RDWR | os.O_CLOEXEC)
    if not stat.S_ISCHR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("invalid_safe_admin_port")
    drop_privileges()
    with os.fdopen(descriptor, "r+b", buffering=0) as channel:
        serve_channel(channel, owner=path.name)


if __name__ == "__main__":
    main()
