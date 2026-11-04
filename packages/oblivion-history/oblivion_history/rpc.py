"""A UID-bound sync-only socket. The daemon owns every profile root."""

import json
import os
from pathlib import Path
import socket
import stat
import struct
import time
import select
from contextlib import ExitStack

MAX_REQUEST = 1024
MAX_RESPONSE = 1024 * 1024


def peer_uid(stream):
    if hasattr(socket, "SO_PEERCRED"):
        return struct.unpack(
            "3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )[1]
    # This also permits fixture use on the native development Mac. Production
    # runs the daemon inside Debian and uses SO_PEERCRED above.
    import ctypes

    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.getpeereid(stream.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise ValueError("history_peer_check_failed")
    return uid.value


def exact(stream, length):
    data = bytearray(length)
    view = memoryview(data)
    while view:
        received = stream.recv_into(view)
        if received == 0:
            raise ValueError("history_rpc_disconnected")
        view = view[received:]
    return data


def receive(stream, limit):
    length = struct.unpack("!I", exact(stream, 4))[0]
    if not 0 < length <= limit:
        raise ValueError("invalid_history_frame")
    return json.loads(exact(stream, length))


def send(stream, value, limit):
    data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    if len(data) > limit:
        raise ValueError("history_status_too_large")
    stream.sendall(struct.pack("!I", len(data)) + data)


def request(path):
    return call(path, {"version": 1, "operation": "sync"})["report"]


def call(path, message):
    path = Path(path)
    metadata = path.lstat()
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_mode & 0o077
        or metadata.st_uid != os.getuid()
    ):
        raise ValueError("untrusted_history_socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(180)
        stream.connect(str(path))
        if peer_uid(stream) != os.getuid():
            raise ValueError("untrusted_history_peer")
        send(stream, message, MAX_REQUEST)
        result = receive(stream, MAX_RESPONSE)
        if (
            not isinstance(result, dict)
            or result.get("version") != 1
            or "result" not in result
            and not isinstance(result.get("report"), dict)
        ):
            raise ValueError("invalid_history_response")
        return result


def summary(report):
    grouped = {}
    for row in report["retained"]:
        key = tuple(
            row.get(field, "")
            for field in ("target", "source", "kind", "storage", "projection")
        )
        grouped[key] = grouped.get(key, 0) + row["count"]
    retained = [
        {
            **dict(zip(("target", "source", "kind", "storage", "projection"), key)),
            "count": count,
        }
        for key, count in grouped.items()
    ]
    return {
        "ingested": report["ingested"],
        "projected": report["projected"],
        "busy": report["busy"],
        "errors": report["errors"][:64],
        "retained": retained,
        "pending": report.get("pending", []),
    }


def notify_ready():
    path = os.environ.get("NOTIFY_SOCKET")
    if path:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stream:
            stream.sendto(b"READY=1", "\0" + path[1:] if path.startswith("@") else path)


def serve(path, callback, interval, *, admin_path=None, admin=None):
    path = Path(path)
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_mode & 0o077
        or parent.st_uid != os.getuid()
    ):
        raise ValueError("private_history_directory_required")
    if admin_path and Path(admin_path).parent != path.parent:
        raise ValueError("private_history_directory_required")
    with ExitStack() as stack:
        listeners = {}
        for filename, handler in (
            (path, None),
            (Path(admin_path) if admin_path else None, admin),
        ):
            if filename is None:
                continue
            listener = stack.enter_context(
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            )
            listener.bind(str(filename))
            os.chmod(filename, 0o600)
            listener.listen(16)
            listeners[listener] = handler
        notify_ready()
        next_sync = time.monotonic() + interval
        try:
            while True:
                ready = select.select(
                    list(listeners), [], [], max(0, next_sync - time.monotonic())
                )[0]
                if not ready:
                    callback()
                    next_sync = time.monotonic() + interval
                    continue
                listener = ready[0]
                stream, _ = listener.accept()
                with stream:
                    try:
                        stream.settimeout(5)
                        if peer_uid(stream) != os.getuid():
                            continue
                        message = receive(stream, MAX_REQUEST)
                        handler = listeners[listener]
                        if handler is None:
                            if (
                                message != {"version": 1, "operation": "sync"}
                                or type(message.get("version")) is not int
                            ):
                                raise ValueError("invalid_history_request")
                            result = {"version": 1, "report": summary(callback())}
                        else:
                            result = {
                                "version": 1,
                                "result": handler(admin_request(message)),
                            }
                        stream.settimeout(10)
                        send(stream, result, MAX_RESPONSE)
                    except (OSError, ValueError, TypeError, struct.error):
                        # Invalid clients cannot choose paths or see exception
                        # text. A disconnect does not cancel an atomic sync.
                        pass
                next_sync = time.monotonic() + interval
        finally:
            path.unlink(missing_ok=True)
            if admin_path:
                Path(admin_path).unlink(missing_ok=True)


def admin_request(message):
    if (
        not isinstance(message, dict)
        or type(message.get("version")) is not int
        or message.get("version") != 1
    ):
        raise ValueError("invalid_history_request")
    if message == {"version": 1, "operation": "list"}:
        return message
    if message.get("operation") == "catalog-state" and set(message) == {"version", "operation", "cursor"}:
        import uuid

        cursor = message["cursor"]
        if cursor is not None and (not isinstance(cursor, str) or str(uuid.UUID(cursor)) != cursor):
            raise ValueError("invalid_history_request")
        return message
    if (
        set(message) != {"version", "operation", "chat_id", "confirm"}
        or message["operation"] != "delete"
    ):
        raise ValueError("invalid_history_request")
    import uuid

    if (
        not isinstance(message["chat_id"], str)
        or str(uuid.UUID(message["chat_id"])) != message["chat_id"]
    ):
        raise ValueError("invalid_history_request")
    if message["confirm"] != message["chat_id"]:
        raise ValueError("history_delete_confirmation_mismatch")
    return message
