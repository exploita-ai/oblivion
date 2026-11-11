"""Forward only versioned Safe tools over this guest's dedicated virtio port.

No host path, Safe identity, provider credential or arbitrary command is accepted.
The host binds the other end to this particular VM opening.
"""
import json
import os
import re
import select
import socket
import struct
import threading
import time

LIMIT = 24 * 1024
PORT = "/dev/virtio-ports/oblivion.safe-tools"
SOCKET = "/run/oblivion-safe-tools.sock"


def read_exact(fd, length, deadline):
    data = bytearray()
    while len(data) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise TimeoutError()
        chunk = os.read(fd, length - len(data))
        if not chunk:
            raise EOFError()
        data.extend(chunk)
    return data


def write_all(fd, data, deadline):
    offset = 0
    while offset < len(data):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
            raise TimeoutError()
        try:
            offset += os.write(fd, data[offset:])
        except BlockingIOError:
            continue


def read_frame(fd, deadline):
    length, = struct.unpack(">I", read_exact(fd, 4, deadline))
    if not 0 < length <= LIMIT:
        raise ValueError("invalid_frame")
    return json.loads(read_exact(fd, length, deadline))


def write_frame(fd, value, deadline):
    data = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    if not 0 < len(data) <= LIMIT:
        raise ValueError("invalid_frame")
    write_all(fd, struct.pack(">I", len(data)) + data, deadline)


def capabilities(value):
    if (not isinstance(value, dict)
            or set(value) != {"version", "kind", "operations", "limit"}
            or type(value["version"]) is not int or value["version"] != 1
            or value["kind"] != "capabilities" or value["limit"] != LIMIT
            or value["operations"] != ["safe_status", "safe_create", "chat_create", "chat_status", "chat_cancel"]):
        raise ValueError("invalid_capabilities")
    return value


def request(value):
    if (not isinstance(value, dict) or set(value) != {"version", "request_id", "call"}
            or type(value["version"]) is not int or value["version"] != 1
            or not isinstance(value["request_id"], str)
            or not re.fullmatch("[0-9a-f]{32}", value["request_id"])
            or not isinstance(value["call"], dict)):
        raise ValueError("invalid_request")
    call = value["call"]
    if call.get("operation") == "safe-status":
        if set(call) != {"operation", "offset"} or type(call["offset"]) is not int or not 0 <= call["offset"] <= 32:
            raise ValueError("invalid_request")
    elif call.get("operation") == "chat-create":
        if (set(call) != {"operation", "agent", "task", "request_id"}
                or call["agent"] not in ("codex", "claude", "opencode2")
                or not isinstance(call["task"], str) or not call["task"].strip()
                or len(call["task"].encode()) > 16384 or "\0" in call["task"]
                or not isinstance(call["request_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", call["request_id"])):
            raise ValueError("invalid_request")
    elif call.get("operation") == "chat-status":
        if not set(call) <= {"operation", "job_id", "request_id"}:
            raise ValueError("invalid_request")
        selected = [call.get(key) for key in ("job_id", "request_id") if call.get(key) is not None]
        if len(selected) != 1 or not isinstance(selected[0], str) or not re.fullmatch(r"[a-f0-9]{32}", selected[0]):
            raise ValueError("invalid_request")
    elif call.get("operation") == "chat-cancel":
        if set(call) != {"operation", "job_id"} or not isinstance(call["job_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", call["job_id"]):
            raise ValueError("invalid_request")
    elif call.get("operation") == "safe-create":
        if (not {"operation", "agent", "task"} <= set(call)
                or not set(call) <= {"operation", "agent", "task", "creator_chat_id"}
                or call["agent"] not in ("codex", "claude", "opencode2")
                or not isinstance(call["task"], str) or not call["task"].strip()
                or len(call["task"].encode()) > 16384 or "\0" in call["task"]):
            raise ValueError("invalid_request")
        creator = call.get("creator_chat_id")
        if creator is not None and (not isinstance(creator, str) or not creator
                or len(creator.encode()) > 256 or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in creator)):
            raise ValueError("invalid_request")
    else:
        raise ValueError("invalid_request")
    return value


def response(value, request_id):
    if (not isinstance(value, dict) or type(value.get("version")) is not int or value.get("version") != 1
            or value.get("request_id") != request_id or type(value.get("ok")) is not bool):
        raise ValueError("invalid_response")
    if value["ok"]:
        if set(value) != {"version", "request_id", "ok", "result"} or not isinstance(value["result"], dict):
            raise ValueError("invalid_response")
    elif (set(value) != {"version", "request_id", "ok", "error"}
          or not isinstance(value["error"], str) or not re.fullmatch("[a-z0-9_]{1,96}", value["error"])):
        raise ValueError("invalid_response")
    return value


def serve(port, listener, offered):
    # Discovery must remain responsive while another agent creates a Safe.
    # Only one client may forward an RPC; overlapping calls receive Busy.
    forwarding = threading.Lock()
    clients = threading.BoundedSemaphore(4)
    stopped = threading.Event()

    def client(connection):
        try:
            with connection:
                try:
                    value = request(read_frame(connection.fileno(), time.monotonic() + 10))
                except (EOFError, TimeoutError, ValueError, OSError):
                    return
                if not forwarding.acquire(blocking=False):
                    write_frame(connection.fileno(), {"version": 1, "request_id": value["request_id"],
                                "ok": False, "error": "safe_tools_busy"}, time.monotonic() + 2)
                    return
                try:
                    deadline = time.monotonic() + 180
                    write_frame(port, value, deadline)
                    result = response(read_frame(port, deadline), value["request_id"])
                except (EOFError, TimeoutError, ValueError, OSError):
                    stopped.set()
                    return
                finally:
                    forwarding.release()
                try:
                    write_frame(connection.fileno(), result, deadline)
                except (EOFError, TimeoutError, OSError):
                    # Consume the committed reply even if its caller vanished;
                    # never replay it or leave its frame for the next caller.
                    return
        except (EOFError, TimeoutError, ValueError, OSError):
            return
        finally:
            clients.release()

    poll = select.poll()
    poll.register(listener, select.POLLIN)
    poll.register(port, select.POLLHUP | select.POLLERR)
    while not stopped.is_set():
        for descriptor, events in poll.poll(100):
            if descriptor == port:
                raise EOFError()
            connection, _ = listener.accept()
            peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer[1] not in (0, 1000):
                connection.close()
                continue
            try:
                write_frame(connection.fileno(), offered, time.monotonic() + 2)
            except (TimeoutError, ValueError, OSError):
                connection.close()
                continue
            if not clients.acquire(blocking=False):
                connection.close()
                continue
            threading.Thread(target=client, args=(connection,), daemon=True).start()


def main():
    if os.geteuid() != 0:
        raise PermissionError()
    port = os.open(PORT, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    listener = None
    try:
        deadline = time.monotonic() + 90
        write_all(port, b"tools\n", deadline)
        offered = capabilities(read_frame(port, deadline))
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(SOCKET)
        os.chmod(SOCKET, 0o600)
        os.chown(SOCKET, 1000, 1000)
        listener.listen(8)
        write_frame(port, {"version": 1, "kind": "ready"}, deadline)
        serve(port, listener, offered)
    finally:
        if listener is not None:
            listener.close()
            os.unlink(SOCKET)
        os.close(port)


if __name__ == "__main__":
    try:
        main()
    except (EOFError, TimeoutError, ValueError, OSError):
        raise SystemExit(1)
