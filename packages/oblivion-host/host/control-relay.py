#!/usr/bin/python3
"""Private native host transport. No TCP listener or filesystem export.

Request: u32be JSON length, JSON local-control header with version=1, then secret.
Response: u32be JSON length, JSON local-control response. A successful agent-attach
response is followed by raw agent-channel bytes until either endpoint closes.
The local controller connection remains open as the attachment's ownership lease.
"""

import array
import concurrent.futures
import hmac
import json
import os
import resource
import selectors
import socket
import struct
import threading
import stat
from pathlib import Path

CONTROL = "/run/oblivion-control.sock"
PORT = 4050
MAX_HEADER = 1024
MAX_SECRET = 4096
MAX_FAMILY_PASSWORD_SECRET = 16 * 1024
MAX_IMPORT_SECRET = 4 * 1024 * 1024 + 4096
MAX_RESPONSE = 1024 * 1024
MAX_BUFFER = 256 * 1024
MAX_CLIENTS = 64
AUTH_HELLO = b"OBLVCTL1"
AUTH_ACK = b"OBLVAUT1"


def secret_limit(operation):
    if operation == "family-password-change":
        return MAX_FAMILY_PASSWORD_SECRET
    if operation == "share-import-begin":
        return MAX_IMPORT_SECRET
    return MAX_SECRET


def runtime_token(arguments=None, path=Path("/run/oblivion-runtime-auth/control-token")):
    if arguments is None:
        arguments = Path("/proc/cmdline").read_text().split()
    selected = [value.split("=", 1)[1] for value in arguments if value.startswith("oblivion.runtime-backend=")]
    if "oblivion.runtime=1" not in arguments or len(selected) != 1:
        raise ValueError("runtime_backend_profile_required")
    if selected[0] == "apple-vz":
        return None
    if selected[0] not in ("qemu-kvm", "hcs-hyperv"):
        raise ValueError("runtime_backend_profile_required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size != 32 or info.st_nlink != 1:
            raise ValueError("private_runtime_token_required")
        with os.fdopen(fd, "rb", closefd=False) as source:
            token = bytearray(32)
            if source.readinto(token) != 32:
                token[:] = bytes(32)
                raise ValueError("private_runtime_token_required")
            return token
    finally:
        os.close(fd)


def authenticate_runtime(remote, token):
    offered = exact(remote, len(AUTH_HELLO) + 32)
    try:
        if not hmac.compare_digest(memoryview(offered)[:len(AUTH_HELLO)], AUTH_HELLO) or not hmac.compare_digest(memoryview(offered)[len(AUTH_HELLO):], token):
            raise ValueError("untrusted_runtime_client")
        remote.sendall(AUTH_ACK)
    finally:
        offered[:] = bytes(len(offered))


def exact(stream, size):
    data = bytearray(size)
    view = memoryview(data)
    while view:
        received = stream.recv_into(view)
        if received == 0:
            raise EOFError()
        view = view[received:]
    return data


def response(stream, data):
    if len(data) > MAX_RESPONSE:
        raise ValueError("response_too_large")
    stream.sendall(struct.pack("!I", len(data)))
    stream.sendall(data)


def error_response(stream, code):
    response(stream, json.dumps({"ok": False, "output": "", "error": code}, separators=(",", ":")).encode())


def controller_response(stream, prefix=b""):
    data = bytearray(prefix)
    while len(data) <= MAX_RESPONSE:
        chunk = stream.recv(min(65536, MAX_RESPONSE + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    raise ValueError("response_too_large")


def descriptor(stream):
    data, ancillary, flags, _ = stream.recvmsg(1, socket.CMSG_SPACE(array.array("i").itemsize * 8), socket.MSG_CMSG_CLOEXEC)
    descriptors = array.array("i")
    for level, kind, value in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors.frombytes(value[:len(value) - len(value) % descriptors.itemsize])
    if data != b"F" or len(descriptors) != 1 or flags & socket.MSG_CTRUNC:
        for fd in descriptors:
            os.close(fd)
        # Failed attachments return the controller's ordinary JSON error.
        if data and not descriptors and not flags & socket.MSG_CTRUNC:
            return None, controller_response(stream, data)
        raise ValueError("invalid_descriptor")
    return socket.socket(fileno=descriptors[0]), None


def bridge(remote, guest, lease):
    remote.setblocking(False)
    guest.setblocking(False)
    lease.setblocking(False)
    inbound = bytearray()
    outbound = bytearray()
    guest_eof = False
    with selectors.DefaultSelector() as poller:
        poller.register(lease, selectors.EVENT_READ)
        while not guest_eof or outbound:
            for stream, events in (
                (remote, (selectors.EVENT_READ if len(inbound) < MAX_BUFFER else 0)
                 | (selectors.EVENT_WRITE if outbound else 0)),
                (guest, (selectors.EVENT_READ if not guest_eof and len(outbound) < MAX_BUFFER else 0)
                 | (selectors.EVENT_WRITE if inbound else 0)),
            ):
                try:
                    if events:
                        poller.modify(stream, events)
                    else:
                        poller.unregister(stream)
                except KeyError:
                    if events:
                        poller.register(stream, events)
            for key, events in poller.select():
                stream = key.fileobj
                if stream is lease:
                    return
                if events & selectors.EVENT_WRITE:
                    pending = outbound if stream is remote else inbound
                    try:
                        length = stream.send(pending)
                    except (BlockingIOError, InterruptedError):
                        continue
                    if length == 0:
                        return
                    del pending[:length]
                if events & selectors.EVENT_READ:
                    pending = inbound if stream is remote else outbound
                    try:
                        data = stream.recv(min(65536, MAX_BUFFER - len(pending)))
                    except (BlockingIOError, InterruptedError):
                        continue
                    if not data:
                        if stream is remote:
                            # stdin EOF has a dedicated agent-channel frame.
                            # Transport EOF means the launcher disconnected.
                            return
                        guest_eof = True
                    pending.extend(data)


def serve_client(remote, token, controller=CONTROL):
    attached = False
    authenticated = token is None
    secret = bytearray()
    try:
        remote.settimeout(10)
        if token is not None:
            authenticate_runtime(remote, token)
            authenticated = True
        length = struct.unpack("!I", exact(remote, 4))[0]
        if not 0 < length <= MAX_HEADER:
            raise ValueError("invalid_header_length")
        header = json.loads(exact(remote, length))
        if not isinstance(header, dict) or type(header.get("version")) is not int or header["version"] != 1:
            raise ValueError("invalid_protocol_version")
        del header["version"]
        size = header.get("secret_len")
        if type(size) is not int or not 0 <= size <= secret_limit(header.get("operation")):
            raise ValueError("invalid_secret_length")
        operation = header.get("operation")
        local_header = json.dumps(header, separators=(",", ":")).encode()
        if len(local_header) > MAX_HEADER:
            raise ValueError("invalid_header_length")
        secret = exact(remote, size)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as local:
            local.settimeout(10)
            local.connect(controller)
            uid = struct.unpack("3i", local.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
            if uid != 0:
                raise ValueError("untrusted_controller")
            local.sendall(struct.pack("!I", len(local_header)))
            local.sendall(local_header)
            local.sendall(secret)
            secret[:] = bytes(len(secret))
            timeout = 1800 if operation == "session-storage" else 210 if operation in ("egress", "proxy-profiles", "start-agent", "open-child-documents", "backup-export-begin", "backup-import-finish", "family-password-change", "family-password-recover") else 120
            local.settimeout(timeout)
            remote.settimeout(timeout)
            if operation in ("agent-attach", "file-attach", "live-media-reserve", "share-attach", "share-import-attach", "share-export-lease", "backup-attach"):
                guest, rejection = descriptor(local)
                if guest is None:
                    response(remote, rejection)
                    return
                with guest:
                    response(remote, json.dumps({"ok": True, "output": exact(local, 32).decode("ascii"), "error": None}).encode())
                    attached = True
                    bridge(remote, guest, local)
                return
            local.shutdown(socket.SHUT_WR)
            response(remote, controller_response(local))
    except (OSError, EOFError, ValueError, TypeError, struct.error):
        # No payloads, provider errors, argv or decrypted paths reach logs.
        # Once attached, framing belongs to the agent protocol exclusively.
        if not attached and authenticated:
            try:
                error_response(remote, "remote_control_failed")
            except OSError:
                pass
    finally:
        secret[:] = bytes(len(secret))
        remote.close()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    active = threading.BoundedSemaphore(MAX_CLIENTS)
    token = runtime_token()
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
        listener.bind((socket.VMADDR_CID_ANY, PORT))
        listener.listen(MAX_CLIENTS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CLIENTS) as pool:
            while True:
                remote, address = listener.accept()
                # CID2 identifies the hypervisor host, not its OS user. QEMU
                # and HCS additionally prove the private token before any frame.
                if address[0] != socket.VMADDR_CID_HOST or not active.acquire(blocking=False):
                    remote.close()
                    continue
                future = pool.submit(serve_client, remote, token)
                future.add_done_callback(lambda _: active.release())


if __name__ == "__main__":
    main()
