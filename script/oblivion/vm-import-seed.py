#!/usr/bin/env python3
"""Lab only: interrupt the real receiver before END, inside its session vault."""
import hashlib
import json
import os
import socket
import struct
import subprocess
import time
from pathlib import Path

marker = Path("/vault/state/import-recovery-seeded")
if marker.exists():
    raise SystemExit(0)
identifier = "0" * 32
payload = (b"OBLIVION_IMPORT_PARTIAL_CANARY_c26a" * 4096)[:128 * 1024]
manifest = json.dumps([{"kind": "file", "path": "unfinished.txt", "size": len(payload),
    "sha256": hashlib.sha256(payload).hexdigest()}], separators=(",", ":")).encode()
request = json.dumps({"approval": {"id": identifier,
    "manifest_sha256": hashlib.sha256(manifest).hexdigest()},
    "limits": {"entries": 64, "bytes": 1024 * 1024}}).encode()
stream, peer = socket.socketpair()
stream.settimeout(10)


def descriptor():
    os.dup2(peer.fileno(), 3)
    os.set_inheritable(3, True)


receiver = subprocess.Popen(["/usr/bin/oblivion-copy", "import", "/vault/.oblivion-inbox",
    "/vault/imports", "30000"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL, user=1001, group=1000, extra_groups=[], env={},
    close_fds=False, preexec_fn=descriptor)
peer.close()
try:
    stream.sendall(struct.pack(">I", len(request)) + request + b"OBLVCP01"
        + struct.pack(">I", len(manifest)) + manifest)
    ready = b""
    while len(ready) < 8:
        chunk = stream.recv(8 - len(ready))
        assert chunk
        ready += chunk
    assert ready == b"receive\n"
    stream.sendall(payload[:64 * 1024])
    partial = Path("/vault/.oblivion-inbox") / identifier / "pending/unfinished.txt"
    deadline = time.monotonic() + 10
    while not partial.exists() or partial.stat().st_size != 64 * 1024:
        assert receiver.poll() is None and time.monotonic() < deadline
        time.sleep(0.01)
    receiver.kill()
    receiver.wait(timeout=5)
    # Establish a persistent crash fixture; this is not a power-loss test.
    os.sync()
    marker.write_bytes(b"synthetic killed receiver")
finally:
    stream.close()
    if receiver.poll() is None:
        receiver.kill()
        receiver.wait(timeout=5)
