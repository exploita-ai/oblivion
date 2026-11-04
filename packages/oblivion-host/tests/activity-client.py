#!/usr/bin/env python3
"""Exercise the native activity command over a real private Unix channel.

Uses a temporary HOME, no credentials, no VM and no production controller.
Run from packages/oblivion-host: python3 tests/activity-client.py
"""
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading

package = Path(__file__).resolve().parents[1]
built = subprocess.run(["cargo", "build", "--bin", "oblivion", "--message-format=json"], cwd=package, capture_output=True, text=True, check=True)
binary = next(json.loads(line)["executable"] for line in built.stdout.splitlines()
              if json.loads(line).get("reason") == "compiler-artifact"
              and json.loads(line)["target"]["name"] == "oblivion" and json.loads(line).get("executable"))
root = Path(tempfile.mkdtemp(prefix="oblivion-activity-client-", dir="/tmp"))
listener = socket.socket(socket.AF_UNIX)
listener.bind(str(root / "control"))
os.chmod(root / "control", 0o600)
listener.listen()
listener.settimeout(5)
observed = []


def exact(peer, length):
    output = bytearray()
    while len(output) < length:
        chunk = peer.recv(length - len(output))
        if not chunk:
            raise EOFError()
        output.extend(chunk)
    return output


def controller():
    peer, _ = listener.accept()
    with peer:
        size = struct.unpack(">I", exact(peer, 4))[0]
        header = json.loads(exact(peer, size))
        observed.append((header, json.loads(exact(peer, header["secret_len"]))))
        reply = json.dumps({"ok": True, "output": "", "error": None}).encode()
        peer.sendall(struct.pack(">I", len(reply)) + reply)


worker = threading.Thread(target=controller, daemon=True)
worker.start()
env = {**os.environ, "HOME": str(root), "XDG_CONFIG_HOME": str(root), "OBLIVION_CONTROL_SOCKET": str(root / "control")}
payload = {"host": "a" * 32, "safe": {"slot": 2, "safe_id": "b" * 32, "nonce": "c" * 32}}
try:
    result = subprocess.run([binary, "activity"], input=json.dumps(payload).encode(), env=env, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    worker.join(timeout=2)
    assert len(observed) == 1
    header, body = observed[0]
    assert header["operation"] == "activity" and header["version"] == 1 and header["slot"] == 2
    assert header["session"] is None and header["expected_session"] is None
    assert body == payload and result.stdout == b"" and result.stderr == b""
    malformed = subprocess.run([binary, "activity"], input=b"x" * 1025, env=env, capture_output=True, timeout=5)
    assert malformed.returncode != 0 and b"Activity report is too large" in malformed.stderr
    unknown = subprocess.run([binary, "activity"], input=json.dumps({**payload, "text": "private keystrokes"}).encode(), env=env, capture_output=True, timeout=5)
    assert unknown.returncode != 0 and b"private keystrokes" not in unknown.stderr
    assert len(observed) == 1
    print("Native activity: scoped identity-only RPC / no runtime startup / strict bounded input: PASS")
finally:
    listener.close()
    shutil.rmtree(root)
