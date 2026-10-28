#!/usr/bin/python3 -B
"""Real headless Cage/data-control clients and the confined SPICE adapter.

Only the daemon-side Unix peer is a fixture. This is not UTM/VirtualBox
acceptance and neither an outer-host clipboard nor user data is accessed.
"""
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import time

TEXT = "Oblivion città · clipboard\nsecond line"
SOCKET = "/run/oblivion-clipboard-broker/socket"


def exact(stream, count):
    value = b""
    while len(value) < count:
        part = stream.recv(count-len(value))
        assert part, "Clipboard peer closed"
        value += part
    return value


def message(stream):
    kind, first, second, size = struct.unpack("<IIII", exact(stream, 16))
    assert size <= 256 * 1024
    return kind, first, second, exact(stream, size)


def send(stream, kind, first=0, second=0, data=b""):
    stream.sendall(struct.pack("<IIII", kind, first, second, len(data)) + data)


def read_clipboard():
    return subprocess.check_output(["wl-paste", "--no-newline", "--type", "text/plain;charset=utf-8"],
                                   timeout=5, stderr=subprocess.DEVNULL)


def types():
    return subprocess.run(["wl-paste", "--list-types"], capture_output=True, timeout=5).stdout


def wait_types():
    deadline = time.monotonic() + 5
    while b"text/plain;charset=utf-8" not in types():
        assert time.monotonic() < deadline, "Wayland offer deadline"
        time.sleep(0.01)


def main():
    os.umask(0o077)
    assert os.getuid() == 1104
    listener = socket.socket(socket.AF_UNIX)
    listener.settimeout(5)
    listener.bind(SOCKET)
    listener.listen(1)
    agent = subprocess.Popen(["/usr/bin/oblivion-clipboard"], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    writer = None
    checks = []
    try:
        peer, _ = listener.accept()
        with peer:
            peer.settimeout(5)
            assert message(peer)[0] == 0  # Initial output geometry, no resize request.
            send(peer, 2, data=struct.pack("<I", 1))
            wait_types()
            assert not select.select([peer], [], [], 0)[0], "Clipboard was fetched without paste"
            checks.append("Host announcement offers text without fetching its contents")
            pasted = subprocess.Popen(["wl-paste", "--no-newline", "--type", "text/plain;charset=utf-8"],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            assert message(peer)[:3] == (3, 0, 1)
            send(peer, 4, second=1, data=TEXT.encode())
            assert pasted.communicate(timeout=5)[0] == TEXT.encode() and pasted.returncode == 0
            checks.append("Host-to-guest UTF-8 paste traverses the real Wayland source")
            writer = subprocess.Popen(["wl-copy", "--foreground", "--type", "text/plain;charset=utf-8"],
                                      stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            writer.stdin.write(TEXT.encode()); writer.stdin.close()
            assert message(peer) == (2, 0, 0, struct.pack("<I", 1))
            send(peer, 3, second=1)
            assert message(peer) == (4, 0, 1, TEXT.encode())
            checks.append("Guest-to-host copy returns exactly the selected UTF-8 text")
            send(peer, 3, first=1, second=1)
            # The next legitimate request forms a barrier: PRIMARY must not
            # read or return the separately owned CLIPBOARD selection.
            send(peer, 3, second=1)
            assert message(peer) == (4, 0, 1, TEXT.encode())
            checks.append("PRIMARY requests cannot obtain the text selection")
            send(peer, 3, second=2)
            assert message(peer) == (4, 0, 0, b"")
            checks.append("Image and nontext requests are refused")
        assert agent.wait(timeout=5) == 0
        checks.append("Daemon disconnect stops the adapter without stopping Cage")
        assert not list(Path(os.environ["XDG_RUNTIME_DIR"]).rglob("*.log"))
        print(json.dumps({"passed": True, "checks": checks, "scope": __doc__.strip()}, indent=2), flush=True)
    finally:
        if writer is not None:
            writer.terminate(); writer.wait(timeout=5)
        if agent.poll() is None:
            agent.terminate(); agent.wait(timeout=5)
        listener.close()
        Path(SOCKET).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
