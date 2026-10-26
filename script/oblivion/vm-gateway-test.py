#!/usr/bin/python3
"""Gateway component tests in disposable, swap-free Debian; no external NIC."""
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import select
import signal
import socket
import subprocess
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BUNDLE = Path("/run/oblivion-lab-bundle")
KEY = "synthetic-provider-key-from-private-channel"
TOKEN = "c" * 64


def check(label):
    print("PASS: " + label, flush=True)


def capture(packets, finished):
    # Inspect packets in RAM; retain counters only, never HTTP bodies or tokens.
    counts = dict(packets=0, tcp=0, udp=0, ipv4=0, ipv6=0, other=0, non_loopback=0, truncated=0)
    while True:
        if not select.select([packets], [], [], 0 if finished.is_set() else 0.1)[0]:
            if finished.is_set():
                return counts
            continue
        packet, _, flags, _ = packets.recvmsg(262144)
        counts["packets"] += 1
        counts["truncated"] += bool(flags & socket.MSG_TRUNC)
        if packet[12:14] == b"\x08\x00":
            counts["ipv4"] += 1
            protocol, source, destination = packet[23], packet[26:30], packet[30:34]
        elif packet[12:14] == b"\x86\xdd":
            counts["ipv6"] += 1
            protocol, source, destination = packet[20], packet[22:38], packet[38:54]
        else:
            counts["other"] += 1
            continue
        counts["tcp"] += protocol == 6
        counts["udp"] += protocol == 17
        counts["non_loopback"] += not (ipaddress.ip_address(source).is_loopback and ipaddress.ip_address(destination).is_loopback)


def wait(pid):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        result = os.waitpid(pid, os.WNOHANG)
        if result[0]:
            return os.waitstatus_to_exitcode(result[1])
        time.sleep(0.01)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    raise AssertionError("broker did not exit")


def exact(stream, count):
    value = b""
    while len(value) < count:
        chunk = stream.recv(count - len(value))
        assert chunk
        value += chunk
    return value


def production(drop_identity, binary="oblivion-api", proxy=None):
    control, inherited = socket.socketpair()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    address = listener.getsockname()
    channel = fcntl.fcntl(inherited, fcntl.F_DUPFD_CLOEXEC, 10)
    incoming = fcntl.fcntl(listener, fcntl.F_DUPFD_CLOEXEC, 10)
    output, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.dup2(write, 1)
        os.dup2(write, 2)
        os.dup2(channel, 3)
        os.dup2(incoming, 4)
        os.closerange(5, 1024)
        if drop_identity:
            os.setgroups([])
            os.setgid(1000)
            os.setuid(1000)
        os.execve(str(BUNDLE / binary), [str(BUNDLE / binary)], {})
    for fd in (write, channel, incoming):
        os.close(fd)
    inherited.close()
    listener.close()
    control.settimeout(10)
    if not drop_identity:
        assert wait(pid) == 1
        assert os.read(output, 8192) == (binary + ": service_failed\n").encode()
        os.close(output)
        control.close()
        check(binary + ": production binary rejects execution as root")
        return
    try:
        config = {"session_token": TOKEN, "socks": "127.0.0.1:1"}
        if binary == "oblivion-api":
            config["api_key"] = KEY
        if binary == "oblivion-egress":
            config = {"transport": {"mode": "tor"}, "session_token": TOKEN}
        control.sendall((json.dumps(config) + "\n").encode())
        assert control.recv(128) == b'{"ready":true}\n'
        status = Path(f"/proc/{pid}/status").read_text()
        assert re.search(r"^Uid:\s+1000\s+1000\s+1000\s+1000$", status, re.M)
        assert re.search(r"^NoNewPrivs:\s+1$", status, re.M)
        assert re.search(r"^CapEff:\s+0000000000000000$", status, re.M)
        limits = Path(f"/proc/{pid}/limits").read_text()
        core = next(line for line in limits.splitlines() if line.startswith("Max core file size"))
        assert core.split()[-3:] == ["0", "0", "bytes"]
        assert KEY.encode() not in Path(f"/proc/{pid}/cmdline").read_bytes()
        check(binary + ": production binary accepts a root-owned control channel as UID 1000 with no capabilities, no-new-privileges and core limit zero")
        if binary == "oblivion-api":
            for token, expected in [("invalid", b"HTTP/1.1 401"), (TOKEN, b"HTTP/1.1 502")]:
                body = json.dumps({"model": "abliterated-model", "messages": [
                    {"role": "user", "content": "synthetic prompt"}], "stream": True})
                with socket.create_connection(address, timeout=10) as client:
                    client.sendall(("POST /v1/chat/completions HTTP/1.1\r\nHost: gateway\r\n"
                        f"Authorization: Bearer {token}\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n\r\n{body}").encode())
                    response = b""
                    while chunk := client.recv(65536):
                        response += chunk
                    assert response.startswith(expected)
                    assert KEY.encode() not in response
            check("production API rejects a wrong token and fails closed with SOCKS unavailable")
        elif binary == "oblivion-tools":
            for token, expected in [("invalid", b"HTTP/1.1 407"), (TOKEN, b"HTTP/1.1 502")]:
                auth = base64.b64encode(("oblivion-tools:" + token).encode()).decode()
                with socket.create_connection(address, timeout=10) as client:
                    client.sendall(("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
                        f"Proxy-Authorization: Basic {auth}\r\n\r\n").encode())
                    response = b""
                    while chunk := client.recv(65536):
                        response += chunk
                    assert response.startswith(expected)
                    assert TOKEN.encode() not in response
            check("production tools proxy rejects a wrong token and fails closed with its private connector unavailable")
        else:
            with socket.create_connection(address, timeout=10) as client:
                client.sendall(bytes([5, 1, 2]))
                assert client.recv(2) == bytes([5, 2])
                client.sendall(bytes([1, len(b"oblivion-api")]) + b"oblivion-api" + bytes([64]) + TOKEN.encode())
                assert client.recv(2) == bytes([1, 0])
                host = b"api.abliteration.ai"
                client.sendall(bytes([5, 1, 0, 3, len(host)]) + host + struct.pack("!H", 443))
                if proxy is None:
                    assert client.recv(1) == b""
                else:
                    upstream, _ = proxy.accept()
                    with upstream:
                        upstream.settimeout(10)
                        assert exact(upstream, 3) == bytes([5, 1, 2])
                        upstream.sendall(bytes([5, 2]))
                        assert exact(upstream, 1) == bytes([1])
                        assert exact(upstream, exact(upstream, 1)[0]) == b"oblivion-api"
                        assert exact(upstream, exact(upstream, 1)[0]) == TOKEN.encode()
                        upstream.sendall(bytes([1, 0]))
                        assert exact(upstream, 5) == bytes([5, 1, 0, 3, len(host)])
                        assert exact(upstream, len(host) + 2) == host + struct.pack("!H", 443)
                        # Exercise a domain-form bound address as well; it is
                        # unrelated to destination identity or local DNS.
                        upstream.sendall(bytes([5, 0, 0, 3, 3]) + b"bnd" + bytes([0, 1]))
                        assert exact(client, 10) == bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                        client.sendall(b"opaque-TLS-bytes")
                        assert exact(upstream, len(b"opaque-TLS-bytes")) == b"opaque-TLS-bytes"
                        upstream.sendall(b"reply")
                        assert exact(client, 5) == b"reply"
            check("production egress sends the grant isolation identity and remote domain to the synthetic Tor SOCKS entry" if proxy else "production egress authenticates the local grant and fails closed with Tor unavailable")
        control.close()
        assert wait(pid) == 0
        pid = None
        assert os.read(output, 8192) == b""
        with socket.socket() as client:
            assert client.connect_ex(address) != 0
        check(binary + ": production controller disconnect removes the listener and exits without stdout or stderr")
    finally:
        control.close()
        os.close(output)
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except ProcessLookupError:
                pass


try:
    assert os.getuid() == 0
    assert len(Path("/proc/swaps").read_text().splitlines()) == 1
    assert sorted(path.name for path in Path("/sys/class/net").iterdir()) == ["lo"]
    manifest = (BUNDLE / "SHA256SUMS").read_bytes()
    for line in manifest.decode().splitlines():
        digest, name = line.split()
        assert Path(name).name == name
        assert hashlib.sha256((BUNDLE / name).read_bytes()).hexdigest() == digest
    print("OBLIVION_GATEWAY_BUNDLE_SHA256 " + hashlib.sha256(manifest).hexdigest(), flush=True)
    print("OBLIVION_GATEWAY_FIXTURE_SHA256 " + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), flush=True)
    check("Debian ARM laboratory has no swap, no external network interface and verified gateway binaries")
    # This path is embedded by Cargo into the executable activation tests. The
    # symlink reaches a read-only executable RAM mount, not a shared filesystem.
    target = Path("/tmp/target/debug/oblivion-api")
    target.parent.mkdir(parents=True)
    target.symlink_to(BUNDLE / "oblivion-api-lab")
    (target.parent / "oblivion-egress").symlink_to(BUNDLE / "oblivion-egress-lab")
    (target.parent / "oblivion-tools").symlink_to(BUNDLE / "oblivion-tools-lab")
    for executable, expected in [("gateway-tests", 28), ("activation-tests", 10)]:
        result = subprocess.run(["setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
            "--no-new-privs", "--", str(BUNDLE / executable)],
            capture_output=True, text=True, timeout=120, env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"})
        assert result.returncode == 0, result.stdout + result.stderr
        passed = re.findall(r"^test (.+) \.\.\. ok$", result.stdout, re.M)
        assert len(passed) == expected, result.stdout
        for test in passed:
            check(executable + ": " + test)
    production(False)
    production(True)
    production(False, "oblivion-egress")
    production(True, "oblivion-egress")
    production(False, "oblivion-tools")
    production(True, "oblivion-tools")
    with socket.socket() as proxy:
        proxy.bind(("127.0.0.1", 9050))
        proxy.listen()
        proxy.settimeout(10)
        production(True, "oblivion-egress", proxy)
    # Only public executable bytes cross this read-only virtual block device.
    # Application state stays in guest RAM; there is no host filesystem share.
    guest = Path("/run/oblivion-adapter")
    if (guest / "manifest.json").exists():
        manifest = json.loads((guest / "manifest.json").read_text())
        binary = guest / "oblivion"
        with Path("/dev/disk/by-id/virtio-oblivion-adapter").open("rb") as source, binary.open("xb") as target:
            remaining = manifest["bytes"]
            while remaining:
                chunk = source.read(min(remaining, 1024 * 1024))
                assert chunk
                target.write(chunk)
                remaining -= len(chunk)
        binary.chmod(0o555)
        expected = manifest["sha256"]
        subprocess.run(["mount", "-o", "remount,ro", str(guest)], check=True)
    else:
        guest = Path("/run/oblivion-adapter-image")
        guest.mkdir()
        subprocess.run(["mount", "-t", "squashfs", "-o", "loop,ro,nodev,nosuid",
            "/usr/lib/oblivion/vm/guest.squashfs", str(guest)], check=True)
        binary = guest / "usr/bin/oblivion"
        expected = json.loads((guest / "usr/lib/oblivion/build-evidence.json").read_text())["binary_sha256"]
    try:
        with binary.open("rb") as file:
            actual = hashlib.file_digest(file, "sha256").hexdigest()
        assert actual == expected
        print("OBLIVION_ADAPTER_BINARY_SHA256 " + actual, flush=True)
        finished = threading.Event()
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as packets, ThreadPoolExecutor(max_workers=1) as pool:
            packets.bind(("lo", 0))
            packets.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            captured = pool.submit(capture, packets, finished)
            try:
                result = subprocess.run(["setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
                    "--no-new-privs", "--", str(BUNDLE / "gateway-tests"), "broker::tests::adapter::",
                    "--ignored", "--test-threads=1"], capture_output=True, text=True, timeout=480,
                    env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "OBLIVION_ADAPTER_BIN": str(binary)})
            finally:
                finished.set()
            counters = captured.result(timeout=10)
            counters["kernel_packets"], counters["dropped"] = struct.unpack("II", packets.getsockopt(263, 6, 8))
        print("OBLIVION_ADAPTER_CAPTURE " + json.dumps(counters, sort_keys=True), flush=True)
        assert counters["tcp"] > 0 and counters["tcp"] == counters["ipv4"] + counters["ipv6"], counters
        assert not any(counters[key] for key in ["udp", "other", "non_loopback", "truncated", "dropped"]), counters
        assert result.returncode == 0, result.stdout + result.stderr
        passed = re.findall(r"^test (.+) \.\.\. ok$", result.stdout, re.M)
        assert len(passed) == 2, result.stdout
        for test in passed:
            check("compiled adapter: " + test)
    finally:
        subprocess.run(["umount", str(guest)], check=True)
    print("OBLIVION_VM_LAB_PASS", flush=True)
except BaseException:
    print("OBLIVION_VM_LAB_FAIL", flush=True)
    raise
