#!/usr/bin/env python3
"""Real session A-to-B network grants, token handoff and revocation."""
import hashlib
import base64
import json
import os
import shutil
import select
import signal
import socket
import struct
import re
import subprocess
import time
from pathlib import Path

CONFIG = "/run/oblivion-gateway-host-test.json"
GENERAL = b"synthetic-general-password"
PASSWORD = b"synthetic-session-password-a"
KEY = b"OBLIVION_API_KEY_CANARY_5c91"
NEXT = b"OBLIVION_API_NEXT_CANARY_86ab"
RAM_KEY = b"OBLIVION_API_RAM_CANARY_a13e"
OWNER = "oblivion-gateway-host.service"
VM = "oblivion-gateway-vm.service"
STREAM = Path("/run/oblivion-stream-lab").exists()
SOCKS = Path("/run/oblivion-stream-socks").exists()
PROXY_USER = b"OBLIVION_PROXY_USER_CANARY_31d2"
PROXY_PASSWORD = b"OBLIVION_PROXY_PASSWORD_CANARY_72a4"
PROXY = {"mode": "socks5", "endpoint": "10.0.2.2:9050", "authentication": {
    "username": PROXY_USER.decode(), "password": PROXY_PASSWORD.decode()}}


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=120, **kwargs)
    assert result.returncode == 0, (args, result.stderr)
    return result.stdout.decode().strip()


def command(operation, *arguments, secret=b"", success=True):
    result = subprocess.run(["/usr/bin/oblivion-storage-lab", "--config", CONFIG, operation, *arguments],
        input=secret, capture_output=True, timeout=120)
    assert (result.returncode == 0) == success, (operation, result.stderr,
        run("systemctl", "show", OWNER, "--property=Result"),
        run("systemctl", "show", VM, "--property=Result"),
        run("journalctl", "--no-pager", "-n", "20", "-u", OWNER, "-u", VM))
    return result.stdout.decode().strip() if success else result.stderr.decode().strip()


def status():
    return json.loads(command("status"))


def property(unit, name):
    return run("systemctl", "show", unit, "--property=" + name, "--value")


def qmp(role, operation, arguments=None):
    path = "/run/oblivion-gateway-vm/qmp.sock" if role == "gateway" else "/run/oblivion-session/qmp.sock"
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(10)
        client.connect(path)
        with client.makefile("rwb", buffering=0) as channel:
            assert "QMP" in json.loads(channel.readline(65536))
            for identifier, request in enumerate([{"execute": "qmp_capabilities"},
                    {"execute": operation, **({"arguments": arguments} if arguments is not None else {})}]):
                channel.write(json.dumps({**request, "id": identifier}).encode() + b"\n")
                while True:
                    reply = json.loads(channel.readline(65536))
                    if "event" in reply:
                        continue
                    assert reply.get("id") == identifier and "return" in reply, reply
                    break


def check(label):
    print("PASS: " + label, flush=True)


def stopped():
    deadline = time.monotonic() + 40
    while any(property(unit, "ActiveState") not in ["inactive", "failed"] for unit in [OWNER, VM]):
        assert time.monotonic() < deadline, "gateway cleanup deadline"
        time.sleep(0.1)
    assert not Path("/run/oblivion-gateway-vm/qmp.sock").exists()


def ready():
    current = status()
    assert current["gateway_state"] == "active" and current["gateway_vm_state"] == "active", current
    pid = int(property(VM, "MainPID"))
    owner = int(property(OWNER, "MainPID"))
    data = Path(f"/proc/{pid}/status").read_text()
    owner_status = Path(f"/proc/{owner}/status").read_text()
    assert "Uid:\t0\t0\t0\t0" in owner_status
    assert "CapEff:\t0000000000000002" in owner_status and "NoNewPrivs:\t1" in owner_status
    assert "Uid:\t1101\t1101\t1101\t1101" in data and "CapEff:\t0000000000000000" in data
    assert "NoNewPrivs:\t1" in data
    assert not Path(f"/proc/{pid}/root/run/oblivion/general").exists()
    assert not Path(f"/proc/{pid}/root/dev/oblivion-session").exists()
    for process in [pid, owner]:
        for name in ["cmdline", "environ"]:
            value = Path(f"/proc/{process}/{name}").read_bytes()
            assert not any(secret in value for secret in [KEY, NEXT, RAM_KEY, PROXY_USER, PROXY_PASSWORD])
    return pid, owner


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stream_status():
    expected = json.loads(Path("/run/oblivion-gateway-image/stream.json").read_text())
    identifier = time.monotonic_ns()
    if SOCKS:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(10)
            client.connect("/run/oblivion-stream-provider.sock")
            client.sendall(json.dumps({"operation": "status", "id": identifier}).encode() + b"\n")
            with client.makefile("rb") as reader:
                value = json.loads(reader.readline(65536))
        assert value["id"] == identifier and value["fixture_sha256"] == expected["provider_sha256"]
        assert not value["errors"], value
        return value
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(10)
        client.connect("/run/oblivion-gateway-vm/console.sock")
        assert struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1] == 1101
        client.sendall(json.dumps({"operation": "status", "id": identifier}).encode() + b"\n")
        data = b""
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            chunk = client.recv(65536)
            assert chunk and len(data) + len(chunk) <= 65536
            data += chunk
            while b"\n" in data:
                line, data = data.split(b"\n", 1)
                if b"OBLIVION_STREAM " not in line:
                    continue
                value = json.loads(line.split(b"OBLIVION_STREAM ", 1)[1])
                if value["id"] != identifier:
                    continue
                assert value["fixture_sha256"] == expected["provider_sha256"]
                assert value["api_sha256"] == expected["api_sha256"]
                assert not value["errors"], value
                return value
    raise AssertionError("provider observation deadline")


def stream_closed(identifier):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        value = stream_status()
        if identifier in value["closed"] and not value["active"]:
            return
        time.sleep(0.05)
    raise AssertionError("upstream TLS stream survived revocation")


print("OBLIVION_SESSION_NETWORK_FIXTURE_SHA256 " + digest(__file__), flush=True)
os.umask(0o077)
bundle = Path("/run/oblivion-lab-bundle")
manifest = (bundle / "SHA256SUMS").read_text()
for line in manifest.splitlines():
    expected, name = line.split()
    assert digest(bundle / name) == expected
    if name in ["oblivion-storage", "oblivion-storage-lab", "oblivion-control", "oblivion-manager"]:
        assert digest(Path("/usr/bin") / name) == expected
print("OBLIVION_HOST_BUNDLE_SHA256 " + hashlib.sha256(manifest.encode()).hexdigest(), flush=True)
image = Path("/run/oblivion-gateway-image")
for role, serial in [("gateway", "oblivion-gw-image"), ("session", "oblivion-ss-image")]:
    directory = Path("/run/oblivion-" + role + "-image")
    metadata = json.loads((directory / "manifest.json").read_text())
    shutil.copyfile("/dev/disk/by-id/virtio-" + serial, directory / (role + ".squashfs"))
    for name, expected in metadata.items():
        assert (directory / name).stat().st_size == expected["bytes"] and digest(directory / name) == expected["sha256"]
        (directory / name).chmod(0o644)
    run("mount", "-o", "remount,ro", str(directory))
    print("OBLIVION_" + role.upper() + "_IMAGE_SHA256 " + metadata[role + ".squashfs"]["sha256"], flush=True)

# The installed host image predates the new runtime mount target. Copy only its
# public QEMU binaries/libraries into RAM; neither profile nor vault is copied.
root = Path("/run/oblivion-gateway-qemu-root")
root.mkdir(mode=0o755)
run("mount", "-t", "tmpfs", "-o", "mode=0755,nodev,nosuid,size=512m", "tmpfs", str(root))
shutil.copytree("/usr/lib/oblivion/vm/qemu-root", root, symlinks=True, dirs_exist_ok=True)
(root / "run/oblivion-gateway-vm").mkdir(mode=0o755, exist_ok=True)
root.chmod(0o755)
run("mount", "-o", "remount,ro", str(root))
# Older retained host images need the public account in laboratory RAM. New
# images already contain it: validate that identity instead of duplicating it.
for name, entry in {
    "passwd": "oblivion-gateway-vm:x:1101:1101::/nonexistent:/usr/sbin/nologin\n",
    "group": "oblivion-gateway-vm:x:1101:\n",
}.items():
    source = Path("/etc") / name
    content = source.read_text()
    existing = [line.split(":") for line in content.splitlines() if line.split(":")[0] == "oblivion-gateway-vm" or line.split(":")[2] == "1101"]
    if existing:
        assert len(existing) == 1 and existing[0][0] == "oblivion-gateway-vm" and existing[0][2] == "1101"
        if name == "passwd":
            assert existing[0][3] == "1101" and existing[0][-1] == "/usr/sbin/nologin"
        continue
    target = Path("/run") / ("oblivion-lab-" + name)
    target.write_text(content + entry)
    target.chmod(0o644)
    run("mount", "--bind", str(target), str(source))
    run("mount", "-o", "remount,bind,ro", str(source))
run("mkfs.ext4", "-q", "-m", "0", "/dev/vdb")
run("mount", "/dev/vdb", "/data")
Path(CONFIG).write_text(json.dumps({"general_image": "/data/general.luks", "general_mib": 768,
    "session_mib": 128, "pbkdf_memory_kib": 65536, "manager_uid": 1000, "gateway_network": SOCKS,
    "vm": {"root": str(root), "kernel": "/run/oblivion-session-image/kernel",
        "initrd": "/run/oblivion-session-image/initrd", "filesystem": "/run/oblivion-session-image/session.squashfs",
        "memory_mib": 1536, "cpus": 2, "accelerator": "tcg"},
    "gateway": {"root": str(root), "kernel": str(image / "kernel"), "initrd": str(image / "initrd"),
        "filesystem": str(image / "gateway.squashfs"), "memory_mib": 1024, "cpus": 2, "accelerator": "tcg"}}))
unit = (bundle / OWNER).read_text().replace(
    "/usr/bin/oblivion-storage --config /etc/oblivion/controller.json",
    "/usr/bin/oblivion-storage-lab --config " + CONFIG)
unit = unit.replace("StandardError=null", "StandardError=journal")
Path("/run/systemd/system/" + OWNER).write_text(unit)
run("systemctl", "daemon-reload")
if SOCKS:
    # The outer VM has no NIC. QEMU's 10.0.2.2 host alias reaches only this
    # synthetic loopback listener; neither Tor nor a real provider is contacted.
    assert digest("/usr/lib/oblivion-stream-fixture/provider.py") == json.loads((image / "stream.json").read_text())["provider_sha256"]
    provider = subprocess.Popen(["python3", "/usr/lib/oblivion-stream-fixture/provider.py", "--external"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 10
    while not Path("/run/oblivion-stream-provider.sock").exists():
        assert provider.poll() is None and time.monotonic() < deadline, "external provider startup"
        time.sleep(0.05)
    assert stream_status()["active"] == []
assert status()["api_key_present"] is None
command("init-general", secret=GENERAL)
command("unlock", secret=GENERAL)
assert status()["api_key_present"] is False
stopped()
check("general unlock without an API key leaves gateway services and VM stopped")

if SOCKS:
    command("egress", secret=json.dumps({"action": "save", "transport": PROXY}).encode())
    assert status()["egress"] == {"saved": {"mode": "socks5", "endpoint": "10.0.2.2:9050", "authenticated": True},
        "selected": {"mode": "socks5", "endpoint": "10.0.2.2:9050", "authenticated": True}, "temporary": False}
    # Invalid Tor state must be ignored, not imported or rewritten in SOCKS mode.
    Path("/run/oblivion/general/profile/tor-state").write_bytes(b"unused-tor-state-fixture")
    check("encrypted external SOCKS profile is selected before the key starts the gateway")

command("set-api-key", secret=KEY)
ready()
a = command("create", secret=PASSWORD)
b = command("create", secret=b"synthetic-session-password-b")
if SOCKS:
    previous_gateway, _ = ready()
    policy_command = json.dumps({"action": "put", "rule": {
        "destination": "denied.example.com", "port": 443, "action": "deny", "session": a}, "save": True}).encode()
    command("network-policy", secret=policy_command)
    for port in [80, 443]:
        command("network-policy", secret=json.dumps({"action": "put", "rule": {
            "destination": "api.abliteration.ai", "port": port, "action": "allow", "session": a}, "save": True}).encode())
    policy_file = Path("/run/oblivion/general/profile/network-policy.json")
    assert json.loads(policy_file.read_text())["rules"][0]["session"] == a
    assert ready()[0] == previous_gateway
    check("a scoped web policy is saved in the encrypted profile without restarting an idle gateway")
if STREAM:
    command("api-keys", secret=json.dumps({"action": "add", "name": "Seconda", "key": NEXT.decode()}).encode())
    initial_key, alternate_key = [entry["id"] for entry in status()["api_keys"]["entries"]]
    assert status()["api_keys"]["selected"] == initial_key
    previous_gateway, _ = ready()
    command("api-keys", secret=json.dumps({"action": "select", "id": initial_key}).encode())
    assert ready()[0] == previous_gateway
    check("reselecting the current key records the RAM choice without restarting its gateway or Tor bootstrap")



def console():
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(180)
    client.connect("/run/oblivion-session/console.sock")
    data = receive(client, b"OBLIVION_SESSION_READY")
    expected = Path("/run/oblivion-session-image/opencode.sha256").read_text().split()[0]
    assert ("OBLIVION_SESSION_CLIENT_SHA256 " + expected).encode() in data
    return client


def receive(client, marker):
    data = b""
    deadline = time.monotonic() + 185
    while marker not in data:
        assert time.monotonic() < deadline, "console deadline"
        try:
            chunk = client.recv(65536)
        except OSError as error:
            diagnostic = re.sub(rb"[0-9a-f]{64}", b"<local-token>", data).replace(KEY, b"<provider-key>").replace(NEXT, b"<provider-key>")
            raise AssertionError(diagnostic[-4000:]) from error
        assert chunk, "console closed"
        data += chunk
        if re.search(rb"OBLIVION_WEBTOOLS_FAILED [^\r\n]*\r?\n", data):
            diagnostic = re.sub(rb"[0-9a-f]{64}", b"<local-token>", data).replace(KEY, b"<provider-key>").replace(NEXT, b"<provider-key>")
            raise AssertionError(diagnostic[-10000:])
    assert KEY not in data and NEXT not in data
    return data



def gateway_status():
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(12)
        channel.connect("/run/oblivion/gateway-control.sock")
        request = b'{"operation":"check"}'
        channel.sendall(struct.pack("!I", len(request)) + request)
        def receive_exact(size):
            data = b""
            while len(data) < size:
                chunk = channel.recv(size - len(data))
                assert chunk
                data += chunk
            return data
        size = struct.unpack("!I", receive_exact(4))[0]
        assert size < 1024
        return json.loads(receive_exact(size))


def watched_pids(owner):
    result = []
    for path in Path(f"/proc/{owner}/fd").iterdir():
        try:
            target = os.readlink(path)
        except FileNotFoundError:
            continue
        if target != "anon_inode:[pidfd]":
            continue
        try:
            info = Path(f"/proc/{owner}/fdinfo/{path.name}").read_text()
        except FileNotFoundError:
            continue
        fields = dict(line.split(":", 1) for line in info.splitlines())
        assert int(fields["flags"], 8) & os.O_CLOEXEC
        result.append(int(fields["Pid"]))
    return result


def await_revocation(owner):
    deadline = time.monotonic() + 40
    while gateway_status()["active"] or watched_pids(owner):
        assert time.monotonic() < deadline, "automatic grant revocation deadline"
        time.sleep(0.1)
    assert int(property(OWNER, "MainPID")) == owner
    assert status()["session_open"] and status()["general_open"]
    assert property("oblivion-session.service", "ActiveState") in ["inactive", "failed"]


def probe(client):
    client.sendall(b"probe\n")
    data = receive(client, b"OBLIVION_SESSION_PROBED")
    token = re.search(rb"TOKEN ([0-9a-f]{64})", data).group(1)
    # Actual token is never printed in the outer log or stored on the host.
    for process in [int(property(VM, "MainPID")), int(property(OWNER, "MainPID")),
                    int(property("oblivion-session.service", "MainPID"))]:
        for name in ["cmdline", "environ"]:
            assert token not in Path(f"/proc/{process}/{name}").read_bytes()
    return token


if SOCKS:
    qmp("gateway", "object-add", {"qom-type": "filter-dump", "id": "webtools-capture",
        "netdev": "outside", "file": "/run/oblivion-gateway-vm/webtools-outside.pcap"})
command("enter", a, secret=PASSWORD)
chat = int(property("oblivion-session.service", "MainPID"))
assert property("oblivion-session.service", "PrivateNetwork") == "yes"
assert not Path(f"/proc/{chat}/root/run/oblivion-gateway-vm/control.sock").exists()
assert not Path(f"/proc/{chat}/root/run/oblivion/gateway-control.sock").exists()
client = console()
first = probe(client)
check("A receives a RAM token privately; real broker authenticates it, rejects bad tokens and reports the synthetic provider's offline probe")
if SOCKS:
    client.sendall(b"tools-denied\n")
    receive(client, b"OBLIVION_TOOLS_POLICY_ENFORCED")
    assert command("network-policy", secret=policy_command, success=False) == "session_must_be_closed"
    check("the host grant activates the actual tools listener; invalid tokens, denied/unknown targets and private addresses fail closed, and policy changes are blocked while open")
client.sendall(b"adapter\n")
receive(client, b"OBLIVION_ADAPTER_AUTHENTICATED")
check("compiled OpenCode uses the production launcher and local token; the broker accepts its payload and returns the disabled-provider error")
if SOCKS:
    client.sendall(b"webtools\n")
    try:
        receive(client, b"OBLIVION_COMPILED_WEBTOOLS_VERIFIED")
    except AssertionError:
        # Counters/fixture locations are synthetic diagnostics, not user logs.
        print("OBLIVION_WEBTOOLS_FIXTURE " + json.dumps(stream_status()), flush=True)
        raise
    assert stream_status()["web"] == {"http": 1, "https": 1, "redirect": 1, "shell": 1, "completed": 1}
    check("compiled OpenCode webfetch and a shell client use the local proxy for HTTP and verified HTTPS; redirected, unknown and wrong-port targets fail without external contact or a direct fallback")

if STREAM:
    assert stream_status()["active"] == []
    client.sendall(b"stream\n")
    receive(client, b"OBLIVION_STREAM_STARTED")
    observed = stream_status()
    assert observed["active"] == [1] and observed["credentials"] == {"1": "initial"}
    check("compiled adapter receives SSE through the real session VM, private grant, supervisor and gateway broker")
    if SOCKS:
        previous_gateway, _ = ready()
        assert command("egress", secret=b'{"action":"select","transport":{"mode":"tor"}}', success=False) == "session_must_be_closed"
        assert ready()[0] == previous_gateway and stream_status()["active"] == [1]
        check("active streaming blocks a transport change without interrupting or replacing its gateway")

# Keep the old guest alive while requesting close: the VM interlock rejects
# closing its disk, but revocation must already have removed its API listener.
assert command("close", success=False) == "operation_failed"
if STREAM:
    stream_closed(1)
    assert status()["session_open"] and Path(f"/proc/{chat}").exists()
    client.sendall(b"stream-ended\n")
    receive(client, b"OBLIVION_STREAM_FAILED")
    check("controller revocation closes the provider TLS stream and the adapter reports failure while QEMU and its LUKS mapping are still open")
client.sendall(b"revoked\n")
receive(client, b"OBLIVION_SESSION_REVOKED")
command("force-leave")
client.close()
assert not status()["session_open"] and not Path(f"/proc/{chat}").exists()
check("revocation precedes vault closure and removes broker access even while the old guest remains running")
if SOCKS:
    qmp("gateway", "object-del", {"id": "webtools-capture"})
    packets = Path("/run/oblivion-gateway-vm/webtools-outside.pcap").read_bytes()
    assert 24 < len(packets) <= 4 * 1024 * 1024
    assert not any(secret in packets for secret in [KEY, NEXT, first])
    # Only the disposable laboratory exports synthetic traffic, after the
    # capture is closed. Production launchers never enable this QMP filter.
    print("OBLIVION_WEBTOOLS_PCAP " + base64.b64encode(packets).decode(), flush=True)
    Path("/run/oblivion-gateway-vm/webtools-outside.pcap").unlink()
    check("the laboratory captures A's compiled-client traffic outside the gateway, without a cleartext provider key or local capability")

if STREAM:
    previous_gateway, _ = ready()
    command("api-keys", secret=json.dumps({"action": "select", "id": alternate_key}).encode())
    assert ready()[0] != previous_gateway and not Path(f"/proc/{previous_gateway}").exists()
command("enter", b, secret=b"synthetic-session-password-b")
client = console()
second = probe(client)
assert first != second
client.sendall(b"old " + first + b"\n")
receive(client, b"OBLIVION_OLD_TOKEN_DENIED")
if SOCKS:
    before_web = stream_status()["web"]
    client.sendall(b"tools-scoped-denied\n")
    receive(client, b"OBLIVION_OTHER_POLICY_DENIED")
    assert stream_status()["web"] == before_web
    check("B cannot use A's allowed web destinations and the external fixture receives no request")
_, owner = ready()
chat = int(property("oblivion-session.service", "MainPID"))
assert watched_pids(owner) == [chat] and gateway_status()["active"]
if STREAM:
    client.sendall(b"stream\n")
    receive(client, b"OBLIVION_STREAM_STARTED")
    observed = stream_status()
    alternate_stream = 2 if SOCKS else 1
    assert observed["active"] == [alternate_stream] and observed["credentials"][str(alternate_stream)] == "alternate"
    check("explicit key selection replaces the gateway VM; the real compiled adapter sends the alternate key only through the broker")
os.kill(chat, signal.SIGKILL)
client.close()
await_revocation(owner)
if STREAM:
    stream_closed(alternate_stream)
    assert status()["session_open"]
    check("session QEMU death revokes its active upstream stream through the pidfd observer before explicit volume closure")
assert command("enter", a, secret=PASSWORD, success=False) == "session_already_open"
command("close")
assert not status()["session_open"]
check("B rejects A's token; SIGKILL of its QEMU automatically revokes the broker and closes the matching pidfd while the volume remains interlocked until explicit close")
if STREAM:
    command("api-keys", secret=json.dumps({"action": "select", "id": initial_key}).encode())


command("enter", a, secret=PASSWORD)
client = console()
third = probe(client)
assert third not in [first, second]
client.sendall(b"old " + second + b"\n")
receive(client, b"OBLIVION_OLD_TOKEN_DENIED")
# A dead owner destroys the gateway and all grants; the chat has no fallback.
_, owner = ready()
os.kill(owner, signal.SIGKILL)
stopped()
client.sendall(b"revoked\n")
receive(client, b"OBLIVION_SESSION_REVOKED")
command("force-leave")
client.close()
command("lock")
assert not status()["general_open"]
check("reopened A gets a third token; owner death destroys its gateway access and explicit closure removes both LUKS mappings")

command("unlock", secret=GENERAL)
if SOCKS:
    assert status()["egress"]["selected"]["mode"] == "socks5" and not status()["egress"]["temporary"]
    assert Path("/run/oblivion/general/profile/tor-state").read_bytes() == b"unused-tor-state-fixture"
    check("unlock restores the persisted SOCKS route and credentials without reading or changing Tor state")
command("enter", b, secret=b"synthetic-session-password-b")
client = console()
fourth = probe(client)
assert fourth not in [first, second, third]
_, owner = ready()
os.kill(owner, signal.SIGSTOP)
command("force-leave")
client.close()
stopped()
assert not status()["session_open"]
command("lock")
check("a frozen host owner cannot acknowledge revoke; closure instead destroys the gateway before releasing the session volume")

command("unlock", secret=GENERAL)
command("enter", a, secret=PASSWORD)
client = console()
fifth = probe(client)
assert fifth not in [first, second, third, fourth]
_, owner = ready()
chat = int(property("oblivion-session.service", "MainPID"))
assert watched_pids(owner) == [chat]
# Exit QEMU normally without invoking the storage close/revoke operation.
qmp("session", "quit")
client.close()
await_revocation(owner)
command("close")
command("lock")
check("normal QEMU exit also revokes automatically; repeated opens bind fresh process handles and global lock closes both volumes")

tokens = [first, second, third, fourth, fifth]
if SOCKS:
    command("unlock", secret=GENERAL)
    previous_gateway, _ = ready()
    saved_transport = Path("/run/oblivion/general/profile/transport.json").read_bytes()
    tor_state = Path("/run/oblivion/general/profile/tor-state")
    assert tor_state.read_bytes() == b"unused-tor-state-fixture"
    # Replace the deliberately invalid seed with the selective guard fixture
    # already used by the Tor-state lab. A stored guard is not a bootstrap.
    guard_id = "rsa_id=0123456789ABCDEF0123456789ABCDEF01234567"
    tor_state.write_text("Guard in=default " + guard_id + " nickname=TestGuard sampled_on=2026-10-24T00:00:00 sampled_idx=0 sampled_by=0.4.9.14 listed=1 confirmed_on=2026-10-24T00:01:00 confirmed_idx=0\nTorVersion Tor 0.4.9.14\nLastWritten 2026-10-24 00:02:00\n")
    command("egress", secret=b'{"action":"select","transport":{"mode":"tor"}}')
    tor_gateway, _ = ready()
    assert tor_gateway != previous_gateway and not Path(f"/proc/{previous_gateway}").exists()
    assert status()["egress"]["selected"] == {"mode": "tor"} and status()["egress"]["temporary"]
    assert Path("/run/oblivion/general/profile/transport.json").read_bytes() == saved_transport
    assert gateway_status() == {"ok": False, "configured": True, "active": False}
    assert command("enter", a, secret=PASSWORD, success=False) == "gateway_not_ready"
    assert not status()["session_open"] and property("oblivion-session.service", "ActiveState") in ["inactive", "failed"]
    assert not Path("/dev/mapper/oblivion-session").exists() and not Path("/run/oblivion-session/console.sock").exists()
    assert stream_status()["active"] == [] and stream_status()["closed"] == [1, 2]
    assert tor_state.stat().st_uid == 0 and tor_state.stat().st_mode & 0o777 == 0o600
    assert "TorVersion Tor 0.4.9.14\n" in tor_state.read_text()
    assert guard_id in tor_state.read_text()
    assert all(line.startswith(("Guard ", "TorVersion ", "LastWritten ")) for line in tor_state.read_text().splitlines())
    check("SOCKS-to-Tor imports its saved guard and replaces the gateway; absent bootstrap still rejects opening before any session mapping or VM, with no SOCKS fallback")

    command("egress", secret=b'{"action":"saved"}')
    restored_gateway, _ = ready()
    assert restored_gateway != tor_gateway and not Path(f"/proc/{tor_gateway}").exists()
    assert status()["egress"]["selected"]["mode"] == "socks5" and not status()["egress"]["temporary"]
    assert Path("/run/oblivion/general/profile/transport.json").read_bytes() == saved_transport
    saved_tor_state = tor_state.read_bytes()
    assert guard_id.encode() in saved_tor_state
    assert gateway_status() == {"ok": True, "configured": True, "active": False}
    check("restoring the saved SOCKS profile closes the Tor gateway and completes its selective state checkpoint before replacement")

    command("enter", a, secret=PASSWORD)
    client = console()
    transition_token = probe(client)
    assert transition_token not in tokens
    tokens.append(transition_token)
    client.sendall(b"old " + fifth + b"\n")
    receive(client, b"OBLIVION_OLD_TOKEN_DENIED")
    client.sendall(b"stream\n")
    receive(client, b"OBLIVION_STREAM_STARTED")
    observed = stream_status()
    assert observed["active"] == [3] and observed["credentials"]["3"] == "initial"
    # A torn transfer receipt is a real cleanup error, without stubbing either
    # the transfer controller or the active provider connection.
    transfer_state = Path("/run/oblivion/transfer.json")
    assert not transfer_state.exists()
    transfer_state.write_text("{")
    transfer_state.chmod(0o600)
    assert command("leave", success=False) == "invalid_transfer_state"
    stream_closed(3)
    assert status()["session_open"] and status()["general_open"]
    assert property("oblivion-session.service", "ActiveState") == "active"
    transfer_state.unlink()
    check("failed transfer cleanup still revokes the active provider stream before returning an error; session and general volumes remain interlocked")
    command("force-leave")
    client.close()
    stream_closed(3)
    assert tor_state.read_bytes() == saved_tor_state and not status()["session_open"]
    command("lock")
    check("restored SOCKS serves a fresh-token client stream, rejects the prior token and revokes without mutating the saved Tor checkpoint")

command("unlock", secret=GENERAL)
ready()
# A privileged client that drips a frame must not hold the gateway owner
# indefinitely. The production five-second admission budget expires and the
# owner destroys its VM, rather than keeping credentials behind a stuck channel.
with socket.socket(socket.AF_UNIX) as control:
    control.settimeout(5)
    control.connect("/run/oblivion/gateway-control.sock")
    control.sendall(struct.pack(">I", 1024) + b"{")
    deadline = time.monotonic() + 15
    sent = 1
    while time.monotonic() < deadline:
        if select.select([control], [], [], 1)[0]:
            assert control.recv(1) == b""
            break
        control.sendall(b" ")
        sent += 1
    else:
        raise AssertionError("gateway frame deadline renewed by partial input")
    assert sent > 1
stopped()
assert status()["general_open"] and not status()["session_open"]
check("fragmented private requests expire despite continued progress; the owner destroys its gateway VM and leaves storage state explicit")
command("lock")
assert not status()["general_open"]

if SOCKS:
    assert stream_status()["active"] == []
    command("unlock", secret=GENERAL)
    for identifier in [initial_key, alternate_key]:
        command("api-keys", secret=json.dumps({"action": "remove", "id": identifier}).encode())
    assert status()["api_keys"]["entries"] == [] and not status()["api_key_present"]
    command("lock")
    encrypted_before = digest("/data/general.luks")
    command("unlock-ephemeral", secret=GENERAL)
    stopped()
    assert command("enter-ephemeral", success=False) == "gateway_unavailable"
    assert not Path("/run/oblivion/ephemeral.luks").exists()
    saved_keys = Path("/run/oblivion/general/profile/abliteration.keys.json").read_bytes()
    temporary_command = json.dumps({"action": "temporary", "name": "Solo RAM", "key": RAM_KEY.decode()}).encode()
    command("api-keys", secret=temporary_command)
    ready()
    assert status()["api_keys"]["entries"][0]["temporary"]
    assert Path("/run/oblivion/general/profile/abliteration.keys.json").read_bytes() == saved_keys
    check("an empty saved key archive leaves the ephemeral gateway stopped; a new RAM-only key starts it without writing the read-only profile")
    assert status()["general_readonly"] and status()["sessions"] == []
    assert tor_state.read_bytes() == saved_tor_state
    assert command("enter", a, secret=PASSWORD, success=False) == "general_not_writable"
    command("enter-ephemeral")
    client = console()
    ephemeral_token = probe(client)
    assert ephemeral_token not in tokens
    tokens.append(ephemeral_token)
    before_web = stream_status()["web"]
    client.sendall(b"tools-scoped-denied\n")
    receive(client, b"OBLIVION_OTHER_POLICY_DENIED")
    assert stream_status()["web"] == before_web
    check("an ephemeral VM receives a fresh private token and cannot inherit A's session-scoped web permissions")
    client.sendall(b"stream\n")
    receive(client, b"OBLIVION_STREAM_STARTED")
    observed = stream_status()
    assert observed["active"] == [4] and observed["credentials"]["4"] == "temporary"
    assert command("api-keys", secret=temporary_command, success=False) == "session_must_be_closed"
    assert stream_status()["active"] == [4]
    command("force-leave")
    client.close()
    stream_closed(4)
    assert not status()["session_open"] and not Path("/run/oblivion/ephemeral.luks").exists()
    assert "ephemeral.luks" not in run("losetup", "--list", "--output", "BACK-FILE")
    assert digest("/data/general.luks") == encrypted_before
    assert tor_state.read_bytes() == saved_tor_state
    check("closing a streaming ephemeral session revokes its provider connection and removes its RAM disk without writing the general image or Tor state")

    assert Path("/run/oblivion/api-keys.json").exists()
    command("lock")
    assert not Path("/run/oblivion/api-keys.json").exists()
    assert not Path("/run/oblivion/api-key-selection").exists()
    command("unlock-ephemeral", secret=GENERAL)
    stopped()
    assert status()["api_keys"]["entries"] == [] and not status()["api_key_present"]
    command("api-keys", secret=json.dumps({"action": "temporary", "name": "Nuova RAM", "key": NEXT.decode()}).encode())
    ready()
    command("enter-ephemeral")
    client = console()
    next_ephemeral_token = probe(client)
    assert next_ephemeral_token not in tokens
    tokens.append(next_ephemeral_token)
    client.sendall(b"old " + ephemeral_token + b"\n")
    receive(client, b"OBLIVION_OLD_TOKEN_DENIED")
    client.sendall(b"stream\n")
    receive(client, b"OBLIVION_STREAM_STARTED")
    observed = stream_status()
    assert observed["active"] == [5] and observed["credentials"]["5"] == "alternate"
    assert not transfer_state.exists()
    transfer_state.write_text("{")
    transfer_state.chmod(0o600)
    assert command("lock", success=False) == "invalid_transfer_state"
    stopped()
    stream_closed(5)
    assert status()["session_open"] and status()["general_open"]
    assert Path("/run/oblivion/ephemeral.luks").exists()
    transfer_state.unlink()
    check("failed global lock stops the gateway and active ephemeral stream before transfer cleanup, without falsely reporting either volume closed")
    command("lock")
    client.close()
    stopped()
    stream_closed(5)
    assert not status()["session_open"] and not status()["general_open"]
    assert not Path("/run/oblivion/ephemeral.luks").exists()
    assert "ephemeral.luks" not in run("losetup", "--list", "--output", "BACK-FILE")
    assert digest("/data/general.luks") == encrypted_before
    assert not Path("/run/oblivion/api-keys.json").exists()
    assert not Path("/run/oblivion/api-keys.json.pending").exists()
    assert not Path("/run/oblivion/api-key-selection").exists()
    check("a second ephemeral VM rejects the previous token; global lock terminates its active stream, gateway and RAM volume while leaving the general image byte-identical")
    check("locking discards RAM credentials; the next read-only boot has no key until a new explicit RAM choice, which is observed by the external TLS provider")
    provider.terminate()
    provider.wait(timeout=10)
    Path("/run/oblivion-stream-provider.sock").unlink()

for path in Path("/run").rglob("*"):
    if path.is_symlink() or not path.is_file():
        continue
    with path.open("rb") as stream:
        tail = b""
        while chunk := stream.read(1024 * 1024):
            assert not any(secret in tail + chunk for secret in [KEY, NEXT, RAM_KEY, PROXY_USER, PROXY_PASSWORD, *tokens]), str(path)
            tail = chunk[-128:]
check("runtime regular files contain none of the synthetic provider keys or session tokens after closure")
run("umount", "/data")
print("OBLIVION_VM_LAB_PASS", flush=True)
