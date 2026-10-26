#!/usr/bin/env python3
"""Actual systemd units, manager PTY, LUKS and QEMU; disposable synthetic disks only."""
import codecs
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import platform
import pwd
import select
import shutil
import signal
import socket
import struct
import subprocess
import termios
import time
from pathlib import Path

import pyte

CONFIG = "/run/oblivion-services-test.json"
GENERAL = b"synthetic-general-password"
PASSWORD = b"synthetic-session-password-a"
API_KEY = b"OBLIVION_API_KEY_CANARY_5c91"
NEXT_API_KEY = b"OBLIVION_API_NEXT_CANARY_86ab"
RAM_API_KEY = b"OBLIVION_API_RAM_CANARY_a13e"
PROXY_USER = b"OBLIVION_PROXY_USER_CANARY_31d2"
PROXY_PASSWORD = b"OBLIVION_PROXY_PASSWORD_CANARY_72a4"
PROXY = {"mode": "socks5", "endpoint": "192.168.1.20:1080",
    "authentication": {"username": PROXY_USER.decode(), "password": PROXY_PASSWORD.decode()}}
TOR_SAVE = json.dumps({"action": "save", "transport": {"mode": "tor"}}).encode()
TOR_SELECT = json.dumps({"action": "select", "transport": {"mode": "tor"}}).encode()
PROXY_SAVE = json.dumps({"action": "save", "transport": PROXY}).encode()
PROXY_SELECT = json.dumps({"action": "select", "transport": PROXY}).encode()
SAVED_TRANSPORT = b'{"action":"saved"}'
WEB_RULE = {"destination": "oblivion-policy.example.com", "port": 443, "action": "allow"}
WEB_SAVE = json.dumps({"action": "put", "rule": WEB_RULE, "save": True}).encode()
WEB_SELECT = json.dumps({"action": "put", "rule": {**WEB_RULE, "action": "deny"}, "save": False}).encode()
SAVED_POLICY = b'{"action":"saved"}'
CONTROLLER = "oblivion-controller.service"
MANAGER = "oblivion-manager.service"
RECOVER = "oblivion-recover.service"
terminal = pyte.Screen(100, 30)
stream = pyte.Stream(terminal)
decoder = codecs.getincrementaldecoder("utf-8")("replace")
output = bytearray()
AUDIT_ARCH, WRITE_SYSCALLS = {"aarch64": (0xc00000b7, [64, 68]), "x86_64": (0xc000003e, [1, 18])}[platform.machine()]


def check(label):
    print("PASS: " + label, flush=True)


def systemctl(*arguments):
    result = subprocess.run(["systemctl", *arguments], capture_output=True, timeout=180)
    assert result.returncode == 0, (arguments, result.stderr)
    return result.stdout.decode().strip()


def property(unit, name):
    return systemctl("show", unit, "--property=" + name, "--value")


def command(operation, *arguments, secret=b"", success=True):
    result = subprocess.run(["/usr/bin/oblivion-storage-lab", "--config", CONFIG, operation, *arguments],
        input=secret, capture_output=True, timeout=90)
    assert (result.returncode == 0) == success, (operation, result.stderr)
    return result.stdout.decode().strip() if success else result.stderr.decode().strip()


def status():
    return json.loads(command("status"))


def key_command(action, **fields):
    return json.dumps({"action": action, **fields}).encode()


def stored_key():
    path = Path("/run/oblivion/general/profile/abliteration.keys.json")
    if not path.exists():
        return path.with_name("abliteration.key").read_bytes()
    selected = status()["api_keys"]["selected"]
    return next((entry["key"].encode() for entry in json.loads(path.read_text())["entries"] if entry["id"] == selected), None)


def fill_profile(path):
    with path.open("xb") as file:
        space = os.statvfs(path.parent)
        allocated = space.f_bavail * space.f_frsize - 65536
        os.posix_fallocate(file.fileno(), 0, allocated)
        deadline = time.monotonic() + 5
        while True:
            assert time.monotonic() < deadline, "profile fill deadline"
            try:
                os.posix_fallocate(file.fileno(), allocated, 4096)
                allocated += 4096
            except OSError as error:
                assert error.errno == errno.ENOSPC
                return


def read_terminal():
    if select.select([master], [], [], 0.1)[0]:
        data = os.read(master, 65536)
        output.extend(data)
        stream.feed(decoder.decode(data))


def wait_screen(marker):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        read_terminal()
        if marker in "\n".join(terminal.display):
            return
    raise AssertionError(("screen timeout", marker, "\n".join(terminal.display),
        systemctl("status", MANAGER) if property(MANAGER, "ActiveState") == "active" else property(MANAGER, "Result")))


def send(value, marker):
    os.write(master, value)
    wait_screen(marker)


def wait_restart(unit, previous):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        pid = int(property(unit, "MainPID"))
        if pid > 0 and pid != previous and property(unit, "ActiveState") == "active":
            return pid
        read_terminal()
    raise AssertionError(("restart timeout", unit, property(unit, "Result")))


def locked():
    current = status()
    assert not any(current[k] for k in ["general_open", "general_mounted", "session_open", "recovery_required"]), current
    assert current["vm_state"] in ["inactive", "failed"], current


def reopen():
    send(b"\r", "Password del volume generale")
    send(GENERAL + b"\r", "Sessioni protette")
    assert not status()["session_open"]
    send(b"\r", "Password della sessione")
    send(PASSWORD + b"\r", "Conversazioni e documenti")
    wait_screen("/exit blocca")


def file_digest(path):
    with Path(path).open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def interrupt_creation(operation, secret, executable):
    # Trace real exec/syscall events so even a fast mkfs can be stopped after a
    # successful write to the actual mapped block device.
    # No fake cryptsetup, shortened production timeout or filesystem hook is used.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long

    def trace(request, pid, data=0, address=0):
        result = libc.ptrace(request, pid, address, data)
        assert result != -1, (request, pid, ctypes.get_errno())
        return result

    child = subprocess.Popen(["/usr/bin/oblivion-storage-lab", "--config", CONFIG, operation],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=lambda: trace(0, 0))  # PTRACE_TRACEME, before controller exec
    child.stdin.write(secret)
    child.stdin.close()
    live = {child.pid}
    deadline = time.monotonic() + 45
    target = None
    try:
        pid, state = os.waitpid(child.pid, 0)
        assert os.WIFSTOPPED(state)
        trace(0x4200, pid, 1 | 2 | 4 | 8 | 16 | 0x100000)  # TRACESYSGOOD, fork/vfork/clone/exec + EXITKILL
        trace(7, pid)  # CONT
        while target is None:
            assert time.monotonic() < deadline, ("exec boundary timeout", executable)
            pid, state = os.waitpid(-1, os.WNOHANG | 0x40000000)  # __WALL
            if pid == 0:
                time.sleep(0.001)
                continue
            if os.WIFEXITED(state) or os.WIFSIGNALED(state):
                live.discard(pid)
                assert pid != child.pid, "creation completed before target exec"
                continue
            event = state >> 16
            if event in [1, 2, 3]:
                forked = ctypes.c_ulong()
                trace(0x4201, pid, ctypes.byref(forked))  # GETEVENTMSG
                live.add(forked.value)
            if event == 4 and Path(f"/proc/{pid}/exe").resolve().name == executable:
                target = pid
                break
            trace(7, pid, 0 if os.WSTOPSIG(state) in [signal.SIGTRAP, signal.SIGSTOP] else os.WSTOPSIG(state))
        block = Path("/dev/mapper/oblivion-general" if operation == "init-general" else "/dev/mapper/oblivion-session").resolve()
        writing_block = False
        while True:
            trace(24, target)  # PTRACE_SYSCALL
            while True:
                assert time.monotonic() < deadline, "block write timeout"
                pid, state = os.waitpid(target, os.WNOHANG | 0x40000000)
                if pid:
                    break
                time.sleep(0.001)
            assert os.WIFSTOPPED(state) and os.WSTOPSIG(state) == signal.SIGTRAP | 0x80
            info = ctypes.create_string_buffer(88)
            assert trace(0x420e, target, info, len(info)) >= 33  # GET_SYSCALL_INFO
            assert struct.unpack_from("=I", info.raw, 4)[0] == AUDIT_ARCH
            if info.raw[0] == 1:  # syscall entry: union at byte 24, then nr and fd
                number, fd = struct.unpack_from("=QQ", info.raw, 24)
                writing_block = number in WRITE_SYSCALLS and Path(f"/proc/{target}/fd/{fd}").resolve() == block
            if info.raw[0] == 2 and writing_block and struct.unpack_from("=q", info.raw, 24)[0] > 0:
                break  # successful write/pwrite64 exit; mkfs has not completed
        print("OBLIVION_FAULT_AFTER_BLOCK_WRITE " + operation, flush=True)
        os.kill(child.pid, signal.SIGKILL)
        assert os.WIFSIGNALED(os.waitpid(child.pid, 0)[1])
        live.remove(child.pid)
        child.returncode = -signal.SIGKILL
        assert command("status", success=False) == "controller_busy"
        assert command("recover", success=False) == "controller_busy"
    finally:
        for pid in live:
            os.kill(pid, signal.SIGKILL)
        for pid in live:
            os.waitpid(pid, 0)
    command("recover")
    locked()


print("OBLIVION_SERVICES_FIXTURE_SHA256 " + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), flush=True)
os.umask(0o077)
bundle = Path("/run/oblivion-lab-bundle")
manifest = (bundle / "SHA256SUMS").read_text()
for line in manifest.splitlines():
    digest, name = line.split()
    assert hashlib.sha256((bundle / name).read_bytes()).hexdigest() == digest, name
    if name in ["oblivion-storage", "oblivion-storage-lab", "oblivion-manager", "oblivion-control"]:
        assert hashlib.sha256((Path("/usr/bin") / name).read_bytes()).hexdigest() == digest, name
print("OBLIVION_HOST_BUNDLE_SHA256 " + hashlib.sha256(manifest.encode()).hexdigest(), flush=True)
subprocess.run(["mkfs.ext4", "-q", "-m", "0", "/dev/vdb"], check=True)
subprocess.run(["mount", "/dev/vdb", "/data"], check=True)
Path(CONFIG).write_text(json.dumps({"general_image": "/data/general.luks", "general_mib": 768,
    "session_mib": 128, "pbkdf_memory_kib": 65536, "manager_uid": 1000,
    "vm": {"root": "/usr/lib/oblivion/vm/qemu-root", "kernel": "/usr/lib/oblivion/vm/kernel",
           "initrd": "/usr/lib/oblivion/vm/initrd", "filesystem": "/usr/lib/oblivion/vm/guest.squashfs",
           "memory_mib": 1536, "cpus": 2, "accelerator": "tcg"}}))
interrupt_creation("init-general", GENERAL, "mke2fs")
assert status()["general_incomplete"] and not status()["general_present"]
before = file_digest("/data/general.luks.pending")
assert command("init-general", secret=GENERAL, success=False) == "image_exists_or_unavailable"
assert file_digest("/data/general.luks.pending") == before
check("interrupted general filesystem formatting retains an unpublished file and retry never overwrites it")
with Path("/run/oblivion/storage.lock").open("rb") as operation_lock:
    fcntl.flock(operation_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert command("recover", success=False) == "controller_busy"
assert status()["recovery_required"]
assert command("unlock", secret=GENERAL, success=False) == "recovery_required"
command("lock")
locked()
check("recovery latches before a busy operation lock and only verified closure clears it")
# Older immutable lab images predate the dedicated manager account. Supply the
# same public account records as the current Dockerfile, exclusively in RAM.
if not any(user.pw_uid == 1000 for user in pwd.getpwall()):
    for name, entry in [("passwd", "oblivion-manager:x:1000:1000::/run/oblivion-manager:/usr/sbin/nologin\n"),
            ("group", "oblivion-manager:x:1000:\n")]:
        overlay = Path("/run/oblivion-lab-" + name)
        overlay.write_text((Path("/etc") / name).read_text() + entry)
        overlay.chmod(0o644)
        subprocess.run(["mount", "--bind", str(overlay), "/etc/" + name], check=True)
assert pwd.getpwuid(1000).pw_name == "oblivion-manager"
master, slave = os.openpty()
os.chown(os.ttyname(slave), 1000, 1000)
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
for file in bundle.glob("*.service"):
    shutil.copyfile(file, Path("/run/systemd/system") / file.name)
    directory = Path("/run/systemd/system") / (file.name + ".d")
    directory.mkdir()
    # Only the binary/config/console paths change. Lifecycle, dependencies and
    # manager confinement are the exact units intended for the live image.
    if file.name == MANAGER:
        override = f"TTYPath={os.ttyname(slave)}\nTTYRows=30\nTTYColumns=100\n"
    else:
        operation = "serve" if file.name == CONTROLLER else "recover"
        override = f"ExecStart=\nExecStart=/usr/bin/oblivion-storage-lab --config {CONFIG} {operation}\n"
        if file.name == CONTROLLER:
            override += f"ExecStartPre=\nExecStartPre=-/usr/bin/oblivion-storage-lab --config {CONFIG} recover\n"
            override += f"ExecStopPost=\nExecStopPost=/usr/bin/oblivion-storage-lab --config {CONFIG} recover\n"
    (directory / "lab.conf").write_text("[Service]\n" + override)
systemctl("daemon-reload")
try:
    systemctl("start", CONTROLLER)
    wait_screen("Preparazione generale interrotta")
    manager_pid = int(property(MANAGER, "MainPID"))
    process = Path(f"/proc/{manager_pid}/status").read_text()
    assert "Uid:\t1000\t1000\t1000\t1000" in process and "CapEff:\t0000000000000000" in process
    assert "NoNewPrivs:\t1" in process
    assert os.readlink(f"/proc/{manager_pid}/ns/net") != os.readlink("/proc/1/ns/net")
    assert property(CONTROLLER, "Type") == "notify"
    locked()
    check("systemd waits for controller readiness and runs the confined manager as UID 1000")
    # Real UID 1000 clients drip incomplete frames/secrets into the production
    # controller. Progress every second must not renew its ten-second deadline.
    probe = subprocess.run(["python3", "-c", r'''
import json, select, socket, struct, time
for secret in [False, True]:
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(5)
        client.connect("/run/oblivion-control.sock")
        header = json.dumps({"operation": "unlock", "session": None, "secret_len": 1024}).encode()
        client.sendall(struct.pack(">I", len(header) if secret else 1024))
        client.sendall(header + b"x" if secret else b"{")
        deadline = time.monotonic() + 20
        sent = 1
        response = bytearray()
        while time.monotonic() < deadline:
            if select.select([client], [], [], 1)[0]:
                # The rejected request may leave unread inbound bytes. Linux
                # can reset after delivering the controller's error response.
                try:
                    while chunk := client.recv(4096):
                        response.extend(chunk)
                        assert len(response) <= 4096
                except ConnectionResetError:
                    pass
                break
            client.sendall(b"x" if secret else b" ")
            sent += 1
        assert sent > 1
        reply = json.loads(response)
        assert reply == {"ok": False, "output": "", "error": "incomplete_secret" if secret else "invalid_frame"}, reply
with socket.socket(socket.AF_UNIX) as client:
    client.settimeout(10)
    client.connect("/run/oblivion-control.sock")
    header = json.dumps({"operation": "status", "session": None, "secret_len": 0}).encode()
    client.sendall(struct.pack(">I", len(header)) + header)
    client.shutdown(socket.SHUT_WR)
    response = bytearray()
    while chunk := client.recv(4096):
        response.extend(chunk)
        assert len(response) <= 1024 * 1024
    reply = json.loads(response)
    assert reply["ok"] and not json.loads(reply["output"])["general_open"], reply
'''], user=1000, group=1000, extra_groups=[], capture_output=True, timeout=50)
    assert probe.returncode == 0, probe.stderr
    assert int(property(CONTROLLER, "MainPID")) > 0
    check("fragmented controller frames and secrets expire despite continued progress; the same service accepts the next valid request")
    assert status()["api_key_present"] is None and status()["egress"] is None
    assert command("egress", secret=TOR_SAVE, success=False) == "general_not_open"
    assert command("network-policy", secret=WEB_SAVE, success=False) == "general_not_open"
    assert command("set-api-key", secret=API_KEY, success=False) == "general_not_writable"
    assert command("clear-api-key", success=False) == "general_not_writable"
    send(b"d", "Premi D di nuovo")
    send(b"x", "Preparazione generale interrotta")
    assert file_digest("/data/general.luks.pending") == before
    send(b"d", "Premi D di nuovo")
    send(b"d", "Prima preparazione")
    assert not status()["general_incomplete"] and not status()["general_present"]
    outer_filler = Path("/data/space-fixture")
    space = os.statvfs("/data")
    with outer_filler.open("xb") as file:
        os.posix_fallocate(file.fileno(), 0, space.f_bavail * space.f_frsize - 4 * 1024 * 1024)
    send(b"\r", "Nuovo volume generale - password")
    send(GENERAL + b"\r", "Ripeti la password del volume generale")
    send(GENERAL + b"\r", "Spazio insufficiente")
    assert status()["general_incomplete"] and not status()["general_present"]
    outer_filler.unlink()
    send(b"d", "Premi D di nuovo")
    send(b"d", "Prima preparazione")
    check("outer disk exhaustion cannot publish a partial general volume; explicit cleanup permits retry")
    send(b"\r", "Nuovo volume generale - password")
    send(GENERAL + b"\r", "Ripeti la password del volume generale")
    send(GENERAL + b"\r", "Archivio generale bloccato")
    assert status()["general_present"] and not status()["general_incomplete"]
    before = file_digest("/data/general.luks")
    assert command("init-general", secret=GENERAL, success=False) == "general_already_exists"
    assert command("discard-general-pending", success=False) == "general_already_exists"
    assert file_digest("/data/general.luks") == before
    check("trusted setup confirms discard, recreates a complete general volume and protects existing archives")
    command("unlock-ephemeral", secret=GENERAL)
    assert status()["api_key_present"] is False
    command("lock")
    assert file_digest("/data/general.luks") == before
    send(b"\r", "Password del volume generale")
    send(GENERAL + b"\r", "Nessuna sessione")
    assert status()["api_key_present"] is False
    send(b"a", "API key Abliteration - salvata")
    send(b"\x1b", "API Abliteration: non configurata")
    assert status()["api_key_present"] is False
    send(b"a", "API key Abliteration - salvata")
    send(b"short\r", "API key non valida")
    assert status()["api_key_present"] is False
    send(b"a", "API key Abliteration - salvata")
    send(API_KEY + b"\r", "API Abliteration: configurata")
    key_file = Path("/run/oblivion/general/profile/abliteration.keys.json")
    assert stored_key() == API_KEY
    assert key_file.stat().st_uid == 0 and key_file.stat().st_mode & 0o777 == 0o600
    assert API_KEY.decode() not in command("status")
    forbidden = subprocess.run(["cat", str(key_file)], user=1000, group=1000, extra_groups=[], capture_output=True)
    assert forbidden.returncode != 0 and not forbidden.stdout
    check("trusted manager saves a hidden API key only in the root-owned encrypted profile; status and manager UID cannot retrieve it")
    assert status()["egress"] == {"saved": {"mode": "tor"}, "selected": {"mode": "tor"}, "temporary": False}
    assert command("egress", secret=PROXY_SAVE, success=False) == "external_proxy_requires_network"
    config = json.loads(Path(CONFIG).read_text())
    # This storage/UI suite has no gateway VM. Enable the root network policy
    # only to exercise profile choices; no external connection is created.
    assert config.get("gateway") is None
    config["gateway_network"] = True
    Path(CONFIG).write_text(json.dumps(config))
    send(b"r", "percorso di rete")
    send(b"s", "Proxy SOCKS5 - IPv4:porta")
    send(b"192.168.1.20:1080\r", "Con autenticazione")
    send(b"a", "Username SOCKS5")
    send(PROXY_USER + b"\r", "Password SOCKS5")
    send(PROXY_PASSWORD + b"\r", "Salva nel generale cifrato")
    send(b"s", "Rete: SOCKS5 192.168.1.20:1080")
    transport_file = Path("/run/oblivion/general/profile/transport.json")
    assert json.loads(transport_file.read_text()) == {"version": 1, "transport": PROXY}
    assert transport_file.stat().st_uid == 0 and transport_file.stat().st_mode & 0o777 == 0o600
    forbidden = subprocess.run(["cat", str(transport_file)], user=1000, group=1000, extra_groups=[], capture_output=True)
    assert forbidden.returncode != 0 and not forbidden.stdout
    assert PROXY_USER.decode() not in command("status") and PROXY_PASSWORD.decode() not in command("status")
    check("trusted network menu saves hidden proxy credentials only in the root-owned encrypted profile; offline policy refuses external proxies")
    saved_transport = transport_file.read_bytes()
    send(b"r", "percorso di rete")
    send(b"t", "Salva nel generale cifrato")
    send(b"t", "Rete: Tor (temporanea)")
    selection_file = Path("/run/oblivion/transport-selection.json")
    assert transport_file.read_bytes() == saved_transport and status()["egress"]["temporary"]
    assert selection_file.stat().st_uid == 0 and selection_file.stat().st_mode & 0o777 == 0o600
    send(b"r", "percorso di rete")
    send(b"p", "Rete: SOCKS5 192.168.1.20:1080")
    assert not selection_file.exists() and not status()["egress"]["temporary"]
    for body in [b'{"action":"saved","transport":{"mode":"tor"}}',
                 b'{"action":"save","transport":{"mode":"tor","extra":true}}']:
        assert command("egress", secret=body, success=False) == "invalid_transport_command"
        assert transport_file.read_bytes() == saved_transport
    pending_transport = transport_file.with_suffix(".json.pending")
    pending_transport.symlink_to(transport_file)
    assert command("egress", secret=TOR_SAVE, success=False) == "file_unavailable"
    pending_transport.unlink()
    os.link(transport_file, pending_transport)
    assert command("egress", secret=TOR_SAVE, success=False) == "unsafe_file"
    pending_transport.unlink()
    pending_transport.write_bytes(b"interrupted-transport-update")
    command("egress", secret=PROXY_SAVE)
    assert not pending_transport.exists()
    command("egress", secret=TOR_SELECT)
    transport_file.write_bytes(b'{"version":999}')
    assert command("status", success=False) == "invalid_transport_profile"
    transport_file.write_bytes(saved_transport)
    command("egress", secret=SAVED_TRANSPORT)
    check("temporary transport stays in RAM; saved selection restores it; unknown fields, aliases and corrupt profiles never trigger a fallback")
    transport_filler = transport_file.with_name("transport-space-fixture")
    fill_profile(transport_filler)
    assert command("egress", secret=TOR_SAVE, success=False) == "transport_write_failed"
    assert transport_file.read_bytes() == saved_transport
    transport_filler.unlink()
    command("egress", secret=PROXY_SAVE)
    assert transport_file.read_bytes() == saved_transport
    check("full-disk transport update preserves the prior profile; retry replaces the interrupted private staging file")
    assert status()["network_policy"] == {"policy": {"version": 1, "rules": []}, "enabled": False, "temporary": False}
    send(b"w", "regole web")
    send(b"a", "Dominio, *.dominio o IP pubblico")
    send(WEB_RULE["destination"].encode() + b"\r", "Porta di destinazione")
    send(b"443\r", "attualmente blocca")
    send(b"a", "Salva nel generale cifrato")
    send(b"s", "Consenti oblivion-policy.example.com:443")
    policy_file = Path("/run/oblivion/general/profile/network-policy.json")
    policy_selection = Path("/run/oblivion/network-policy-selection.json")
    saved_policy = policy_file.read_bytes()
    assert json.loads(saved_policy) == {"version": 1, "rules": [WEB_RULE]}
    assert policy_file.stat().st_uid == 0 and policy_file.stat().st_mode & 0o777 == 0o600
    forbidden = subprocess.run(["cat", str(policy_file)], user=1000, group=1000, extra_groups=[], capture_output=True)
    assert forbidden.returncode != 0 and not forbidden.stdout
    send(b"d", "Rimuovi regola")
    send(b"\x1b", "Consenti oblivion-policy.example.com:443")
    send(b"d", "Rimuovi regola")
    send(b"t", "Nessuna regola.")
    assert status()["network_policy"]["temporary"] and policy_file.read_bytes() == saved_policy
    send(b"p", "Consenti oblivion-policy.example.com:443")
    assert not policy_selection.exists()
    send(b"\x1b", "Sessioni protette")
    check("trusted web rules menu saves a root-owned policy, cancellation preserves it and temporary removal restores from the encrypted profile")
    for body in [b'{"action":"saved","extra":true}',
            json.dumps({"action":"put","rule":{**WEB_RULE,"destination":"127.0.0.1"},"save":True}).encode()]:
        assert command("network-policy", secret=body, success=False) == "invalid_network_command"
        assert policy_file.read_bytes() == saved_policy
    pending_policy = policy_file.with_suffix(".json.pending")
    pending_policy.symlink_to(policy_file)
    assert command("network-policy", secret=WEB_SAVE, success=False) == "file_unavailable"
    pending_policy.unlink()
    os.link(policy_file, pending_policy)
    assert command("network-policy", secret=WEB_SAVE, success=False) == "unsafe_file"
    pending_policy.unlink()
    pending_policy.write_bytes(b"interrupted-network-policy")
    command("network-policy", secret=WEB_SAVE)
    assert not pending_policy.exists() and policy_file.read_bytes() == saved_policy
    command("network-policy", secret=WEB_SELECT)
    policy_file.write_bytes(b'{"version":999}')
    assert command("status", success=False) == "invalid_network_policy"
    policy_file.write_bytes(saved_policy)
    assert status()["network_policy"]["temporary"]
    check("unknown fields, reserved destinations, staging aliases and a corrupt saved policy fail closed even with a RAM override")
    before_selection = policy_selection.read_bytes()
    policy_filler = policy_file.with_name("policy-space-fixture")
    fill_profile(policy_filler)
    assert command("network-policy", secret=WEB_SAVE, success=False) == "network_policy_write_failed"
    assert policy_file.read_bytes() == saved_policy and policy_selection.read_bytes() == before_selection
    policy_filler.unlink()
    command("network-policy", secret=WEB_SAVE)
    assert not policy_selection.exists() and policy_file.read_bytes() == saved_policy
    check("full-disk policy replacement preserves both the saved file and RAM selection; retry publishes and clears the override")
    for secret in [b"too short", b"invalid-key with-spaces", b"invalid-key-with-newline\n"]:
        assert command("set-api-key", secret=secret, success=False) == "invalid_api_key"
        assert stored_key() == API_KEY
    pending_key = key_file.with_name("abliteration.keys.json.pending")
    pending_key.symlink_to(key_file)
    assert command("set-api-key", secret=NEXT_API_KEY, success=False) == "file_unavailable"
    pending_key.unlink()
    os.link(key_file, pending_key)
    assert command("clear-api-key", success=False) == "unsafe_file"
    pending_key.unlink()
    pending_key.write_bytes(b"interrupted-key-update")
    command("set-api-key", secret=NEXT_API_KEY)
    assert stored_key() == NEXT_API_KEY and not pending_key.exists()
    check("invalid keys and staging aliases are rejected; an interrupted private staging file permits an atomic retry")
    filler_key = key_file.with_name("key-space-fixture")
    legacy_key = key_file.with_name("abliteration.key")
    legacy_key.write_bytes(NEXT_API_KEY)
    key_file.unlink()  # Recreate the previously supported, root-owned format.
    assert status()["api_keys"]["entries"][0]["name"] == "Importata"
    assert not key_file.exists()
    fill_profile(filler_key)
    assert command("set-api-key", secret=API_KEY, success=False) == "profile_write_failed"
    assert stored_key() == NEXT_API_KEY
    filler_key.unlink()
    command("set-api-key", secret=API_KEY)
    assert stored_key() == API_KEY
    assert not legacy_key.exists()
    check("legacy key is read without migration; ENOSPC preserves it and retry publishes the versioned archive before deleting the legacy file")
    fill_profile(filler_key)
    before_key = key_file.read_bytes()
    assert command("set-api-key", secret=NEXT_API_KEY, success=False) == "profile_write_failed"
    assert key_file.read_bytes() == before_key
    filler_key.unlink()
    command("set-api-key", secret=API_KEY)
    # Publication may have completed before legacy cleanup. Never fall back to
    # the old credential, including when the authoritative archive is invalid.
    legacy_key.write_bytes(NEXT_API_KEY)
    assert stored_key() == API_KEY
    before_key = key_file.read_bytes()
    key_file.write_bytes(b'{"version":999}')
    assert command("status", success=False) == "invalid_key_archive"
    key_file.write_bytes(before_key)
    command("set-api-key", secret=API_KEY)
    assert not legacy_key.exists()
    check("full-disk replacement preserves the archive; published archives take precedence over leftover legacy secrets and malformed archives fail closed")
    send(b"b", "Archivio generale bloccato")
    assert status()["api_key_present"] is None
    send(b"\r", "Password del volume generale")
    send(GENERAL + b"\r", "API Abliteration: configurata")
    assert stored_key() == API_KEY
    send(b"x", "Premi X di nuovo")
    send(b"a", "API Abliteration: configurata")
    assert stored_key() == API_KEY
    send(b"x", "Premi X di nuovo")
    send(b"x", "API Abliteration: non configurata")
    assert json.loads(key_file.read_text())["entries"] == [] and status()["api_key_present"] is False
    send(b"a", "API key Abliteration - salvata")
    send(API_KEY + b"\r", "API Abliteration: configurata")
    check("key persists across lock/unlock; removal requires confirmation and cancellation preserves it")
    first_key = status()["api_keys"]["selected"]
    send(b"g", "chiavi Abliteration")
    send(b"a", "Nome della nuova chiave")
    send(b"Lavoro\r", "API key Abliteration - salvata")
    send(NEXT_API_KEY + b"\r", "Lavoro")
    second_key = status()["api_keys"]["entries"][1]["id"]
    assert first_key != second_key and status()["api_keys"]["selected"] == first_key
    send(b"j", "> Lavoro")
    send(b"r", "Nuovo nome della chiave")
    send(b"Archivio\r", "> Archivio")
    send(b"d", "Archivio [predefinita]")
    assert status()["api_keys"]["default"] == second_key
    send(b"k", "> Predefinita")
    before_key = key_file.read_bytes()
    send(b"\r", "Chiave selezionata: Predefinita")
    assert key_file.read_bytes() == before_key and stored_key() == API_KEY
    assert status()["api_keys"]["selected"] == first_key
    check("trusted manager adds and renames a second hidden key, saves its default and selects another key only in RAM")
    send(b"n", "Scegli la chiave per questa apertura")
    send(b"j", "> Archivio")
    send(b"\r", "Nuova sessione - password")

    send(PASSWORD + b"\r", "Ripeti la password")
    send(PASSWORD + b"\r", "Conversazioni e documenti")
    wait_screen("/exit blocca")
    session_id = status()["sessions"][0]
    assert command("set-api-key", secret=NEXT_API_KEY, success=False) == "session_must_be_closed"
    assert command("clear-api-key", success=False) == "session_must_be_closed"
    assert stored_key() == NEXT_API_KEY
    assert command("api-keys", secret=key_command("select", id=first_key), success=False) == "session_must_be_closed"
    assert command("api-keys", secret=key_command("remove", id=second_key), success=False) == "session_must_be_closed"
    for body in [TOR_SAVE, TOR_SELECT, SAVED_TRANSPORT]:
        assert command("egress", secret=body, success=False) == "session_must_be_closed"
    assert transport_file.read_bytes() == saved_transport
    check("active chat blocks persistent, temporary and saved-profile transport changes")
    for body in [WEB_SAVE, WEB_SELECT, SAVED_POLICY]:
        assert command("network-policy", secret=body, success=False) == "session_must_be_closed"
    assert policy_file.read_bytes() == saved_policy
    check("an active chat blocks every saved or temporary web policy change")
    check("key picker chooses the opening credential; an active session blocks key mutations and identity changes")
    send(b"\x1d", "Sessioni protette")
    send(b"g", "chiavi Abliteration")
    send(b"j", "> Archivio")
    send(b"x", "Premi X di nuovo")
    send(b"x", "chiavi Abliteration")
    assert status()["api_keys"]["selected"] is None and status()["api_keys"]["default"] is None
    assert status()["api_key_present"] is False and len(status()["api_keys"]["entries"]) == 1
    send(b"d", "Predefinita [predefinita]")
    assert status()["api_keys"]["selected"] is None
    send(b"\r", "Chiave selezionata: Predefinita")
    assert stored_key() == API_KEY
    check("removing the selected key never rotates to the remaining account; explicit default and selection restore access")
    archive = Path(f"/run/oblivion/general/sessions/{session_id}.luks")
    before = file_digest(archive)
    Path("/run/oblivion/general/profile/canary").write_bytes(b"OBLIVION_VM_A_CANARY_4d02")
    interrupt_creation("create", PASSWORD, "mke2fs")
    encrypted_before = file_digest("/data/general.luks")
    command("unlock-ephemeral", secret=GENERAL)
    assert status()["api_key_present"] is True
    assert command("set-api-key", secret=NEXT_API_KEY, success=False) == "general_not_writable"
    assert command("clear-api-key", success=False) == "general_not_writable"
    for body in [key_command("add", name="No", key=NEXT_API_KEY.decode()), key_command("rename", id=first_key, name="No"),
                 key_command("remove", id=first_key), key_command("default", id=first_key),
                 key_command("replace", id=first_key, key=NEXT_API_KEY.decode())]:
        assert command("api-keys", secret=body, success=False) == "general_not_writable"
    command("api-keys", secret=key_command("select", id=first_key))
    assert status()["api_keys"]["selected"] == first_key
    assert command("egress", secret=TOR_SAVE, success=False) == "general_not_writable"
    assert status()["egress"]["selected"]["mode"] == "socks5" and not status()["egress"]["temporary"]
    command("egress", secret=TOR_SELECT)
    assert status()["egress"]["selected"]["mode"] == "tor" and status()["egress"]["temporary"]
    command("egress", secret=PROXY_SELECT)
    assert selection_file.exists() and status()["egress"]["temporary"]
    command("egress", secret=SAVED_TRANSPORT)
    assert not selection_file.exists()
    command("egress", secret=TOR_SELECT)
    assert transport_file.read_bytes() == saved_transport
    assert command("network-policy", secret=WEB_SAVE, success=False) == "general_not_writable"
    command("network-policy", secret=WEB_SELECT)
    assert status()["network_policy"]["temporary"] and policy_selection.exists()
    assert status()["network_policy"]["policy"]["rules"][0]["action"] == "deny"
    assert policy_file.read_bytes() == saved_policy
    command("network-policy", secret=SAVED_POLICY)
    assert not policy_selection.exists()
    command("network-policy", secret=WEB_SELECT)
    pending_id = next(Path("/run/oblivion/general/sessions").glob("*.pending")).stem
    assert command("discard-session-pending", pending_id, success=False) == "general_not_writable"
    assert status()["incomplete_sessions"] == []
    command("lock")
    assert file_digest("/data/general.luks") == encrypted_before
    assert not selection_file.exists()
    assert not policy_selection.exists() and status()["network_policy"] is None
    check("read-only web policy overrides use only RAM, clear on lock and leave the encrypted profile byte-identical")
    check("read-only transport choices use RAM, clear on lock and leave the entire encrypted image byte-identical")
    check("read-only profile exposes key metadata and permits RAM selection, rejects saved-key mutations and pending deletion, and remains byte-identical")
    terminal.reset()
    os.kill(manager_pid, signal.SIGKILL)
    manager_pid = wait_restart(MANAGER, manager_pid)
    wait_screen("Archivio generale bloccato")
    send(b"e", "avvio effimero, sola lettura")
    send(GENERAL + b"\r", "Nuova sessione effimera")
    assert status()["general_readonly"] and status()["sessions"] == []
    assert command("enter", session_id, secret=PASSWORD, success=False) == "general_not_writable"
    ephemeral = Path("/run/oblivion/ephemeral.luks")
    # A failed preparation cannot overwrite an existing path. Cleanup occurs
    # only after the kernel mapping and its VM have really stopped.
    ephemeral.symlink_to(archive)
    assert command("enter-ephemeral", success=False) == "image_exists_or_unavailable"
    assert file_digest(archive) == before
    ephemeral.unlink()
    # Lower only the disposable VM's tmpfs quota, without exhausting physical
    # memory or relying on OOM timing. Allocation must never fall back to disk.
    runtime_space = os.statvfs("/run")
    runtime_limit = runtime_space.f_blocks * runtime_space.f_frsize
    runtime_used = (runtime_space.f_blocks - runtime_space.f_bfree) * runtime_space.f_frsize
    subprocess.run(["mount", "-o", f"remount,size={runtime_used + 32 * 1024 * 1024}", "/run"], check=True)
    try:
        assert command("enter-ephemeral", success=False) == "insufficient_space"
        assert ephemeral.exists() and not status()["session_open"]
        assert not Path("/dev/mapper/oblivion-session").exists()
        assert property("oblivion-session.service", "ActiveState") in ["inactive", "failed"]
        assert command("enter-ephemeral", success=False) == "image_exists_or_unavailable"
    finally:
        subprocess.run(["mount", "-o", f"remount,size={runtime_limit}", "/run"], check=True)
    send(b"b", "Archivio generale bloccato")
    assert not ephemeral.exists() and file_digest("/data/general.luks") == encrypted_before
    send(b"e", "avvio effimero, sola lettura")
    send(GENERAL + b"\r", "Nuova sessione effimera")
    check("exhausted RAM filesystem quota refuses ephemeral allocation without a disk fallback or VM; lock removes the partial RAM file and leaves the general image unchanged")
    ram_keys = Path("/run/oblivion/api-keys.json")
    ram_pending = ram_keys.with_suffix(".json.pending")
    key_selection_file = Path("/run/oblivion/api-key-selection")
    temporary_command = key_command("temporary", name="Volatile", key=RAM_API_KEY.decode())
    saved_keys = key_file.read_bytes()
    assert command("api-keys", secret=key_command("temporary", name="Volatile", key="short"), success=False) == "invalid_api_key"
    ram_pending.symlink_to(key_file)
    assert command("api-keys", secret=temporary_command, success=False) == "file_unavailable"
    ram_pending.unlink()
    send(b"g", "chiavi Abliteration")
    send(b"t", "Nome della chiave temporanea")
    send(b"Volatile\r", "solo RAM fino al blocco")
    send(RAM_API_KEY + b"\r", "Nuova sessione effimera")
    ram_id = status()["api_keys"]["selected"]
    assert ram_id != first_key and status()["api_keys"]["entries"][1]["temporary"]
    assert ram_keys.stat().st_uid == 0 and ram_keys.stat().st_mode & 0o777 == 0o600
    assert subprocess.check_output(["stat", "-f", "-c", "%T", str(ram_keys)]).strip() == b"tmpfs"
    assert RAM_API_KEY in ram_keys.read_bytes() and RAM_API_KEY.decode() not in command("status")
    forbidden = subprocess.run(["cat", str(ram_keys)], user=1000, group=1000, extra_groups=[], capture_output=True)
    assert forbidden.returncode != 0 and not forbidden.stdout
    assert key_file.read_bytes() == saved_keys and file_digest("/data/general.luks") == encrypted_before
    check("the trusted readonly key menu accepts a hidden RAM credential; only root can read its tmpfs archive and neither status nor the encrypted profile receives the secret")
    saved_ram_keys = ram_keys.read_bytes()
    saved_selection = key_selection_file.read_bytes()
    runtime_space = os.statvfs("/run")
    runtime_limit = runtime_space.f_blocks * runtime_space.f_frsize
    runtime_used = (runtime_space.f_blocks - runtime_space.f_bfree) * runtime_space.f_frsize
    subprocess.run(["mount", "-o", f"remount,size={runtime_used}", "/run"], check=True)
    try:
        assert command("api-keys", secret=temporary_command, success=False) == "selection_write_failed"
        assert command("api-keys", secret=key_command("select", id=first_key), success=False) == "selection_write_failed"
        assert ram_keys.read_bytes() == saved_ram_keys and key_selection_file.read_bytes() == saved_selection
    finally:
        subprocess.run(["mount", "-o", f"remount,size={runtime_limit}", "/run"], check=True)
    command("api-keys", secret=key_command("select", id=ram_id))
    send(b"g", "Volatile [RAM]")
    send(b"j", "> Volatile [RAM]")
    send(b"r", "Nuovo nome della chiave")
    send(b"Solo RAM\r", "Solo RAM [RAM]")
    assert not ram_pending.exists()
    send(b"s", "Sostituisci la API key selezionata")
    send(NEXT_API_KEY + b"\r", "Solo RAM [RAM]")
    assert NEXT_API_KEY in ram_keys.read_bytes() and RAM_API_KEY not in ram_keys.read_bytes()
    send(b"x", "Premi X di nuovo")
    send(b"q", "Solo RAM [RAM]")
    assert status()["api_keys"]["selected"] == ram_id
    send(b"x", "Premi X di nuovo")
    send(b"x", "Predefinita [predefinita]")
    assert status()["api_keys"]["selected"] is None and not status()["api_key_present"]
    assert key_file.read_bytes() == saved_keys and file_digest("/data/general.luks") == encrypted_before
    check("RAM key rename, replacement and confirmed removal leave the saved archive untouched; ENOSPC preserves the prior key and selection and removal never rotates to the saved account")
    send(b"t", "Nome della chiave temporanea")
    send(b"Volatile\r", "solo RAM fino al blocco")
    send(RAM_API_KEY + b"\r", "Nuova sessione effimera")
    send(b"n", "Scegli la chiave per questa apertura")
    send(b"j", "> Volatile [RAM]")
    send(b"\r", "Conversazioni e documenti")
    wait_screen("/exit blocca")
    assert status()["session_open"] and status()["general_readonly"]
    assert command("enter-ephemeral", success=False) == "vm_already_running"
    assert command("api-keys", secret=temporary_command, success=False) == "session_must_be_closed"
    assert ephemeral.stat().st_uid == 0 and ephemeral.stat().st_mode & 0o777 == 0o600
    assert ephemeral.stat().st_size == status()["session_bytes"]
    assert ephemeral.stat().st_blocks * 512 >= ephemeral.stat().st_size
    assert subprocess.check_output(["stat", "-f", "-c", "%T", str(ephemeral)]).strip() == b"tmpfs"
    first_ephemeral = subprocess.check_output(["cryptsetup", "luksUUID", str(ephemeral)]).strip()
    assert str(ephemeral).encode() in subprocess.check_output(["cryptsetup", "status", "oblivion-session"])
    assert subprocess.run(["findmnt", "--noheadings", "--source", "/dev/mapper/oblivion-session"], capture_output=True).returncode == 1
    send(b"OBLIVION_TUI_A_REQUEST", "OBLIVION_TUI_A_REQUEST")
    send(b"\r", "OBLIVION_TUI_A_REPLY")
    check("trusted ephemeral boot opens a read-only profile and a fresh RAM-backed LUKS VM; the compiled TUI executes the real document-writing shell tool")
    send(b"\x1d", "Nuova sessione effimera")
    assert not status()["session_open"] and not ephemeral.exists()
    assert str(ephemeral).encode() not in subprocess.check_output(["losetup", "--list", "--output", "BACK-FILE"])
    assert property("oblivion-session.service", "ActiveState") in ["inactive", "failed"]
    assert file_digest("/data/general.luks") == encrypted_before
    send(b"n", "Scegli la chiave per questa apertura")
    send(b"j", "> Volatile [RAM]")
    send(b"\r", "Conversazioni e documenti")
    wait_screen("/exit blocca")
    assert subprocess.check_output(["cryptsetup", "luksUUID", str(ephemeral)]).strip() != first_ephemeral
    send(b"OBLIVION_TUI_B_REQUEST", "OBLIVION_TUI_B_REQUEST")
    send(b"\r", "OBLIVION_TUI_B_REPLY")
    check("closing an ephemeral chat removes its RAM disk; the next VM has a distinct LUKS identity, no prior document, temporary files or conversation")
    terminal.reset()
    os.kill(manager_pid, signal.SIGKILL)
    manager_pid = wait_restart(MANAGER, manager_pid)
    wait_screen("Archivio generale bloccato")
    locked()
    assert not ephemeral.exists() and file_digest("/data/general.luks") == encrypted_before
    assert not ram_keys.exists() and not ram_pending.exists() and not key_selection_file.exists()
    assert not key_selection_file.with_name("api-key-selection.pending").exists()
    assert str(ephemeral).encode() not in subprocess.check_output(["losetup", "--list", "--output", "BACK-FILE"])
    check("manager death destroys the ephemeral VM and RAM disk before restart, closes both mappings and leaves the complete encrypted general image byte-identical")
    send(b"\r", "Password del volume generale")
    send(GENERAL + b"\r", "Sessioni protette")
    assert command("enter-ephemeral", success=False) == "ephemeral_boot_required"
    current = status()
    assert len(current["api_keys"]["entries"]) == 1 and not current["api_keys"]["entries"][0]["temporary"]
    saved_keys = key_file.read_bytes()
    command("api-keys", secret=temporary_command)
    temporary_id = status()["api_keys"]["selected"]
    assert status()["api_keys"]["entries"][1]["temporary"] and RAM_API_KEY in ram_keys.read_bytes()
    assert key_file.read_bytes() == saved_keys
    command("api-keys", secret=key_command("remove", id=temporary_id))
    assert status()["api_keys"]["selected"] is None
    assert key_file.read_bytes() == saved_keys
    command("api-keys", secret=key_command("select", id=first_key))
    check("RAM credentials remain separate even with a writable general profile; removal does not select a saved account until an explicit choice")
    assert current["sessions"] == [session_id] and len(current["incomplete_sessions"]) == 1
    pending_id = current["incomplete_sessions"][0]
    assert command("open", pending_id, secret=PASSWORD, success=False) == "file_unavailable"
    assert file_digest(archive) == before
    pending = Path(f"/run/oblivion/general/sessions/{pending_id}.pending")
    partial = file_digest(pending)
    send(b"i", "Creazioni interrotte - mai aperte")
    send(b"d", "Premi D di nuovo")
    send(b"x", "Creazioni interrotte - mai aperte")
    assert file_digest(pending) == partial
    send(b"d", "Premi D di nuovo")
    send(b"d", "Nessuna creazione interrotta")
    assert not pending.exists() and file_digest(archive) == before
    assert command("discard-session-pending", session_id, success=False) == "file_unavailable"
    assert command("discard-session-pending", "../profile", success=False) == "invalid_session_id"
    alias_id = "f" * 32
    alias = archive.parent / (alias_id + ".pending")
    alias.symlink_to(archive)
    assert command("discard-session-pending", alias_id, success=False) == "file_unavailable"
    alias.unlink()
    os.link(archive, alias)
    assert command("discard-session-pending", alias_id, success=False) == "unsafe_file"
    alias.unlink()
    assert file_digest(archive) == before
    check("interrupted session formatting survives restart, cannot open, and is discarded only after confirmation")
    # Fill the general filesystem with a synthetic preallocation. The next
    # creation must fail without touching the already published session.
    filler = Path("/run/oblivion/general/profile/space-fixture")
    with filler.open("xb") as file:
        os.posix_fallocate(file.fileno(), 0, status()["available_bytes"] - 4 * 1024 * 1024)
    send(b"i", "Sessioni protette")
    send(b"n", "Nuova sessione - password")
    send(PASSWORD + b"\r", "Ripeti la password")
    send(PASSWORD + b"\r", "Spazio insufficiente")
    assert status()["sessions"] == [session_id] and not status()["session_open"]
    assert len(status()["incomplete_sessions"]) == 1 and file_digest(archive) == before
    assert Path("/run/oblivion/general/profile/canary").read_bytes() == b"OBLIVION_VM_A_CANARY_4d02"
    filler.unlink()
    send(b"i", "Creazioni interrotte - mai aperte")
    send(b"d", "Premi D di nuovo")
    send(b"d", "Nessuna creazione interrotta")
    assert not status()["incomplete_sessions"] and status()["available_bytes"] >= status()["session_bytes"]
    send(b"i", "Sessioni protette")
    send(b"\r", "Password della sessione")
    send(PASSWORD + b"\r", "Conversazioni e documenti")
    wait_screen("/exit blocca")
    check("disk exhaustion is explicit, preserves existing archives and permits reopening after pending cleanup")
    terminal.reset()
    os.kill(manager_pid, signal.SIGKILL)
    manager_pid = wait_restart(MANAGER, manager_pid)
    wait_screen("Archivio generale bloccato")
    locked()
    check("SIGKILL of manager powers down the VM and closes both LUKS mappings before restarting")
    reopen()
    controller_pid = int(property(CONTROLLER, "MainPID"))
    terminal.reset()
    os.kill(controller_pid, signal.SIGKILL)
    wait_restart(CONTROLLER, controller_pid)
    manager_pid = wait_restart(MANAGER, manager_pid)
    wait_screen("Archivio generale bloccato")
    locked()
    check("SIGKILL of controller stops its dependent manager and recovers before both restart")
    reopen()
    vm_pid = int(property("oblivion-session.service", "MainPID"))
    os.kill(vm_pid, signal.SIGSTOP)
    terminal.reset()
    os.kill(manager_pid, signal.SIGKILL)
    manager_pid = wait_restart(MANAGER, manager_pid)
    wait_screen("RECUPERO NECESSARIO")
    current = status()
    assert current["recovery_required"] and current["session_open"] and current["general_open"], current
    for operation, arguments, secret in [("create", [], PASSWORD), ("enter", [session_id], PASSWORD),
            ("unlock", [], GENERAL), ("unlock-ephemeral", [], GENERAL),
            ("set-api-key", [], NEXT_API_KEY), ("clear-api-key", [], b""), ("egress", [], TOR_SELECT),
            ("network-policy", [], WEB_SELECT)]:
        assert command(operation, *arguments, secret=secret, success=False) == "recovery_required"
    rejected = subprocess.run(["/usr/bin/oblivion-control", "create"], input=PASSWORD,
        capture_output=True, user=1000, group=1000, extra_groups=[], timeout=30)
    assert rejected.returncode != 0 and rejected.stderr == b"control_request_failed\n"
    check("unresponsive VM leaves recovery latched and rejects every new opening")
    # Restart once more while recovery is failing: the error must survive UI restarts.
    terminal.reset()
    os.kill(manager_pid, signal.SIGKILL)
    manager_pid = wait_restart(MANAGER, manager_pid)
    wait_screen("RECUPERO NECESSARIO")
    assert status()["recovery_required"]
    send(b"f", "Premi F di nuovo")
    send(b"x", "RECUPERO NECESSARIO")
    assert status()["session_open"] and int(property("oblivion-session.service", "MainPID")) == vm_pid
    send(b"f", "Premi F di nuovo")
    send(b"f", "Archivio generale bloccato")
    locked()
    check("recovery survives restart; cancelled force-stop preserves VM; explicit confirmation closes both volumes")
    reopen()
    # An explicit service stop must complete without ordering deadlocks or orphan VMs.
    systemctl("stop", CONTROLLER)
    locked()
    assert property(MANAGER, "ActiveState") in ["inactive", "failed"]
    assert not Path(f"/proc/{manager_pid}").exists()
    check("controller stop drains dependent services and leaves no active VM or open volume")
    assert all(secret not in output for secret in [GENERAL, PASSWORD, API_KEY, NEXT_API_KEY, RAM_API_KEY, PROXY_USER, PROXY_PASSWORD])
    check("synthetic passwords, API keys and proxy credentials never appear on the managed console")
    subprocess.run(["umount", "/data"], check=True)
    print("OBLIVION_VM_LAB_PASS", flush=True)
except BaseException:
    print("OBLIVION_VM_LAB_FAIL", flush=True)
    # This disposable image journals only synthetic diagnostics in RAM.
    subprocess.run(["journalctl", "-b", "-u", CONTROLLER, "-u", MANAGER, "-u", RECOVER,
        "-u", "oblivion-session.service", "--no-pager", "-n", "80"])
    subprocess.run(["systemctl", "show", "oblivion-session.service", "--property=ActiveState,SubState,Result,CPUUsageNSec,MemoryCurrent"])
    if Path("/run/oblivion-session/qmp.sock").exists():
        # Inspect the actual nested CPU on failure. Register values belong only
        # to this synthetic lab; production QMP remains private to the host.
        try:
            with socket.socket(socket.AF_UNIX) as diagnostic:
                diagnostic.settimeout(5)
                diagnostic.connect("/run/oblivion-session/qmp.sock")
                with diagnostic.makefile("rb") as reader:
                    assert "QMP" in json.loads(reader.readline(65536))
                    for number, request in enumerate([{"execute": "qmp_capabilities"},
                            {"execute": "query-status"},
                            {"execute": "human-monitor-command", "arguments": {"command-line": "info registers"}}]):
                        diagnostic.sendall(json.dumps({**request, "id": number}).encode() + b"\n")
                        while True:
                            reply = json.loads(reader.readline(65536))
                            if reply.get("id") == number:
                                print("OBLIVION_GUEST_DIAGNOSTIC " + json.dumps(reply), flush=True)
                                break
        except (OSError, ValueError, AssertionError) as error:
            print("OBLIVION_GUEST_DIAGNOSTIC_FAILED " + type(error).__name__, flush=True)
    raise
finally:
    os.close(slave)
    os.close(master)
