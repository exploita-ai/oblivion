#!/usr/bin/env python3
"""Physical live: production gateway/TUI, synthetic RAM vault, no provider call."""
import fcntl
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time


def run(args, data=None, timeout=120, check=True):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if check:
        assert result.returncode == 0, (args, result.stderr.decode(errors="replace"))
    return result


def storage(operation, *args, secret=b"", success=True):
    result = run([STORAGE, "--config", str(config), operation, *args],
                 data=secret, check=success)
    if not success:
        assert result.returncode != 0, operation
    return result


def state():
    return json.loads(storage("status").stdout)


def property(unit, name):
    return run(["systemctl", "show", unit, "-p", name, "--value"]).stdout.decode().strip()


def writes():
    return {d.name: [int(p.read_text().split()[i]) for i in [4, 6, 11, 13]]
            for d in Path("/sys/block").iterdir() if (d / "device").exists()
            for p in [d / "stat"]}


def check(label):
    report["checks"].append(label)
    print("PASS: " + label, file=sys.stderr, flush=True)


def wait_recovery():
    deadline = time.monotonic() + 120
    while (b"oblivion-recover.service" in run(["systemctl", "list-jobs", "--no-legend"]).stdout
           or property("oblivion-recover.service", "ActiveState") in ["activating", "active", "deactivating"]):
        assert time.monotonic() < deadline, "recovery deadline"
        time.sleep(0.1)


def gateway_status():
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(15)
        channel.connect("/run/oblivion/gateway-control.sock")
        request = b'{"operation":"check"}'
        channel.sendall(struct.pack("!I", len(request)) + request)
        def receive(size):
            data = b""
            while len(data) < size:
                chunk = channel.recv(size - len(data))
                assert chunk
                data += chunk
            return data
        size = struct.unpack("!I", receive(4))[0]
        assert size < 1024
        return json.loads(receive(size))


def qmp(role, operation):
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(15)
        channel.connect(f"/run/oblivion-{role}/qmp.sock")
        with channel.makefile("rwb", buffering=0) as stream:
            assert "QMP" in json.loads(stream.readline())
            for command in ["qmp_capabilities", operation]:
                stream.write(json.dumps({"execute": command}).encode() + b"\n")
                while True:
                    reply = json.loads(stream.readline())
                    if "event" not in reply:
                        assert "return" in reply, reply
                        break
            return reply["return"]


def wait_screen(marker):
    fresh = bytearray()
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        assert manager.poll() is None, ("manager exited", manager.returncode)
        if select.select([master], [], [], 0.1)[0]:
            value = os.read(master, 65536)
            screen.extend(value)
            fresh.extend(value)
            if marker.encode() in re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", fresh):
                return
    raise AssertionError(("screen timeout", marker, fresh[-2000:].decode(errors="replace")))


def capture():
    try:
        with capture_socket, (evidence / "outgoing.pcap").open("wb") as file:
            file.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            while not capture_stop.is_set():
                if not select.select([capture_socket], [], [], 0.2)[0]:
                    continue
                packet, address = capture_socket.recvfrom(65535)
                if address[2] != socket.PACKET_OUTGOING:
                    continue
                protocol, port = "other", None
                if packet[12:14] == b"\x08\x00" and len(packet) >= 34:
                    start = 14 + (packet[14] & 15) * 4
                    protocol = {6: "tcp", 17: "udp", 1: "icmp"}.get(packet[23], "other-ipv4")
                    if protocol in ["tcp", "udp"] and len(packet) >= start + 4:
                        source, port = struct.unpack("!HH", packet[start:start + 4])
                        if protocol == "tcp" and (source == 22 or port == 22):
                            continue
                elif packet[12:14] == b"\x86\xdd":
                    protocol = "ipv6"
                elif packet[12:14] == b"\x08\x06":
                    protocol = "arp"
                label = protocol + (":" + str(port) if port is not None else "")
                traffic[label] = traffic.get(label, 0) + 1
                assert all(value not in packet for value in [GENERAL, PASSWORD, API_KEY]), "cleartext canary in uplink"
                if file.tell() + len(packet) + 16 > 64 * 1024 * 1024:
                    raise AssertionError("capture size limit")
                now = time.time()
                file.write(struct.pack("<IIII", int(now), int(now % 1 * 1000000), len(packet), len(packet)))
                file.write(packet)
            report["capture_kernel_stats"] = struct.unpack("II", capture_socket.getsockopt(263, 6, 8))
    except BaseException as error:
        capture_errors.append(str(error))


os.umask(0o077)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--storage-binary", default="/usr/bin/oblivion-storage")
STORAGE = parser.parse_args().storage_binary
assert Path(STORAGE).is_absolute() and not any(c.isspace() for c in STORAGE)
metadata = Path(STORAGE).stat()
assert metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0
assert os.getuid() == 0 and os.uname().machine == "x86_64"
assert len(Path("/proc/swaps").read_text().splitlines()) == 1
assert run(["findmnt", "-n", "-o", "FSTYPE", "/run"]).stdout.strip() == b"tmpfs"
assert run(["findmnt", "-n", "-o", "FSTYPE", "/"]).stdout.strip() == b"overlay"
assert Path("/sys/module/pstore/parameters/backend").read_text().strip() in ["none", "(null)"]
assert os.statvfs("/run").f_bavail * os.statvfs("/run").f_frsize > 2 * 1024 ** 3
original = json.loads(run(["/usr/bin/oblivion-storage", "--config", "/etc/oblivion/controller.json", "status"]).stdout)
assert not any(original[key] for key in ["general_open", "session_open", "general_present", "recovery_required"])
# /run is noexec on the live: a replacement needs a dedicated readonly exec mount.
assert json.loads(run([STORAGE, "--config", "/etc/oblivion/controller.json", "status"]).stdout) == original
GENERAL = b"OBLIVION_GENERAL_SYNTHETIC_c782"
PASSWORD = b"OBLIVION_SESSION_SYNTHETIC_f921"
API_KEY = b"OBLIVION_FAKE_API_SYNTHETIC_916e"
runtime = Path(tempfile.mkdtemp(prefix="oblivion-session-probe-", dir="/run"))
evidence = Path(tempfile.mkdtemp(prefix="oblivion-session-evidence-", dir="/run"))
config = runtime / "controller.json"
override_dir = Path("/run/systemd/system/oblivion-gateway-host.service.d")
override = override_dir / "physical-probe.conf"
assert not override.exists()
settings = json.loads(Path("/etc/oblivion/controller.json").read_text())
settings.update(general_image=str(runtime / "general.luks"), general_mib=768,
                session_mib=128, pbkdf_memory_kib=65536, gateway_network=False)
config.write_text(json.dumps(settings))
started = time.monotonic()
before = writes()
report = {"passed": False, "checks": [], "evidence_directory": str(evidence), "provider_requests_sent": False,
          "storage_sha256": hashlib.sha256(Path(STORAGE).read_bytes()).hexdigest(),
          "storage_from_iso": STORAGE == "/usr/bin/oblivion-storage",
          "scope": "Production binaries and VM images on physical KVM, RAM vault and synthetic key; no inference."}
manager = daemon = capture_thread = None
master = None
stopped = False
screen = bytearray()
traffic, capture_errors = {}, []
capture_stop = threading.Event()
try:
    run(["systemctl", "stop", "oblivion-manager.service", "oblivion-controller.service"])
    stopped = True
    wait_recovery()
    storage("recover")
    override_dir.mkdir(exist_ok=True)
    # Capture only static error identifiers in RAM while exercising synthetic data.
    override.write_text("[Service]\nExecStart=\nExecStart=" + STORAGE + " --config " + str(config)
                       + " gateway-host-run\nStandardError=append:" + str(evidence / "gateway-error.log") + "\n")
    run(["systemctl", "daemon-reload"])
    storage("init-general", secret=GENERAL)
    storage("unlock", secret=GENERAL)
    session = storage("create", secret=PASSWORD).stdout.decode().strip()
    failure = storage("enter", session, secret=PASSWORD, success=False)
    assert failure.stderr.strip() == b"gateway_unavailable", failure.stderr
    assert not state()["session_open"] and not Path("/dev/mapper/oblivion-session").exists()
    check("Absent API key and stopped gateway refuse session opening before decryption")
    storage("set-api-key", secret=API_KEY)
    assert state()["gateway_vm_state"] == "active"
    assert qmp("gateway-vm", "query-kvm") == {"enabled": True, "present": True}
    assert gateway_status()["configured"]
    check("Production Tor gateway boots with KVM while external networking is disabled")
    storage("lock")
    route = json.loads(run(["ip", "-j", "-4", "route", "show", "default"]).stdout)
    interface = min(route, key=lambda r: r.get("metric", 0))["dev"]
    capture_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture_socket.bind((interface, 0))
    capture_thread = threading.Thread(target=capture, daemon=True)
    capture_thread.start()
    settings["gateway_network"] = True
    config.write_text(json.dumps(settings))
    storage("unlock", secret=GENERAL)
    if not gateway_status()["ok"]:
        failure = storage("enter", session, secret=PASSWORD, success=False)
        assert failure.stderr.strip() == b"gateway_not_ready", failure.stderr
        assert not state()["session_open"] and not Path("/dev/mapper/oblivion-session").exists()
        check("Pending Tor bootstrap refuses session opening before decryption")
    deadline = time.monotonic() + 300
    while not gateway_status()["ok"]:
        assert time.monotonic() < deadline, "Tor bootstrap deadline"
        time.sleep(1)
    check("Production Tor bootstraps on the physical uplink without an inference request")
    report["tor_ready_seconds"] = round(time.monotonic() - started, 2)
    Path("/run/oblivion-control.sock").unlink(missing_ok=True)
    daemon = subprocess.Popen([STORAGE, "--config", str(config), "serve"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 10
    while not Path("/run/oblivion-control.sock").exists():
        assert daemon.poll() is None and time.monotonic() < deadline
        time.sleep(0.05)
    master, slave = os.openpty()
    os.chown(os.ttyname(slave), 1000, 1000)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    def terminal_session():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    manager = subprocess.Popen(["/usr/bin/oblivion-manager"], stdin=slave, stdout=slave, stderr=slave,
        user=1000, group=1000, extra_groups=[], preexec_fn=terminal_session,
        env={"TERM": "linux", "HOME": "/run/oblivion-manager", "PATH": "/usr/bin:/bin"})
    os.close(slave)
    wait_screen("Sessioni protette")
    os.write(master, b"\r")
    wait_screen("Password della sessione")
    os.write(master, PASSWORD + b"\r")
    wait_screen("/exit blocca")
    assert state()["session_open"] and state()["vm_state"] == "active"
    assert qmp("session", "query-kvm") == {"enabled": True, "present": True}
    pid = int(property("oblivion-session.service", "MainPID"))
    process = Path(f"/proc/{pid}")
    assert re.search(r"^Uid:\s+1100\s+1100\s+1100\s+1100$", (process / "status").read_text(), re.M)
    assert not (process / "root/run/oblivion/general").exists()
    args = (process / "cmdline").read_bytes()
    assert not any(value in args for value in [b"virtiofs", b"virtfs", b"-fsdev", API_KEY])
    check("Nonroot production manager opens the real chat TUI in a KVM session without shared host filesystems")
    os.write(master, b"\x1d")
    wait_screen("Sessioni protette")
    assert not state()["session_open"] and not Path("/dev/mapper/oblivion-session").exists()
    check("Reserved host key stops the session VM and closes its LUKS mapping")
    os.write(master, b"q")
    deadline = time.monotonic() + 120
    while manager.poll() is None:
        assert time.monotonic() < deadline, "manager exit deadline"
        if select.select([master], [], [], 0.1)[0]:
            try:
                screen.extend(os.read(master, 65536))
            except OSError:
                break
    assert manager.wait(timeout=10) == 0
    assert not any(state()[key] for key in ["general_open", "session_open"])
    assert all(secret not in screen for secret in [GENERAL, PASSWORD, API_KEY])
    check("Manager exit closes both encryption layers without echoing synthetic passwords or API key")
    report["passed"] = True
finally:
    if manager and manager.poll() is None:
        manager.terminate()
        manager.wait(timeout=15)
    if master is not None:
        os.close(master)
    if daemon and daemon.poll() is None:
        daemon.terminate()
        daemon.wait(timeout=15)
    # Keep recovery available even if the candidate binary cannot execute.
    report["recovered"] = run(["/usr/bin/oblivion-storage", "--config", str(config), "recover"], check=False).returncode == 0 if stopped else True
    capture_stop.set()
    if capture_thread:
        capture_thread.join(timeout=10)
        assert not capture_thread.is_alive()
    report["capture_errors"] = capture_errors
    report["gateway_error"] = (evidence / "gateway-error.log").read_text() if (evidence / "gateway-error.log").exists() else ""
    report["outgoing_packet_counts_excluding_ssh"] = traffic
    if (evidence / "outgoing.pcap").exists():
        report["pcap_sha256"] = hashlib.sha256((evidence / "outgoing.pcap").read_bytes()).hexdigest()
    (evidence / "synthetic-terminal.bin").write_bytes(screen)
    override.unlink(missing_ok=True)
    if override_dir.exists() and not any(override_dir.iterdir()):
        override_dir.rmdir()
    run(["systemctl", "daemon-reload"])
    if stopped:
        run(["systemctl", "start", "oblivion-controller.service"])
        deadline = time.monotonic() + 30
        while property("oblivion-manager.service", "ActiveState") != "active":
            assert time.monotonic() < deadline, "manager restore deadline"
            time.sleep(0.1)
    safe = not any(Path("/dev/mapper/" + name).exists() for name in ["oblivion-session", "oblivion-general"])
    if safe:
        shutil.rmtree(runtime)
    report["ram_vault_removed"] = safe and not runtime.exists()
    report["disk_counters_unchanged"] = writes() == before
    report["manager_restored"] = property("oblivion-manager.service", "ActiveState") == "active"
    report["passed"] = report["passed"] and report["recovered"] and report["ram_vault_removed"] and report["disk_counters_unchanged"] and report["manager_restored"] and not capture_errors
    report["seconds"] = round(time.monotonic() - started, 2)
    print(json.dumps(report, indent=2), flush=True)
assert report["passed"]
