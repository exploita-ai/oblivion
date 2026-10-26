#!/usr/bin/env python3
"""Selective Tor state, real cryptsetup/systemd and production Tor in a VM."""
import hashlib
import json
import os
import shutil
import select
import termios
import socket
import struct
import subprocess
import time
from pathlib import Path

CONFIG = "/run/oblivion-gateway-host-test.json"
GENERAL = b"synthetic-general-password"
PASSWORD = b"synthetic-session-password-a"
KEY = b"OBLIVION_API_KEY_CANARY_5c91"
NEXT = b"OBLIVION_API_NEXT_CANARY_86ab"
OWNER = "oblivion-gateway-host.service"
VM = "oblivion-gateway-vm.service"


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
            assert KEY not in value and NEXT not in value
    return pid, owner


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


print("OBLIVION_TOR_STATE_FIXTURE_SHA256 " + digest(__file__), flush=True)
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
metadata = json.loads((image / "manifest.json").read_text())
shutil.copyfile("/dev/disk/by-id/virtio-oblivion-gw-image", image / "gateway.squashfs")
for name, expected in metadata.items():
    assert (image / name).stat().st_size == expected["bytes"] and digest(image / name) == expected["sha256"]
    (image / name).chmod(0o644)
run("mount", "-o", "remount,ro", str(image))
print("OBLIVION_GATEWAY_IMAGE_SHA256 " + metadata["gateway.squashfs"]["sha256"], flush=True)

# The installed host image predates the new runtime mount target. Copy only its
# public QEMU binaries/libraries into RAM; neither profile nor vault is copied.
root = Path("/run/oblivion-gateway-qemu-root")
root.mkdir(mode=0o755)
run("mount", "-t", "tmpfs", "-o", "mode=0755,nodev,nosuid,size=512m", "tmpfs", str(root))
shutil.copytree("/usr/lib/oblivion/vm/qemu-root", root, symlinks=True, dirs_exist_ok=True)
(root / "run/oblivion-gateway-vm").mkdir(mode=0o755)
root.chmod(0o755)
run("mount", "-o", "remount,ro", str(root))
# The old immutable host also predates the dedicated numeric account. Install
# the same public account entries as the new host image, only in laboratory RAM.
for name, entry in {
    "passwd": "oblivion-gateway-vm:x:1101:1101::/nonexistent:/usr/sbin/nologin\n",
    "group": "oblivion-gateway-vm:x:1101:\n",
}.items():
    source = Path("/etc") / name
    content = source.read_text()
    assert not any(line.split(":")[2] == "1101" for line in content.splitlines())
    target = Path("/run") / ("oblivion-lab-" + name)
    target.write_text(content + entry)
    target.chmod(0o644)
    run("mount", "--bind", str(target), str(source))
    run("mount", "-o", "remount,bind,ro", str(source))
run("mkfs.ext4", "-q", "-m", "0", "/dev/vdb")
run("mount", "/dev/vdb", "/data")
Path(CONFIG).write_text(json.dumps({"general_image": "/data/general.luks", "general_mib": 768,
    "session_mib": 128, "pbkdf_memory_kib": 65536, "manager_uid": 1000,
    "vm": {"root": "/usr/lib/oblivion/vm/qemu-root", "kernel": "/usr/lib/oblivion/vm/kernel",
        "initrd": "/usr/lib/oblivion/vm/initrd", "filesystem": "/usr/lib/oblivion/vm/guest.squashfs",
        "memory_mib": 1536, "cpus": 2, "accelerator": "tcg"},
    "gateway": {"root": str(root), "kernel": str(image / "kernel"), "initrd": str(image / "initrd"),
        "filesystem": str(image / "gateway.squashfs"), "memory_mib": 1024, "cpus": 2, "accelerator": "tcg"}}))
unit = (bundle / OWNER).read_text().replace(
    "/usr/bin/oblivion-storage --config /etc/oblivion/controller.json",
    "/usr/bin/oblivion-storage-lab --config " + CONFIG)
unit = unit.replace("StandardError=null", "StandardError=journal")
Path("/run/systemd/system/" + OWNER).write_text(unit)
run("systemctl", "daemon-reload")
assert status()["api_key_present"] is None
command("init-general", secret=GENERAL)
command("unlock", secret=GENERAL)
assert status()["api_key_present"] is False
stopped()
check("general unlock without an API key leaves gateway services and VM stopped")

profile = Path("/run/oblivion/general/profile")
state = profile / "tor-state"
guard = "Guard in=default rsa_id=0123456789ABCDEF0123456789ABCDEF01234567 nickname=TestGuard sampled_on=2026-10-24T00:00:00 sampled_idx=0 sampled_by=0.4.9.14 listed=1 confirmed_on=2026-10-24T00:01:00 confirmed_idx=0\n"
seed = guard + "TorVersion Tor 0.4.9.14\nLastWritten 2026-10-24 00:02:00\n"


def selective():
    data = state.read_text()
    assert all(line.startswith(("Guard ", "TorVersion ", "LastWritten ")) for line in data.splitlines())
    assert "TorVersion Tor 0.4.9.14\n" in data
    metadata = state.stat()
    assert metadata.st_uid == 0 and metadata.st_mode & 0o777 == 0o600 and metadata.st_nlink == 1
    assert KEY.decode() not in data and NEXT.decode() not in data
    return data


def network_ready():
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(12)
        channel.connect("/run/oblivion/gateway-control.sock")
        data = b'{"operation":"check"}'
        channel.sendall(struct.pack("!I", len(data)) + data)
        def receive(size):
            data = b""
            while len(data) < size:
                chunk = channel.recv(size - len(data))
                assert chunk
                data += chunk
            return data
        size = struct.unpack("!I", receive(4))[0]
        assert size < 1024
        return json.loads(receive(size))["ok"]


command("set-api-key", secret=KEY)
ready()
assert not selective().startswith("Guard ")
assert network_ready() # Explicit offline mode retains the local broker test path.
check("fresh Tor state is saved with only version and LastWritten, root-owned inside the encrypted profile")
command("clear-api-key")
stopped()
state.write_text(seed)
state.chmod(0o600)
command("set-api-key", secret=KEY)
ready()
command("lock")
stopped()
command("unlock", secret=GENERAL)
ready()
assert "rsa_id=0123456789ABCDEF0123456789ABCDEF01234567" in selective()
command("lock")
check("Tor imports a saved guard before networking and preserves its identity across two gateway VM lifetimes")

before = digest("/data/general.luks")
command("unlock-ephemeral", secret=GENERAL)
ready()
assert status()["general_readonly"]
assert "rsa_id=0123456789ABCDEF0123456789ABCDEF01234567" in selective()
command("lock")
assert digest("/data/general.luks") == before
check("readonly startup imports the saved guard and performs no write to any byte of the encrypted general profile")

command("unlock", secret=GENERAL)
command("clear-api-key")
for invalid in [seed.replace("Tor 0.4.9.14", "Tor 0.4.10.0"), seed + "BWHistoryReadValues 100,200\n"]:
    state.write_text(invalid)
    assert command("set-api-key", secret=KEY, success=False) == "gateway_start_failed"
    stopped()
    assert state.read_text() == invalid and status()["general_open"]
    command("clear-api-key")
state.write_text(seed)
command("set-api-key", secret=KEY)
command("lock")
check("unreviewed versions and nonselective profiles fail closed without replacing the saved state or claiming the general is locked")

command("unlock", secret=GENERAL)
# Stop through the trusted lifecycle, then arrange a full profile before the
# owner starts. The saved API key remains untouched throughout this fault.
run("systemctl", "stop", OWNER)
stopped()
state.unlink()
(profile / "tor-state.pending").touch(mode=0o600)
filler = Path("/run/oblivion/general/state-lab-filler")
with filler.open("wb", buffering=0) as stream:
    for size in [1024 * 1024, 4096, 1]:
        try:
            while True:
                stream.write(b"\x00" * size)
        except OSError as error:
            assert error.errno == 28
result = subprocess.run(["systemctl", "start", OWNER], capture_output=True, timeout=100)
assert result.returncode != 0
stopped()
assert not state.exists() and json.loads((profile / "abliteration.keys.json").read_text())["entries"][0]["key"].encode() == KEY
filler.unlink()
run("systemctl", "start", OWNER)
ready()
assert not (profile / "tor-state.pending").exists()
selective()
command("lock")
check("a full profile prevents gateway readiness; retry safely replaces interrupted staging and preserves the API key")

if Path("/run/oblivion-tor-online").exists():
    run("busybox", "sysctl", "-q", "-w", "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1")
    device = next(path.parent.name for path in Path("/sys/class/net").glob("*/address") if path.read_text().strip() == "52:54:00:6f:00:04")
    run("busybox", "ip", "address", "add", "10.0.2.15/24", "dev", device)
    run("busybox", "ip", "link", "set", device, "up")
    run("busybox", "ip", "route", "add", "default", "via", "10.0.2.2", "dev", device)
    config = json.loads(Path(CONFIG).read_text())
    config["gateway_network"] = True
    Path(CONFIG).write_text(json.dumps(config))
    console = os.open("/dev/ttyAMA0", os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    settings = termios.tcgetattr(console)
    settings[3] = (settings[3] | termios.ICANON) & ~termios.ECHO
    termios.tcsetattr(console, termios.TCSANOW, settings)
    termios.tcflush(console, termios.TCIFLUSH)
    print("OBLIVION_TOR_ENABLE_WAIT", flush=True)
    assert select.select([console], [], [], 60)[0], "capture barrier deadline"
    assert os.read(console, 3) == b"go\n"
    os.close(console)
    command("unlock", secret=GENERAL)
    ready()
    assert not network_ready()
    deadline = time.monotonic() + 300
    while not network_ready():
        assert time.monotonic() < deadline, "Tor bootstrap deadline"
        time.sleep(1)
    public = selective()
    assert public.startswith("Guard ") and "0123456789ABCDEF0123456789ABCDEF01234567" not in public
    command("lock")
    check("real Tor bootstrap and a persisted sampled guard set precede online session authorization; no provider request is made")
    command("unlock", secret=GENERAL)
    ready()
    identities = {field for line in public.splitlines() if line.startswith("Guard ") for field in line.split() if field.startswith("rsa_id=")}
    assert identities.intersection(selective().split())
    command("lock")
    check("a new gateway imports real sampled guards instead of resetting Tor identity on unlock")

assert not status()["general_open"]
run("umount", "/data")
print("OBLIVION_VM_LAB_PASS", flush=True)
