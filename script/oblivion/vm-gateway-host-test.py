#!/usr/bin/env python3
"""Real LUKS profile, systemd owner and production gateway VM on nested TCG."""
import hashlib
import json
import os
import shutil
import signal
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


print("OBLIVION_GATEWAY_HOST_FIXTURE_SHA256 " + digest(__file__), flush=True)
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

command("set-api-key", secret=KEY)
first, _ = ready()
assert json.loads(Path("/run/oblivion/general/profile/abliteration.keys.json").read_text())["entries"][0]["key"].encode() == KEY
check("saving the protected credential starts a distinct UID 1101 gateway VM and completes private configuration")

command("set-api-key", secret=NEXT)
second, _ = ready()
assert second != first and not Path(f"/proc/{first}").exists()
assert json.loads(Path("/run/oblivion/general/profile/abliteration.keys.json").read_text())["entries"][0]["key"].encode() == NEXT
command("clear-api-key")
stopped()
assert status()["api_key_present"] is False
check("credential replacement destroys the previous VM; removal stops both owner and VM before deleting the key")

saved = Path(CONFIG).read_text()
invalid = json.loads(saved)
invalid["gateway"]["filesystem"] = "/run/missing-oblivion-image"
Path(CONFIG).write_text(json.dumps(invalid))
assert command("set-api-key", secret=KEY, success=False) == "gateway_start_failed"
stopped()
assert status()["general_open"] and status()["api_key_present"]
Path(CONFIG).write_text(saved)
command("lock")
command("unlock", secret=GENERAL)
ready()
check("failed gateway startup preserves the saved key and open-state report; explicit lock and unlock recover")
session = command("create", secret=PASSWORD)
assert command("enter", session, secret=PASSWORD, success=False) == "session_channel_failed"
chat = int(property("oblivion-session.service", "MainPID"))
assert "Uid:\t1100\t1100\t1100\t1100" in Path(f"/proc/{chat}/status").read_text()
ready()
assert property("oblivion-session.service", "PrivateNetwork") == "yes"
assert not Path(f"/proc/{chat}/root/run/oblivion-gateway-vm/control.sock").exists()
assert command("set-api-key", secret=NEXT, success=False) == "session_must_be_closed"
command("force-leave")
ready()
check("a legacy guest without the token receiver fails closed; its VM stays interlocked and cannot see private control or change the key")

pid, owner = ready()
os.kill(owner, signal.SIGKILL)
stopped()
assert not Path(f"/proc/{pid}").exists()
assert status()["general_open"] and status()["api_key_present"]
command("lock")
assert not status()["general_open"]
check("host owner death removes gateway credential memory; explicit lock then closes the general LUKS mapping")

command("unlock", secret=GENERAL)
pid, owner = ready()
os.kill(pid, signal.SIGSTOP)
stopped()
assert not Path(f"/proc/{pid}").exists() and not Path(f"/proc/{owner}").exists()
command("recover")
assert not status()["general_open"] and not status()["recovery_required"]
check("an unresponsive gateway expires the private status deadline and is killed before recovery closes storage")

before = digest("/data/general.luks")
command("unlock-ephemeral", secret=GENERAL)
ready()
assert status()["general_readonly"]
assert command("set-api-key", secret=NEXT, success=False) == "general_not_writable"
command("lock")
stopped()
assert digest("/data/general.luks") == before
check("readonly general supplies the saved credential without modifying any byte of the encrypted profile")

command("unlock", secret=GENERAL)
ready()
command("recover")
stopped()
current = status()
assert not any(current[k] for k in ["general_open", "general_mounted", "session_open", "recovery_required"])
assert current["api_key_present"] is None
check("explicit recovery stops gateway before closing the general")

# Exercise the actual controller service's ExecStopPost composition. The
# existing manager suite covers its dependent TUI; suppress that dependency
# here so this fixture retains the laboratory console.
controller = (bundle / "oblivion-controller.service").read_text().replace(
    "/usr/bin/oblivion-storage --config /etc/oblivion/controller.json",
    "/usr/bin/oblivion-storage-lab --config " + CONFIG).replace("Wants=oblivion-manager.service\n", "")
Path("/run/systemd/system/oblivion-controller.service").write_text(controller)
run("systemctl", "daemon-reload")
run("systemctl", "start", "oblivion-controller.service")
run("setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "/usr/bin/oblivion-control", "unlock", input=GENERAL)
ready()
run("systemctl", "stop", "oblivion-controller.service")
stopped()
current = status()
assert not any(current[k] for k in ["general_open", "general_mounted", "session_open", "recovery_required"])
assert property("oblivion-controller.service", "Result") == "success"
for path in Path("/run").rglob("*"):
    if path.is_symlink() or not path.is_file():
        continue
    with path.open("rb") as stream:
        tail = b""
        while chunk := stream.read(1024 * 1024):
            assert KEY not in tail + chunk and NEXT not in tail + chunk, str(path)
            tail = chunk[-128:]
check("controller service stop closes gateway and LUKS without a dependency deadlock or credentials in runtime files")
run("umount", "/data")
print("OBLIVION_VM_LAB_PASS", flush=True)
