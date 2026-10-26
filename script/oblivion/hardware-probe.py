#!/usr/bin/env python3
"""Non-persistent physical-host checks; never format or mount a physical disk."""
import fcntl
import grp
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def run(args, data=None, timeout=30, check=True):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise AssertionError((args, result.stderr.decode(errors="replace")))
    return result


def writes():
    result = {}
    for path in Path("/sys/block").iterdir():
        if not (path / "device").exists():
            continue
        fields = [int(value) for value in (path / "stat").read_text().split()]
        result[path.name] = {"writes_completed": fields[4], "sectors_written": fields[6],
            "discards_completed": fields[11] if len(fields) > 11 else 0,
            "sectors_discarded": fields[13] if len(fields) > 13 else 0}
    return result


def check(name):
    report["checks"].append(name)
    print("PASS: " + name, file=sys.stderr, flush=True)


assert os.getuid() == 0 and os.uname().machine == "x86_64"
assert len(Path("/proc/swaps").read_text().splitlines()) == 1
assert run(["findmnt", "-n", "-o", "FSTYPE", "/run"]).stdout.strip() == b"tmpfs"
assert run(["findmnt", "-n", "-o", "FSTYPE", "/"]).stdout.strip() == b"overlay"
assert Path("/usr/bin/oblivion-storage").exists()
assert os.statvfs("/run").f_bavail * os.statvfs("/run").f_frsize > 1024 * 1024 * 1024
backend_path = Path("/sys/module/pstore/parameters/backend")
backend = backend_path.read_text().strip() if backend_path.exists() else "not_loaded"
assert backend in ["none", "(null)", "not_loaded"], "Disable persistent crash storage before this test"
before = writes()
report = {"passed": False, "checks": [], "disk_writes_before": before,
    "pstore_backend": backend,
    "scope": "Physical x86/KVM Linux boot with diagnostic init, followed by production controller LUKS operations on RAM files. No provider, production chat, physical disk writes, or shared guest folders."}
started = time.monotonic()
controller_stopped = False
config = None
mounted = False
vm = None
runtime = Path(tempfile.mkdtemp(prefix="oblivion-physical-probe-", dir="/run"))
os.chmod(runtime, 0o711)
try:
    with Path("/dev/kvm").open("rb+") as device:
        assert fcntl.ioctl(device.fileno(), 0xae00) == 12
    check("KVM API is usable on the physical CPU")
    vm_dir = runtime / "vm"
    vm_dir.mkdir(mode=0o700)
    os.chown(vm_dir, 1100, 1100)
    base = Path("/usr/lib/oblivion/vm/session")
    serial = bytearray()
    vm = subprocess.Popen([
        "/usr/bin/qemu-system-x86_64", "-machine", "q35,dump-guest-core=off,mem-merge=off",
        "-accel", "kvm", "-cpu", "host", "-m", "512", "-smp", "2",
        "-nodefaults", "-display", "none", "-monitor", "none", "-nic", "none", "-no-reboot",
        "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-serial", "stdio", "-qmp", "unix:" + str(vm_dir / "qmp.sock") + ",server=on,wait=off",
        "-kernel", str(base / "kernel"), "-initrd", str(base / "initrd"),
        "-append", "root=/dev/vda ro rootfstype=squashfs console=ttyS0 init=/bin/sh panic=-1",
        "-drive", "file=" + str(base / "root.squashfs") + ",format=raw,if=virtio,readonly=on",
        "-device", "virtio-rng-pci"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, user=1100, group=1100, extra_groups=[grp.getgrnam("kvm").gr_gid])
    deadline = time.monotonic() + 90
    while not re.search(rb"(?:^|\r?\n)# ?$", serial):
        assert vm.poll() is None, serial[-3000:].decode(errors="replace")
        assert time.monotonic() < deadline, serial[-3000:].decode(errors="replace")
        if select.select([vm.stdout], [], [], 0.2)[0]:
            serial.extend(os.read(vm.stdout.fileno(), 65536))
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(10)
        client.connect(str(vm_dir / "qmp.sock"))
        with client.makefile("rwb", buffering=0) as channel:
            assert "QMP" in json.loads(channel.readline())
            for operation in ["qmp_capabilities", "query-kvm"]:
                channel.write(json.dumps({"execute": operation}).encode() + b"\n")
                while True:
                    reply = json.loads(channel.readline())
                    if "event" in reply:
                        continue
                    assert "return" in reply, reply
                    break
            assert reply["return"] == {"enabled": True, "present": True}
            report["qemu_kvm"] = reply["return"]
    status = Path(f"/proc/{vm.pid}/status").read_text()
    assert re.search(r"^Uid:\s+1100\s+1100\s+1100\s+1100$", status, re.M)
    report["qemu_uid"] = 1100
    vm.stdin.write(b"export PS1=''; mount -t proc proc /proc; printf '\\nOBLIVION_KVM_BOOT_OK\\n'; uname -m; cat /proc/swaps; busybox poweroff -f\n")
    vm.stdin.flush()
    more, _ = vm.communicate(timeout=30)
    serial.extend(more)
    assert vm.returncode == 0, serial[-3000:].decode(errors="replace")
    assert re.search(rb"\r?\nOBLIVION_KVM_BOOT_OK\r?\nx86_64\r?\n", serial), serial[-3000:]
    report["guest_serial_tail"] = serial[-1800:].decode(errors="replace")
    check("A nonroot QEMU boots the packaged Debian kernel/root filesystem using KVM and powers off cleanly")
    original = json.loads(run(["/usr/bin/oblivion-storage", "--config", "/etc/oblivion/controller.json", "status"]).stdout)
    assert not original["general_open"] and not original["session_open"] and not original["general_present"]
    run(["systemctl", "stop", "oblivion-manager.service", "oblivion-controller.service"], timeout=120)
    controller_stopped = True
    deadline = time.monotonic() + 30
    # Stop queues recovery asynchronously: include pending jobs in the wait.
    while (b"oblivion-recover.service" in run(["systemctl", "list-jobs", "--no-legend", "--no-pager"]).stdout
            or run(["systemctl", "show", "oblivion-recover.service", "-p", "ActiveState", "--value"]).stdout.strip()
            in [b"activating", b"active", b"deactivating"]):
        assert time.monotonic() < deadline
        time.sleep(0.1)
    vaults = runtime / "vaults"
    vaults.mkdir(mode=0o700)
    config = vaults / "controller.json"
    config.write_text(json.dumps({"general_image": str(vaults / "general.luks"), "general_mib": 512,
        "session_mib": 128, "pbkdf_memory_kib": 65536, "manager_uid": 1000}))
    config.chmod(0o600)

    def storage(operation, *args, secret=b"", success=True):
        result = run(["/usr/bin/oblivion-storage", "--config", str(config), operation, *args],
            data=secret, timeout=90, check=success)
        if not success:
            assert result.returncode != 0, "Unexpected acceptance: " + operation
        return result

    general = b"synthetic-physical-general-password"
    session_a = b"synthetic-physical-session-a"
    session_b = b"synthetic-physical-session-b"
    storage("recover")
    storage("init-general", secret=general)
    header = run(["cryptsetup", "luksDump", "--dump-json-metadata", str(vaults / "general.luks")])
    metadata = json.loads(header.stdout)
    assert all(slot["kdf"]["type"] == "argon2id" for slot in metadata["keyslots"].values())
    storage("unlock", secret=b"incorrect-synthetic-password", success=False)
    storage("unlock", secret=general)
    a = storage("create", secret=session_a).stdout.decode().strip()
    b = storage("create", secret=session_b).stdout.decode().strip()
    check("Production controller creates nested LUKS2 volumes in RAM and rejects an incorrect general password")
    storage("open", a, secret=b"incorrect-synthetic-password", success=False)
    storage("open", a, secret=session_a)
    blocked = storage("open", b, secret=session_b, success=False)
    assert b"session_already_open" in blocked.stderr
    check("Session passwords are separate and a second simultaneous opening is rejected")
    mount = vaults / "mounted"
    mount.mkdir(mode=0o700)
    canary = b"OBLIVION_PHYSICAL_RAM_CANARY_A_21d8"
    for index, (session, password) in enumerate([(a, session_a), (b, session_b), (a, session_a)]):
        if not Path("/dev/mapper/oblivion-session").exists():
            storage("open", session, secret=password)
        run(["mount", "-o", "nodev,nosuid,noexec", "/dev/mapper/oblivion-session", str(mount)])
        mounted = True
        path = mount / "workspace/physical-canary"
        if session == b:
            assert not path.exists(), "Session A file visible in session B"
        elif index == 2:
            assert path.read_bytes() == canary
        else:
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(canary)
        run(["umount", str(mount)])
        mounted = False
        storage("close")
    check("Separate filesystems preserve A across reopening and keep its file absent from B")
    storage("lock")
    locked = json.loads(storage("status").stdout)
    assert not locked["general_open"] and not locked["session_open"]
    with (vaults / "general.luks").open("rb") as file:
        previous = b""
        while chunk := file.read(1024 * 1024):
            assert canary not in previous + chunk
            previous = chunk[-len(canary):]
    check("Lock removes both device mappings and the test marker is absent from the closed ciphertext")
    report["passed"] = True
finally:
    if vm and vm.poll() is None:
        vm.kill()
        vm.wait()
    if mounted:
        mounted = run(["umount", str(mount)], check=False).returncode != 0
    if config:
        report["recovery_succeeded"] = run(["/usr/bin/oblivion-storage", "--config", str(config), "recover"], timeout=90, check=False).returncode == 0
    if controller_stopped:
        report["controller_restart_succeeded"] = run(["systemctl", "start", "oblivion-controller.service"], timeout=120, check=False).returncode == 0
        deadline = time.monotonic() + 15
        while run(["systemctl", "is-active", "--quiet", "oblivion-manager.service"], check=False).returncode:
            if time.monotonic() >= deadline:
                break
            time.sleep(0.1)
    safe = not mounted and not Path("/dev/mapper/oblivion-general").exists() and not Path("/dev/mapper/oblivion-session").exists()
    if safe:
        shutil.rmtree(runtime)
    report["ram_cleanup_complete"] = safe and not runtime.exists()
    report["disk_writes_after"] = writes()
    report["physical_disk_write_counters_unchanged"] = report["disk_writes_after"] == before
    report["manager_restored"] = run(["systemctl", "is-active", "--quiet", "oblivion-manager.service"], check=False).returncode == 0
    report["passed"] = report["passed"] and report["ram_cleanup_complete"] and report["physical_disk_write_counters_unchanged"] and report["manager_restored"]
    report["seconds"] = round(time.monotonic() - started, 2)
    print(json.dumps(report, indent=2), flush=True)
assert report["passed"], "Physical probe or cleanup failed"
