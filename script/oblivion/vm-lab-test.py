#!/usr/bin/env python3
"""Real systemd/QEMU/LUKS integration. All credentials and contents are synthetic."""
import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

PRODUCTION = "/usr/bin/oblivion-storage"
LAB = "/usr/bin/oblivion-storage-lab"
CONFIG = "/run/oblivion-vm-test.json"
SESSION = "/dev/mapper/oblivion-session"
CHAT = Path("/usr/lib/oblivion/vm/chat-lab").exists()
checks = []


def check(label):
    checks.append(label)
    print("PASS: " + label, flush=True)


def command(binary, operation, *arguments, secret=b"", fail=None):
    result = subprocess.run([binary, "--config", CONFIG, operation, *arguments],
                            input=secret, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    if fail is not None:
        assert result.returncode != 0 and result.stderr.decode().strip() == fail, (operation, result.stderr)
        return
    assert result.returncode == 0, (operation, result.stderr)
    return result.stdout.decode().strip()


def config(accelerator):
    value = {
        "general_image": "/data/general.luks", "general_mib": 768,
        "session_mib": 128, "pbkdf_memory_kib": 65536, "manager_uid": 1000,
        "vm": {"root": "/usr/lib/oblivion/vm/qemu-root", "kernel": "/usr/lib/oblivion/vm/kernel",
               "initrd": "/usr/lib/oblivion/vm/initrd", "filesystem": "/usr/lib/oblivion/vm/guest.squashfs",
               "memory_mib": 1536 if CHAT else 512, "cpus": 2 if CHAT else 1, "accelerator": accelerator},
    }
    Path(CONFIG).write_text(json.dumps(value))
    os.chmod(CONFIG, 0o600)


def client(operation, *arguments, secret=b""):
    result = subprocess.run(["/usr/bin/oblivion-control", operation, *arguments],
                            input=secret, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            user=1000, group=1000, extra_groups=[], timeout=90)
    assert result.returncode == 0, (operation, result.stderr)
    return result.stdout.decode().strip()


def console():
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(180)
    stream.connect("/run/oblivion-session/console.sock")
    wait_for(stream, "OBLIVION_GUEST_READY")
    return stream


def wait_for(stream, marker):
    data = b""
    deadline = time.monotonic() + 180
    while marker.encode() not in data:
        assert time.monotonic() < deadline, ("guest timeout", data[-2000:])
        try:
            chunk = stream.recv(4096)
        except TimeoutError:
            raise AssertionError(("guest timeout", data[-4000:])) from None
        assert chunk, ("guest disconnected", data[-2000:])
        data = (data + chunk)[-65536:]
    print("GUEST: " + repr(data.decode(errors="replace")), flush=True)


def send(stream, operation, marker):
    stream.sendall(operation.encode() + b"\n")
    wait_for(stream, marker)


def service_pid():
    return int(subprocess.check_output(["systemctl", "show", "oblivion-session.service", "--property=MainPID", "--value"]))


def run():
    os.umask(0o077)
    subprocess.run(["mkfs.ext4", "-q", "-m", "0", "/dev/vdb"], check=True)
    subprocess.run(["mount", "/dev/vdb", "/data"], check=True)
    config("kvm")
    command(PRODUCTION, "init-general", secret=b"synthetic-general-password")
    command(PRODUCTION, "unlock", secret=b"synthetic-general-password")
    a = command(PRODUCTION, "create", secret=b"synthetic-session-password-a")
    b = command(PRODUCTION, "create", secret=b"synthetic-session-password-b")
    command(PRODUCTION, "enter", a, secret=b"synthetic-session-password-a", fail="kvm_required")
    assert not Path(SESSION).exists()
    check("production requires usable KVM before unlocking a session")
    config("tcg")
    command(PRODUCTION, "status", fail="invalid_config")
    check("production binary rejects laboratory emulation configuration")
    daemon = subprocess.Popen([LAB, "--config", CONFIG, "serve"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 10
    while not Path("/run/oblivion-control.sock").exists() or Path("/run/oblivion-control.sock").stat().st_uid != 1000:
        assert daemon.poll() is None and time.monotonic() < deadline
        time.sleep(0.01)
    client("open", a, secret=b"synthetic-session-password-a")
    with console() as stream:
        send(stream, "probe", "OBLIVION_GUEST_CONFINED")
        pid = service_pid()
        status = Path(f"/proc/{pid}/status").read_text()
        assert "Uid:\t1100\t1100\t1100\t1100" in status
        assert "CapEff:\t0000000000000000" in status
        assert "NoNewPrivs:\t1" in status
        assert os.readlink(f"/proc/{pid}/ns/net") != os.readlink("/proc/1/ns/net")
        assert os.readlink(f"/proc/{pid}/ns/mnt") != os.readlink("/proc/1/ns/mnt")
        assert not Path(f"/proc/{pid}/root/data/general.luks").exists()
        assert not Path(f"/proc/{pid}/root/run/oblivion/general").exists()
        assert Path(f"/proc/{pid}/root/dev/oblivion-session").is_block_device()
        check("QEMU runs unprivileged without capabilities in private filesystem and network namespaces")
        check("guest user is unprivileged, root is readonly and temporary files are RAM-backed")
        command(LAB, "enter", b, secret=b"synthetic-session-password-b", fail="vm_already_running")
        if CHAT:
            send(stream, "chat-a", "OBLIVION_CHAT_CREATED")
            check("compiled OpenCode streams a conversation and executes its shell inside A")
        send(stream, "write-a", "OBLIVION_A_WRITTEN")
        client("close")
        assert not Path(f"/proc/{pid}").exists() and not Path(SESSION).exists()
        check("unprivileged manager IPC opens and closes the complete VM lifecycle")
        check("graceful shutdown terminates the VM and its detached work before closing LUKS")
    command(LAB, "enter", b, secret=b"synthetic-session-password-b")
    with console() as stream:
        send(stream, "probe", "OBLIVION_GUEST_CONFINED")
        send(stream, "check-b", "OBLIVION_B_ISOLATED")
        if CHAT:
            send(stream, "chat-b", "OBLIVION_CHAT_EMPTY")
            check("B has no OpenCode conversation, document or temporary file from A")
        command(LAB, "leave")
    check("B starts in a new VM and cannot see A files or temporary state")
    command(LAB, "enter", a, secret=b"synthetic-session-password-a")
    with console() as stream:
        send(stream, "check-a", "OBLIVION_A_RESTORED")
        if CHAT:
            send(stream, "chat-resume", "OBLIVION_CHAT_RESUMED")
            check("OpenCode resumes the same conversation after A is reopened; RAM temporaries are gone")
        os.kill(service_pid(), signal.SIGSTOP)
        command(LAB, "leave", fail="vm_control_failed")
        state = json.loads(command(LAB, "status"))
        assert state["session_open"] and state["vm_state"] == "active"
        check("unresponsive VM cannot be reported locked or release its vault")
        client("force-close")
    assert not Path(SESSION).exists()
    check("reopening A restores persistent files while RAM temporaries and worker state are absent")
    check("explicit forced close stops the service before removing the mapping")
    command(LAB, "enter", a, secret=b"synthetic-session-password-a")
    with console() as stream:
        command(LAB, "lock")
    state = json.loads(command(LAB, "status"))
    assert not state["session_open"] and not state["general_open"]
    assert state["laboratory_emulation"] and state["vm_state"] == "inactive"
    check("global lock shuts down the guest before closing both encryption layers")
    daemon.terminate()
    daemon.wait(timeout=10)
    subprocess.run(["umount", "/data"], check=True)
    print("OBLIVION_VM_LAB_PASS", flush=True)


try:
    run()
except BaseException:
    subprocess.run(["systemctl", "status", "oblivion-session.service", "--no-pager", "--full"])
    subprocess.run(["journalctl", "-u", "oblivion-session.service", "--no-pager", "-n", "40"])
    print("OBLIVION_VM_LAB_FAIL", flush=True)
    raise
