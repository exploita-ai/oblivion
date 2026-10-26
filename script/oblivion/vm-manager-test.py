#!/usr/bin/env python3
"""Real manager PTY + real controller/VMs; only public synthetic credentials."""
import fcntl
import json
import os
import re
import select
import signal
import struct
import subprocess
import termios
import time
from pathlib import Path

CONFIG = "/run/oblivion-manager-test.json"
GENERAL = b"synthetic-general-password"
PASSWORD = b"synthetic-session-password-a"
screen = bytearray()


def check(label):
    print("PASS: " + label, flush=True)


def command(operation, *arguments, secret=b""):
    result = subprocess.run(["/usr/bin/oblivion-storage-lab", "--config", CONFIG, operation, *arguments],
        input=secret, capture_output=True, timeout=90)
    assert result.returncode == 0, (operation, result.stderr)
    return result.stdout.decode().strip()


def wait(marker):
    data = bytearray()
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        assert manager.poll() is None, ("manager exited", manager.returncode, data[-1000:])
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            chunk = os.read(master, 65536)
            screen.extend(chunk)
            data.extend(chunk)
            plain = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", data)
            if marker.encode() in plain:
                return
    raise AssertionError(("screen timeout", marker, bytes(data[-3000:])))


def send(value, marker):
    os.write(master, value)
    wait(marker)


def status():
    return json.loads(command("status"))


def session_create(password):
    send(b"n", "Nuova sessione - password")
    send(password + b"\r", "Ripeti la password")
    send(password + b"\r", "OBLIVION_GUEST_READY")


os.umask(0o077)
subprocess.run(["mkfs.ext4", "-q", "-m", "0", "/dev/vdb"], check=True)
subprocess.run(["mount", "/dev/vdb", "/data"], check=True)
Path(CONFIG).write_text(json.dumps({"general_image": "/data/general.luks", "general_mib": 768,
    "session_mib": 128, "pbkdf_memory_kib": 65536, "manager_uid": 1000,
    "vm": {"root": "/usr/lib/oblivion/vm/qemu-root", "kernel": "/usr/lib/oblivion/vm/kernel",
           "initrd": "/usr/lib/oblivion/vm/initrd", "filesystem": "/usr/lib/oblivion/vm/guest.squashfs",
           "memory_mib": 1536, "cpus": 2, "accelerator": "tcg"}}))
command("init-general", secret=GENERAL)
daemon = subprocess.Popen(["/usr/bin/oblivion-storage-lab", "--config", CONFIG, "serve"],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
deadline = time.monotonic() + 10
while not Path("/run/oblivion-control.sock").exists():
    assert daemon.poll() is None and time.monotonic() < deadline
    time.sleep(0.01)
master, slave = os.openpty()
os.chown(os.ttyname(slave), 1000, 1000)
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))


def terminal_session():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


manager = subprocess.Popen(["/usr/bin/oblivion-manager"], stdin=slave, stdout=slave, stderr=slave,
    user=1000, group=1000, extra_groups=[], preexec_fn=terminal_session,
    env={"TERM": "linux", "PATH": "/usr/bin:/bin", "HOME": "/run/oblivion-manager-home"})
os.close(slave)
try:
    wait("Archivio generale bloccato")
    send(b"\r", "Password del volume generale")
    send(b"incorrect-synthetic-password\r", "Operazione non completata")
    assert not status()["general_open"]
    check("wrong password in the nonroot TUI leaves the general volume locked")
    send(b"\r", "Password del volume generale")
    send(GENERAL + b"\r", "Nessuna sessione")
    assert status()["general_open"] and not status()["session_open"]
    check("trusted TUI unlocks general storage without opening a session")
    session_create(PASSWORD)
    a = status()["sessions"][0]
    send(b"probe\r", "OBLIVION_GUEST_CONFINED")
    send(b"chat-a\r", "OBLIVION_CHAT_CREATED")
    send(b"write-a\r", "OBLIVION_A_WRITTEN")
    check("manager creates A, delegates only its console and runs OpenCode inside the guest")
    send(b"\x1d", "Sessioni protette")
    assert not status()["session_open"]
    check("host-reserved key closes the VM and LUKS before returning to the manager")
    session_create(b"synthetic-session-password-b")
    send(b"check-b\r", "OBLIVION_B_ISOLATED")
    send(b"chat-b\r", "OBLIVION_CHAT_EMPTY")
    send(b"\x1d", "Sessioni protette")
    check("TUI creates B in a new isolated VM without A's files or chat")
    sessions = status()["sessions"]
    # New creation leaves the original selected index at zero.
    if sessions.index(a) == 1:
        send(b"j", "Sessioni protette")
    send(b"\r", "Password della sessione")
    send(PASSWORD + b"\r", "OBLIVION_GUEST_READY")
    send(b"check-a\r", "OBLIVION_A_RESTORED")
    send(b"chat-resume\r", "OBLIVION_CHAT_RESUMED")
    check("TUI reopens A and OpenCode resumes the same persisted conversation")
    pid = int(subprocess.check_output(["systemctl", "show", "oblivion-session.service", "-p", "MainPID", "--value"]))
    os.kill(pid, signal.SIGSTOP)
    send(b"\x1d", "Operazione non completata")
    assert status()["session_open"]
    send(b"f", "Premi F di nuovo")
    send(b"x", "SESSIONE ANCORA APERTA")
    assert status()["session_open"]
    check("failed closure stays visibly open; cancelling forced closure keeps the interlock")
    send(b"f", "Premi F di nuovo")
    send(b"f", "Sessioni protette")
    assert not status()["session_open"]
    check("explicit TUI forced-close confirmation stops the VM before closing its volume")
    # Exit may draw only the busy screen, then clear; wait on the real child.
    os.write(master, b"q")
    while manager.poll() is None:
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            try:
                screen.extend(os.read(master, 65536))
            except OSError:
                break
    assert manager.wait(timeout=10) == 0
    assert not status()["general_open"] and not status()["session_open"]
    assert all(secret not in screen for secret in [GENERAL, PASSWORD, b"synthetic-session-password-b", b"incorrect-synthetic-password"])
    check("passwords never appear in terminal output and exit closes both encryption layers")
    daemon.terminate()
    daemon.wait(timeout=10)
    subprocess.run(["umount", "/data"], check=True)
    print("OBLIVION_VM_LAB_PASS", flush=True)
except BaseException:
    print("OBLIVION_VM_LAB_FAIL", flush=True)
    raise
finally:
    if manager.poll() is None:
        manager.kill()
        manager.wait(timeout=10)
    os.close(master)
