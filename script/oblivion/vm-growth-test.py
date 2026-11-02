#!/usr/bin/env python3
"""Real controller, LUKS and maintenance guest; synthetic disposable volumes only."""
import hashlib
import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path

CONFIG = "/run/oblivion-growth-test.json"
BINARY = "/usr/bin/oblivion-storage-lab"
PASSWORD = "synthetic-session-password"
GENERAL = b"synthetic-general-password"


def command(operation, *arguments, secret=b"", fails=False):
    result = subprocess.run([BINARY, "--config", CONFIG, operation, *arguments],
                            input=secret, capture_output=True, timeout=600)
    assert (result.returncode != 0) == fails, (operation, result.stderr)
    return result.stdout.decode().strip()


def storage(action, **fields):
    return command("session-storage", secret=json.dumps({"action": action, **fields}).encode())


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def wait(peer, marker):
    data = b""
    while marker.encode() not in data:
        chunk = peer.recv(65536)
        assert chunk, ("guest disconnected", data[-1000:])
        data = (data + chunk)[-65536:]


def conversation(id, commands):
    command("enter", id, secret=PASSWORD.encode())
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(300)
        peer.connect("/run/oblivion-session/console.sock")
        wait(peer, "OBLIVION_GUEST_READY")
        for text, marker in commands:
            peer.sendall((text + "\n").encode())
            wait(peer, marker)
        command("leave")


def maintenance_console():
    deadline = time.monotonic() + 60
    while not Path("/run/oblivion-session/console.sock").exists():
        assert time.monotonic() < deadline
        time.sleep(0.1)
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(600)
        peer.connect("/run/oblivion-session/console.sock")
        data = b""
        while chunk := peer.recv(65536):
            data = (data + chunk)[-8192:]
        if data:
            print(data.decode(errors="replace"), flush=True)


def run():
    os.umask(0o077)
    subprocess.run(["mkfs.ext4", "-q", "-m", "0", "/dev/vdb"], check=True)
    subprocess.run(["mount", "/dev/vdb", "/data"], check=True)
    Path(CONFIG).write_text(json.dumps({
        "general_image": "/data/general.luks", "general_mib": 768,
        "session_mib": 512, "pbkdf_memory_kib": 65536, "manager_uid": 1000,
        "vm": {"root": "/usr/lib/oblivion/vm/qemu-root", "kernel": "/usr/lib/oblivion/vm/kernel",
               "initrd": "/usr/lib/oblivion/vm/initrd", "filesystem": "/usr/lib/oblivion/vm/guest.squashfs",
               "memory_mib": 1536, "cpus": 2, "accelerator": "tcg"},
    }))
    command("init-general", secret=GENERAL)
    command("unlock", secret=GENERAL)
    id = storage("create", mib=128, password=PASSWORD)
    command("rename-session", secret=json.dumps({"id": id, "title": "Growth persistence"}).encode())
    chat = Path("/usr/lib/oblivion/vm/chat-lab").exists()
    conversation(id, [("write-a", "OBLIVION_A_WRITTEN")] + ([("chat-a", "OBLIVION_CHAT_CREATED")] if chat else []))
    path = Path(f"/run/oblivion/general/sessions/{id}.luks")
    original = digest(path)
    for fields in [{"mib": 512, "password": "wrong"}, {"mib": 128, "password": PASSWORD}, {"mib": 768, "password": PASSWORD}]:
        command("session-storage", secret=json.dumps({"action": "grow", "id": id, **fields}).encode(), fails=True)
        assert digest(path) == original and not path.with_suffix(".growing").exists()
    print("PASS: wrong passwords, shrinking and insufficient replacement space leave the original unchanged", flush=True)
    monitor = threading.Thread(target=maintenance_console, daemon=True)
    monitor.start()
    try:
        storage("grow", id=id, mib=512, password=PASSWORD)
    finally:
        monitor.join(timeout=5)
    state = json.loads(command("status"))
    assert state["session_bytes"] == 512 * 1048576 and state["session_sizes"][id] == 512 * 1048576
    assert not state["session_open"] and state["vm_state"] == "inactive" and state["pending_growth"] == []
    assert state["session_titles"][id] == "Growth persistence"
    print("PASS: controller publishes the verified enlarged volume and removes the maintenance VM and copy", flush=True)
    command("lock")
    command("unlock", secret=GENERAL)
    conversation(id, [("check-a", "OBLIVION_A_RESTORED")] + ([("chat-resume", "OBLIVION_CHAT_RESUMED")] if chat else []))
    command("enter-documents", id, secret=PASSWORD.encode())
    usage = json.loads(storage("usage"))["usage"]
    assert usage["capacity"] > 400 * 1048576 and usage["available"] > 200 * 1048576
    command("leave")
    print("PASS: password, title, documents and conversation survive growth and full lock/reopen", flush=True)
    command("lock")
    subprocess.run(["umount", "/data"], check=True)
    print("OBLIVION_VM_LAB_PASS", flush=True)


try:
    run()
except BaseException:
    subprocess.run(["journalctl", "-u", "oblivion-session.service", "--no-pager", "-n", "30"])
    print("OBLIVION_VM_LAB_FAIL", flush=True)
    raise
