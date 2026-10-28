#!/usr/bin/env python3
"""Real manager, root worker, readonly import VM and encrypted recipient VM.

Only disposable synthetic disks are attached by run-vm-lab.py.
"""
import fcntl
import contextlib
import hashlib
import json
import os
import re
import select
import signal
import shlex
import shutil
import struct
import subprocess
import termios
import time
from pathlib import Path

CONFIG = "/run/oblivion-import-test.json"
GENERAL = b"synthetic-general-password"
PASSWORD = b"synthetic-session-password-a"
WORKER = "oblivion-transfer-host.service"
screen = bytearray()


def check(label):
    print("PASS: " + label, flush=True)


def systemctl(*args):
    return subprocess.check_output(["systemctl", *args], timeout=150).decode().strip()


def command(operation, *args, secret=b""):
    result = subprocess.run(["oblivion-storage-lab", "--config", CONFIG, operation, *args],
        input=secret, capture_output=True, timeout=150)
    assert result.returncode == 0, (operation, result.stderr)
    return result.stdout.decode().strip()


def status():
    return json.loads(command("status"))


def wait(marker):
    data = bytearray()
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        assert manager.poll() is None, ("manager exited", manager.returncode)
        if select.select([master], [], [], 0.1)[0]:
            chunk = os.read(master, 65536)
            screen.extend(chunk)
            data.extend(chunk)
            plain = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", data)
            if marker.encode() in plain:
                return bytes(plain)
            if b"Operazione non completata" in plain:
                raise AssertionError(("manager operation failed", marker, plain[-2500:]))
            if b"OBLIVION_GUEST_PROBE_FAILED" in plain:
                raise AssertionError(("guest probe failed", marker, plain[-2500:]))
    raise AssertionError(("screen timeout", marker, data[-2500:]))


def send(data, marker):
    os.write(master, data)
    return wait(marker)


def cleaned():
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if not Path("/run/oblivion/transfer.json").exists():
            break
        time.sleep(0.1)
    assert not Path("/run/oblivion/transfer.json").exists()
    assert not Path("/dev/mapper/oblivion-import").exists()
    assert not Path("/dev/mapper/oblivion-export").exists()
    assert systemctl("show", "oblivion-export-vm.service", "-p", "ActiveState", "--value") in ("inactive", "failed")
    assert systemctl("show", "oblivion-import-vm.service", "-p", "ActiveState", "--value") in ("inactive", "failed")
    assert not list(Path("/run/oblivion-session").glob("copy-*.sock"))


def offer():
    send(b"\x1e", "OBLIVION - DOCUMENT TRANSFERS")
    send(b"\r", "Relative USB path")
    send(b"documenti\r", "OBLIVION - CONFIRM IMPORT")
    return json.loads(Path("/run/oblivion/transfer.json").read_text())["id"]


def target_mount(filesystem, readonly=False):
    target = Path("/run/oblivion-export-check")
    target.mkdir(exist_ok=True)
    options = "ro" if readonly else "rw"
    options += ",nodev,nosuid,noexec"
    options += ",utf8=1" if filesystem == "vfat" else ",iocharset=utf8" if filesystem == "exfat" else ",noload" if readonly else ""
    subprocess.run(["mount", "-t", filesystem, "-o", options, "/dev/vdd", str(target)], check=True)
    return target


def format_target(filesystem, full=False):
    cleaned()
    # These are known disposable laboratory disks, never a production code path.
    args = ["mkfs.ext4", "-q", "-F", "-m", "0"] if filesystem == "ext4" else ["mkfs.vfat", "-F", "32", "--mbr=no"] if filesystem == "vfat" else ["mkfs.exfat"]
    subprocess.run([*args, "/dev/vdd"], check=True, stdout=subprocess.DEVNULL)
    assert not list(Path("/sys/class/block/vdd").glob("vdd*")), "fixture disk unexpectedly partitioned"
    target = target_mount(filesystem)
    try:
        (target / "existing.txt").write_bytes(b"OBLIVION_EXPORT_EXISTING_CANARY_f4a8")
        if full:
            with (target / "filler.bin").open("wb", buffering=0) as filler:
                try:
                    while True:
                        filler.write(bytes(1024 * 1024))
                except OSError as error:
                    assert error.errno == 28, error
                filler.truncate(max(0, filler.tell() - 1024 * 1024))
                os.fsync(filler.fileno())
            stats = os.statvfs(target)
            assert 0 < stats.f_bavail * stats.f_frsize < 2 * 1024 * 1024
    finally:
        subprocess.run(["umount", str(target)], check=True)


def exports(copied, mode="persistent", filesystem="ext4"):
    def target_hash():
        with Path("/dev/vdd").open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    def begin():
        send(b"\x1e", "OBLIVION - DOCUMENT TRANSFERS")
        send(b"j", "OBLIVION - DOCUMENT TRANSFERS")
        send(b"e", "Session path")
        authorization = send(f"imports/{copied}/files/documenti\r".encode(), "OBLIVION - AUTHORIZE USB WRITES")
        assert b"Destination: vdd " in authorization, authorization

    before = target_hash()
    begin()
    send(b"\x1b", "OBLIVION - DOCUMENT TRANSFERS")
    send(b"\x1b", "OBLIVION | SESSION OPEN")
    assert target_hash() == before
    cleaned()
    check(f"{mode} export cancellation before device-write authorization leaves the target disk byte-identical")
    begin()
    send(b"e", "OBLIVION - CONFIRM EXPORT")
    identifier = json.loads(Path("/run/oblivion/transfer.json").read_text())["id"]
    writer = systemctl("show", "oblivion-export-vm.service", "-p", "MainPID", "--value")
    argv = Path(f"/proc/{writer}/cmdline").read_bytes().split(b"\0")
    assert argv[argv.index(b"-nic") + 1] == b"none"
    assert any(b"oblivion-export,format=raw" in arg for arg in argv)
    assert not any(b"virtfs" in arg or b"9p" in arg or b"oblivion-session" in arg for arg in argv)
    assert subprocess.check_output(["blockdev", "--getro", "/dev/mapper/oblivion-export"]).strip() == b"0"
    assert "/target" not in Path("/proc/self/mountinfo").read_text()
    send(b"e", "Export completed")
    cleaned()
    assert not Path(f"/proc/{writer}").exists()
    # Inspect only this synthetic disk after detach, never production media.
    target = target_mount(filesystem, readonly=True)
    try:
        exported = target / f"Oblivion-{identifier}/files/imports/{copied}/files/documenti"
        assert (exported / "note.txt").read_bytes() == b"OBLIVION_USB_EDIT_CANARY_1b72"
        assert (exported / "caffè.txt").read_bytes() == b"OBLIVION_USB_SELECTED_CANARY_82f1"
        assert (exported / "vuota").is_dir()
        assert (target / "existing.txt").read_bytes() == b"OBLIVION_EXPORT_EXISTING_CANARY_f4a8"
    finally:
        subprocess.run(["umount", str(target)], check=True)
    send(b"\r", "OBLIVION | SESSION OPEN")
    guest("imports-resumed", "OBLIVION_IMPORT_RESUMED")
    check(f"{mode} manager export reports removal only after writer detach and cleanup")
    check(f"{mode} export preserves the existing USB document and the edited session original")
    if mode == "persistent":
        begin()
        send(b"e", "OBLIVION - CONFIRM EXPORT")
        writer = int(systemctl("show", "oblivion-export-vm.service", "-p", "MainPID", "--value"))
        os.kill(writer, signal.SIGSTOP)
        offset = len(screen)
        send(b"e", "Copying and verifying")
        send(b"\x1b", "Export interrotto senza conferma di smontaggio")
        cleaned()
        assert not status()["session_open"]
        assert b"Export completed" not in screen[offset:]
        assert b"You can remove the device" not in screen[offset:]
        send(b"\r", "Password della sessione")
        send(PASSWORD + b"\r", "OBLIVION_GUEST_READY")
        guest("imports-resumed", "OBLIVION_IMPORT_RESUMED")
        check("an interrupted writer never reports eject success and cleanup preserves the encrypted session original")
    return identifier


def export_faults():
    guest("export-faults", "OBLIVION_EXPORT_FAULTS_READY")
    for filesystem, fault, selection in [("ext4", "ENOSPC", "space"), ("vfat", "case collision", "collision"), ("exfat", "case collision", "collision")]:
        format_target(filesystem, full=fault == "ENOSPC")
        send(b"\x1e", "OBLIVION - DOCUMENT TRANSFERS")
        send(b"j", "OBLIVION - DOCUMENT TRANSFERS")
        send(b"e", "Session path")
        authorization = send(f"workspace/{selection}\r".encode(), "OBLIVION - AUTHORIZE USB WRITES")
        assert b"Destination: vdd " in authorization, authorization
        send(b"e", "OBLIVION - CONFIRM EXPORT")
        offset = len(screen)
        started = time.monotonic()
        send(b"e", "Export interrotto senza conferma di smontaggio")
        assert time.monotonic() - started < 45, "writer error must not await the 300-second relay deadline"
        cleaned()
        assert not status()["session_open"]
        assert b"Export completed" not in screen[offset:]
        assert b"You can remove the device" not in screen[offset:]
        target = target_mount(filesystem, readonly=True)
        try:
            assert not list(target.glob("Oblivion-*"))
            assert (target / "existing.txt").read_bytes() == b"OBLIVION_EXPORT_EXISTING_CANARY_f4a8"
        finally:
            subprocess.run(["umount", str(target)], check=True)
        send(b"\r", "Password della sessione")
        send(PASSWORD + b"\r", "OBLIVION_GUEST_READY")
        guest("export-originals", "OBLIVION_EXPORT_ORIGINALS")
        guest("imports-resumed", "OBLIVION_IMPORT_RESUMED")
        check(f"{filesystem} {fault} revokes the copy promptly, removes the private partial copy and preserves existing documents")


def guest(command_text, marker):
    send(command_text.encode() + b"\r", marker)


def session_terminal(mode="start", probe=None):
    # Real manager credentials, descriptor delegation, renderer and hvc1. This
    # does not obtain a host shell or a path to the session's filesystem.
    with subprocess.Popen(["oblivion-console", "--terminal-screen"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, user=1000, group=1000, extra_groups=[], env={"PATH": "/usr/bin:/bin", "HOME": "/run/oblivion-manager-home"}) as console, subprocess.Popen(
            ["/usr/libexec/oblivion-viewport-probe", "--screen"], stdin=console.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            user=1000, group=1000, extra_groups=[], env={}, bufsize=0) as decoder, contextlib.ExitStack() as cleanup:
        cleanup.callback(console.stdin.close)

        def send_frame(value):
            console.stdin.write(json.dumps(value).encode() + b"\n"); console.stdin.flush()

        def wait_frame(text):
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                assert console.poll() is None, console.stderr.read().decode()
                if not select.select([decoder.stdout], [], [], 0.1)[0]:
                    continue
                value = json.loads(decoder.stdout.readline())
                if value["type"] == "snapshot" and text in value["text"]:
                    return
                assert value["type"] in ("snapshot", "startup"), value
            raise AssertionError("session terminal did not reach " + text)

        send_frame({"type": "resize", "cols": 100, "rows": 30})
        wait_frame("TERMINAL")
        marker = "BACKUP_CHAT_PROBE_DONE" if probe else {"start": "TERMINAL_JOB_STARTED", "attached": "TERMINAL_JOB_CONTINUES", "reopened": "TERMINAL_REOPEN_VERIFIED", "backup": "BACKUP_METADATA_VERIFIED"}[mode]
        private = "printf '" + "".join(f"\\{byte:03o}" for byte in b"OBLIVION_VM_A_CANARY_4d02") + "'"
        command = "" if probe else (private + ' > /vault/workspace/terminal-controller.txt && ' if mode == "start" else
                   'test "$(cat /vault/workspace/terminal-controller.txt)" = "$(' + private + ')" && ')
        command += 'test "$(id -u)" = 1000 && test ! -e /run/oblivion-api/token && '
        if probe:
            command += 'python3 -B /usr/lib/oblivion/vm-backup-chat-probe.py ' + shlex.quote(probe) + ' && '
        elif mode == "backup":
            command += 'test ! -e /run/oblivion-terminal/controller-pid && python3 -c ' + shlex.quote('import json; from pathlib import Path; m=json.loads(Path("/vault/state/oblivion/session.json").read_text()); assert m["format"] == "oblivion-session" and m["version"] == 1 and m["title"] == "Backup fixture"') + ' && '
        elif mode == "attached":
            command += 'kill -0 "$(cat /run/oblivion-terminal/controller-pid)" && '
        else:
            command += 'test ! -e /run/oblivion-terminal/controller-pid && { sleep 600 & printf "%s" "$!" > /run/oblivion-terminal/controller-pid; } && '
        command += "printf '" + "".join(f"\\{byte:03o}" for byte in (marker + "\n").encode()) + "'\n"
        send_frame({"type": "input", "data": list(command.encode())})
        wait_frame(marker)
        console.stdin.close(); console.wait(timeout=5); decoder.wait(timeout=5)
        assert console.returncode == 0 and decoder.returncode == 0
    check("native backup chat probe: " + probe if probe else {"start": "session terminal runs nonroot without a key and detaches with its background job alive",
           "attached": "reattaching the real session terminal preserves its background job",
           "reopened": "reopened terminal preserves its workspace and has no previous boot's jobs",
           "backup": "backup metadata and the original workspace remain inside the session and are readable after reopening"}[mode])


print("OBLIVION_IMPORT_FIXTURE_SHA256 " + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), flush=True)
os.umask(0o077)
subprocess.run(["mkfs.ext4", "-q", "-m", "0", "/dev/vdb"], check=True)
subprocess.run(["mount", "/dev/vdb", "/data"], check=True)
vm = {"root": "/usr/lib/oblivion/vm/qemu-root", "kernel": "/usr/lib/oblivion/vm/kernel",
    "initrd": "/usr/lib/oblivion/vm/initrd", "filesystem": "/usr/lib/oblivion/vm/guest.squashfs",
    "memory_mib": 768, "cpus": 2, "accelerator": "tcg"}
export_lab = Path("/usr/lib/oblivion/vm/export-lab").exists()
backup_lab = "oblivion.lab-backup=1" in Path("/proc/cmdline").read_text().split()
backup_chats = backup_lab and Path("/usr/lib/oblivion/vm/backup-chat-lab").exists()
Path(CONFIG).write_text(json.dumps({"general_image": "/data/general.luks", "general_mib": 1536 if backup_lab else 768,
    "session_mib": 512 if backup_lab else 128, "pbkdf_memory_kib": 65536, "manager_uid": 1000, "vm": vm,
    "import": {**vm, "filesystem": "/usr/lib/oblivion/vm/import.squashfs"},
    "export": {**vm, "filesystem": "/usr/lib/oblivion/vm/export.squashfs"} if export_lab else None}))
dropin = Path("/run/systemd/system") / (WORKER + ".d")
dropin.mkdir(parents=True)
dropin.joinpath("lab.conf").write_text("[Service]\nStandardError=journal\nExecStart=\nExecStopPost=\n"
    f"ExecStart=/usr/bin/oblivion-storage-lab --config {CONFIG} transfer-host-run\n"
    f"ExecStopPost=/usr/bin/oblivion-storage-lab --config {CONFIG} transfer-cleanup\n")
systemctl("daemon-reload")
command("init-general", secret=GENERAL)
daemon = subprocess.Popen(["oblivion-storage-lab", "--config", CONFIG, "serve"],
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


manager = subprocess.Popen(["oblivion-manager"], stdin=slave, stdout=slave, stderr=slave,
    user=1000, group=1000, extra_groups=[], preexec_fn=terminal_session,
    env={"TERM": "linux", "PATH": "/usr/bin:/bin", "HOME": "/run/oblivion-manager-home"})
os.close(slave)


def backup_probe():
    assert export_lab
    identifier = status()["active_session"]
    session_terminal()
    if backup_chats:
        session_terminal(probe="seed")
        command("leave")
    else:
        send(b"\x1d", "Sessioni protette")
    command("rename-session", secret=json.dumps({"id": identifier, "title": "Backup fixture"}).encode())
    volume = Path("/run/oblivion/general/sessions") / (identifier + ".luks")
    def volume_hash(path):
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    before = volume_hash(volume)
    target_id = Path("/sys/class/block/vdd/dev").read_text().strip()
    invalid = subprocess.run(["oblivion-storage-lab", "--config", CONFIG, "transfers"],
        input=json.dumps({"operation": "backup", "id": identifier, "target": target_id, "password": "incorrect-password"}).encode(), capture_output=True, timeout=150)
    assert invalid.returncode != 0 and not status()["session_open"]
    assert volume_hash(volume) == before
    cleaned()
    check("wrong backup password leaves the original encrypted volume unchanged and closed")
    format_target("ext4")
    peer_code = '''import json,socket,struct,sys
p=json.loads(sys.stdin.readline()); s=socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect("/run/oblivion-transfer-host/control.sock")
def send(value):
 b=json.dumps(value,separators=(",",":")).encode(); s.sendall(struct.pack(">I",len(b))+b)
def read(n):
 b=b""
 while len(b)<n:
  chunk=s.recv(n-len(b)); assert chunk; b+=chunk
 return b
send({"id":p["id"],"paths":p.get("paths",["session.oblivion"]),"limits":{"entries":1,"bytes":p["bytes"]}})
assert read(8)==b"OBLVCP01"; encoded=read(struct.unpack(">I",read(4))[0]); manifest=json.loads(encoded)
assert len(manifest)==1 and manifest[0]["path"]=="session.oblivion" and manifest[0]["size"]==p.get("expected_bytes",p["bytes"])
print(json.dumps({"offered":True}),flush=True)
assert sys.stdin.readline().strip()=="approve"
send({"id":p["id"],"manifest_sha256":__import__("hashlib").sha256(encoded).hexdigest()})
print(json.dumps({"approved":True}),flush=True)
print(read(struct.unpack(">I",read(4))[0]).decode(),flush=True)
'''
    # The ordinary fixture qualifies all copy-owner failure modes. The native
    # fixture adds database portability and malformed-volume checks separately.
    for mode in (("copy",) if backup_chats else ("copy", "cancel", "owner-death")):
        result = subprocess.run(["oblivion-control", "transfers"],
            input=json.dumps({"operation": "backup", "id": identifier, "target": target_id, "password": PASSWORD.decode()}).encode(),
            capture_output=True, user=1000, group=1000, extra_groups=[], timeout=150)
        assert result.returncode == 0, result.stderr
        started = json.loads(result.stdout)
        assert started["bytes"] == 512 * 1024 * 1024
        assert not status()["session_open"] and systemctl("show", "oblivion-session.service", "-p", "ActiveState", "--value") in ("inactive", "failed")
        record = Path("/run/oblivion/transfer.json").read_bytes()
        assert PASSWORD not in record and GENERAL not in record and b"Backup fixture" not in record
        locked = volume_hash(volume)
        peer = subprocess.Popen(["python3", "-c", peer_code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            user=1000, group=1000, extra_groups=[], env={}, bufsize=0)
        try:
            peer.stdin.write(json.dumps(started).encode() + b"\n"); peer.stdin.flush()
            assert json.loads(peer.stdout.readline())["offered"]
            owner = int(systemctl("show", WORKER, "-p", "MainPID", "--value"))
            children = Path(f"/proc/{owner}/task/{owner}/children").read_text().split()
            assert len(children) == 1
            child = int(children[0])
            child_status = Path(f"/proc/{child}/status").read_text()
            assert re.search(r"^Uid:\s+65534\s+65534", child_status, re.M) and "NoNewPrivs:\t1" in child_status
            assert re.search(r"^CapEff:\s+0+$", child_status, re.M)
            argv = Path(f"/proc/{child}/cmdline").read_bytes()
            assert PASSWORD not in argv and identifier.encode() not in argv and b"/run/oblivion/general" not in argv
            # An active backup may not race a new session opening.
            blocked = subprocess.run(["oblivion-storage-lab", "--config", CONFIG, "open", identifier], input=PASSWORD, capture_output=True, timeout=30)
            assert blocked.returncode != 0 and b"backup_active" in blocked.stderr
            if mode == "owner-death":
                os.kill(child, signal.SIGKILL)
                peer.kill(); peer.wait(timeout=5)
            else:
                if mode == "cancel": os.kill(child, signal.SIGSTOP)
                peer.stdin.write(b"approve\n"); peer.stdin.flush()
                assert json.loads(peer.stdout.readline())["approved"]
                if mode == "cancel":
                    peer.kill(); peer.wait(timeout=5)
                else:
                    receipt = json.loads(peer.stdout.readline())
                    assert receipt["id"] == started["id"] and receipt["bytes"] == started["bytes"]
                    peer.stdin.close(); assert peer.wait(timeout=5) == 0
            command("transfers", secret=b'{"operation":"cancel"}')
            cleaned()
            assert not Path(f"/proc/{child}").exists()
            assert volume_hash(volume) == locked
            if mode == "copy":
                backup_path = f"Oblivion-{started['id']}/files/session.oblivion"
                backup_digest = locked
                target = target_mount("ext4", readonly=True)
                try:
                    copied = target / f"Oblivion-{started['id']}/files/session.oblivion"
                    assert copied.stat().st_size == started["bytes"]
                    with copied.open("rb") as source:
                        assert hashlib.file_digest(source, "sha256").hexdigest() == locked
                    assert (target / "existing.txt").read_bytes() == b"OBLIVION_EXPORT_EXISTING_CANARY_f4a8"
                    with copied.open("rb") as source:
                        tail = b""
                        while data := source.read(128 * 1024):
                            assert b"Backup fixture" not in tail + data and PASSWORD not in tail + data
                            tail = data[-64:]
                finally:
                    subprocess.run(["umount", str(target)], check=True)
            check("closed 512 MiB LUKS backup: " + mode + " verifies descriptor confinement, original preservation and worker cleanup")
        finally:
            if peer.poll() is None: peer.kill(); peer.wait(timeout=5)
            if peer.stdin and not peer.stdin.closed: peer.stdin.close()
            peer.stdout.close(); peer.stderr.close()
    original = volume_hash(volume)
    source_disk = volume_hash(Path("/dev/vdd"))
    for cancel in (True, False):
        started = json.loads(command("transfers", secret=json.dumps({"operation": "restore", "source": target_id}).encode()))
        pending = volume.with_name(started["id"] + ".pending")
        record = volume.with_name(started["id"] + ".restore")
        peer = subprocess.Popen(["python3", "-c", peer_code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            user=1000, group=1000, extra_groups=[], env={}, bufsize=0)
        try:
            peer.stdin.write(json.dumps({**started, "paths": [backup_path], "expected_bytes": 512 * 1024 ** 2}).encode() + b"\n"); peer.stdin.flush()
            line = peer.stdout.readline()
            assert line, peer.stderr.read()
            assert json.loads(line)["offered"]
            assert not status()["session_open"] and started["id"] not in status()["sessions"]
            if cancel:
                peer.kill(); peer.wait(timeout=5)
            else:
                peer.stdin.write(b"approve\n"); peer.stdin.flush()
                assert json.loads(peer.stdout.readline())["approved"]
                receipt = json.loads(peer.stdout.readline())
                assert receipt["id"] == started["id"] and receipt["bytes"] == 512 * 1024 ** 2
                peer.stdin.close(); assert peer.wait(timeout=5) == 0
            command("transfers", secret=b'{"operation":"cancel"}')
            cleaned()
            assert not status()["session_open"] and volume_hash(volume) == original
            assert volume_hash(Path("/dev/vdd")) == source_disk
            if cancel:
                assert not pending.exists() and not record.exists()
                check("cancelling restore removes its private pending volume and preserves both sources")
                continue
            assert volume_hash(pending) == backup_digest and record.is_file()
            invalid = subprocess.run(["oblivion-storage-lab", "--config", CONFIG, "transfers"],
                input=json.dumps({"operation": "restore-finish", "id": started["id"], "password": "incorrect-password"}).encode(), capture_output=True, timeout=150)
            assert invalid.returncode != 0 and volume_hash(pending) == backup_digest
            assert not status()["session_open"] and started["id"] not in status()["sessions"]
            check("wrong restore password preserves the verified pending copy for retry without publication")
            command("transfers", secret=json.dumps({"operation": "restore-finish", "id": started["id"], "password": PASSWORD.decode()}).encode())
            restored = started["id"]
            assert restored != identifier and set(status()["sessions"]) == {identifier, restored}
            assert status()["session_titles"][restored] == "Backup fixture"
            assert not pending.exists() and not record.exists() and not status()["session_open"]
            command("transfers", secret=json.dumps({"operation": "restore-discard", "id": restored}).encode())
            assert restored in status()["sessions"] and status()["session_titles"][restored] == "Backup fixture"
            command("enter-documents", restored, secret=PASSWORD)
            session_terminal("backup")
            if backup_chats: session_terminal(probe="verify")
            command("leave")
            assert volume_hash(volume) == original and volume_hash(Path("/dev/vdd")) == source_disk
            check("restore creates a separate titled archive entry and offline workspace while preserving the original archive and backup medium")
        finally:
            if peer.poll() is None: peer.kill(); peer.wait(timeout=5)
            if peer.stdin and not peer.stdin.closed: peer.stdin.close()
            peer.stdout.close(); peer.stderr.close()
    command("enter-documents", identifier, secret=PASSWORD)
    session_terminal("backup")
    if backup_chats: session_terminal(probe="verify")
    command("leave")
    if backup_chats:
        fault_restore_probe(peer_code, target_id, volume, volume_hash(volume), backup_path)
    command("lock")
    assert not status()["general_open"] and not status()["session_open"]
    check("backup preparation and copy need no provider key or network gateway")
    print("OBLIVION_VM_LAB_PASS", flush=True)


def fault_restore_probe(peer_code, source, original, original_hash, backup_path):
    configuration = json.loads(Path(CONFIG).read_text())
    Path(CONFIG).write_text(json.dumps({**configuration, "session_mib": 128}))
    fault = command("create", secret=PASSWORD)
    fault_volume = original.with_name(fault + ".luks")
    for action, filename in (("future", "future.oblivion"), ("corrupt-db", "database.oblivion")):
        command("enter-documents", fault, secret=PASSWORD)
        session_terminal(probe=action)
        command("leave")
        target = target_mount("ext4")
        try:
            shutil.copyfile(fault_volume, target / filename)
            with (target / filename).open("rb") as stream: os.fsync(stream.fileno())
        finally:
            subprocess.run(["umount", str(target)], check=True)
    Path(CONFIG).write_text(json.dumps(configuration))
    target = target_mount("ext4")
    try:
        with (target / "header.oblivion").open("wb") as stream:
            stream.write(b"LUKS\xba\xbe\x00\x02"); stream.truncate(32 * 1024 ** 2); stream.flush(); os.fsync(stream.fileno())
        with (target / backup_path).open("rb") as stream, (target / "truncated.oblivion").open("wb") as partial:
            remaining = 32 * 1024 ** 2
            while remaining:
                block = stream.read(min(128 * 1024, remaining)); assert block
                partial.write(block); remaining -= len(block)
            partial.flush(); os.fsync(partial.fileno())
    finally:
        subprocess.run(["umount", str(target)], check=True)
    def digest(path):
        with path.open("rb") as stream: return hashlib.file_digest(stream, "sha256").hexdigest()
    before = set(status()["sessions"])
    disk_hash = digest(Path("/dev/vdd"))
    for filename, size, error in (("future.oblivion", 128, b"unsupported_backup_version"),
            ("database.oblivion", 128, b"invalid_backup_database"),
            ("header.oblivion", 32, None), ("truncated.oblivion", 32, None)):
        started = json.loads(command("transfers", secret=json.dumps({"operation": "restore", "source": source}).encode()))
        peer = subprocess.Popen(["python3", "-c", peer_code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            user=1000, group=1000, extra_groups=[], env={}, bufsize=0)
        try:
            peer.stdin.write(json.dumps({**started, "paths": [filename], "expected_bytes": size * 1024 ** 2}).encode() + b"\n"); peer.stdin.flush()
            line = peer.stdout.readline(); assert line, peer.stderr.read()
            assert json.loads(line)["offered"]
            peer.stdin.write(b"approve\n"); peer.stdin.flush()
            assert json.loads(peer.stdout.readline())["approved"]
            assert json.loads(peer.stdout.readline())["bytes"] == size * 1024 ** 2
            peer.stdin.close(); assert peer.wait(timeout=5) == 0
        finally:
            if peer.poll() is None: peer.kill(); peer.wait(timeout=5)
            if peer.stdin and not peer.stdin.closed: peer.stdin.close()
            peer.stdout.close(); peer.stderr.close()
        command("transfers", secret=b'{"operation":"cancel"}')
        cleaned()
        result = subprocess.run(["oblivion-storage-lab", "--config", CONFIG, "transfers"],
            input=json.dumps({"operation": "restore-finish", "id": started["id"], "password": PASSWORD.decode()}).encode(),
            capture_output=True, timeout=360)
        assert result.returncode != 0, filename
        if error: assert error in result.stderr, (filename, result.stderr)
        if status()["recovery_required"]:
            command("force-leave"); command("recover"); command("unlock", secret=GENERAL)
        assert not status()["session_open"] and set(status()["sessions"]) == before
        command("transfers", secret=json.dumps({"operation": "restore-discard", "id": started["id"]}).encode())
        assert not original.with_name(started["id"] + ".pending").exists()
        assert digest(original) == original_hash and digest(Path("/dev/vdd")) == disk_hash
        check("restore rejects " + filename + " without publication and preserves original archive/source media")
    reserve = Path("/run/oblivion/general/space-fixture")
    stats = os.statvfs(reserve.parent)
    try:
        with reserve.open("xb") as stream:
            os.posix_fallocate(stream.fileno(), 0, stats.f_bavail * stats.f_frsize - 24 * 1024 ** 2)
        result = subprocess.run(["oblivion-storage-lab", "--config", CONFIG, "transfers"],
            input=json.dumps({"operation": "restore", "source": source}).encode(), capture_output=True, timeout=30)
        assert result.returncode != 0 and b"insufficient_restore_space" in result.stderr
        assert set(status()["sessions"]) == before and not Path("/dev/mapper/oblivion-import").exists()
    finally:
        reserve.unlink()
    check("insufficient general-vault space refuses restore before starting a source VM or creating a pending volume")


def execute_test():
    wait("Archivio generale bloccato")
    send(b"\r", "Password del volume generale")
    send(GENERAL + b"\r", "Nessuna sessione")
    if backup_chats:
        identifier = command("create", secret=PASSWORD)
        command("enter-documents", identifier, secret=PASSWORD)
        backup_probe()
        return
    send(b"n", "Nuova sessione - password")
    send(PASSWORD + b"\r", "Ripeti la password")
    send(PASSWORD + b"\r", "OBLIVION_GUEST_READY")
    session_pid = systemctl("show", "oblivion-session.service", "-p", "MainPID", "--value")
    if backup_lab:
        backup_probe()
        return
    if "oblivion.lab-terminal=1" in Path("/proc/cmdline").read_text().split():
        terminal_owner = os.pidfd_open(int(session_pid))
        session_terminal()
        guest("terminal-live", "OBLIVION_TERMINAL_JOB_ALIVE")
        session_terminal("attached")
        send(b"\x1d", "Sessioni protette")
        assert select.select([terminal_owner], [], [], 0)[0]
        os.close(terminal_owner)
        assert not Path("/dev/mapper/oblivion-session").exists()
        check("normal close reaps all terminal jobs before the session volume is locked")
        send(b"\r", "Password della sessione")
        send(PASSWORD + b"\r", "OBLIVION_GUEST_READY")
        session_terminal("reopened")
        terminal_owner = os.pidfd_open(int(systemctl("show", "oblivion-session.service", "-p", "MainPID", "--value")))
        send(b"\x1d", "Sessioni protette")
        assert select.select([terminal_owner], [], [], 0)[0]
        os.close(terminal_owner)
        send(b"b", "Archivio generale bloccato")
        assert not status()["session_open"] and not status()["general_open"]
        print("OBLIVION_VM_LAB_PASS", flush=True)
        return
    send(b"\x1e", "OBLIVION - DOCUMENT TRANSFERS")
    listing = send(b"u", "OBLIVION - SESSION COPIES")
    assert b"Private, not delivered" in listing and b"00000000" in listing
    cleaned()
    send(b"d", "Permanently delete private copy")
    send(b"\x1b", "OBLIVION - SESSION COPIES")
    send(b"d", "Permanently delete private copy")
    send(b"d", "No copies recorded")
    cleaned()
    send(b"\x1b", "OBLIVION | SESSION OPEN")
    check("manager detects a SIGKILL-interrupted receiver and deletes its private copy only after confirmation")
    first = offer()
    assert status()["session_open"]
    source_pid = systemctl("show", "oblivion-import-vm.service", "-p", "MainPID", "--value")
    argv = Path(f"/proc/{source_pid}/cmdline").read_bytes().split(b"\0")
    assert argv[argv.index(b"-nic") + 1] == b"none"
    assert any(b"oblivion-import,format=raw" in arg and b"readonly=on" in arg for arg in argv)
    assert not any(b"virtfs" in arg or b"9p" in arg or b"oblivion-session" in arg for arg in argv)
    assert Path(f"/proc/{source_pid}/root/dev/oblivion-import").stat().st_mode & 0o777 == 0o400
    assert subprocess.check_output(["blockdev", "--getro", "/dev/mapper/oblivion-import"]).strip() == b"1"
    assert "/source" not in Path("/proc/self/mountinfo").read_text()
    check("manager opens a readonly networkless import VM without sharing a filesystem")
    send(b"\x1b", "OBLIVION | SESSION OPEN")
    cleaned()
    guest("imports-empty", "OBLIVION_IMPORTS_EMPTY")
    assert systemctl("show", "oblivion-session.service", "-p", "MainPID", "--value") == session_pid
    check("cancelling the manifest destroys the source VM and leaves the active chat unchanged")
    copied = offer()
    assert copied != first
    send(b"i", "Import verified")
    print("STEP: import receipt verified", flush=True)
    send(b"\r", "OBLIVION | SESSION OPEN")
    cleaned()
    guest("imports-check", "OBLIVION_IMPORT_VERIFIED")
    check("confirmed files are verified, group-editable and visible only inside the session")
    send(b"\x1e", "OBLIVION - DOCUMENT TRANSFERS")
    listing = send(b"u", "OBLIVION - SESSION COPIES")
    assert b"Published, editable by the chat" in listing and copied.encode() in listing
    cleaned()
    # D is deliberately unavailable for an exposed copy, including edited files.
    listing = send(b"d", "OBLIVION - SESSION COPIES")
    assert b"Permanently delete private copy" not in listing
    send(b"\x1b", "OBLIVION | SESSION OPEN")
    guest("imports-resumed", "OBLIVION_IMPORT_RESUMED")
    check("reconciliation reads a private durable receipt without rehashing or deleting later chat edits")
    if export_lab:
        exports(copied)
        export_faults()
        format_target("ext4")
    terminal_owner = os.pidfd_open(int(systemctl("show", "oblivion-session.service", "-p", "MainPID", "--value")))
    session_terminal()
    session_terminal("attached")
    offer()
    assert not select.select([terminal_owner], [], [], 0)[0]
    source_pid = int(systemctl("show", "oblivion-import-vm.service", "-p", "MainPID", "--value"))
    os.kill(source_pid, signal.SIGKILL)
    wait("Operazione non completata")
    cleaned()
    assert not status()["session_open"]
    assert select.select([terminal_owner], [], [], 0)[0]
    os.close(terminal_owner)
    check("failure closure reaps the VM containing every terminal job before reporting the volume locked")
    check("source VM death invalidates approval and closes the session through the manager")
    # Reopen the same volume and verify persistence of the chat's file edit.
    send(b"\r", "Password della sessione")
    send(PASSWORD + b"\r", "OBLIVION_GUEST_READY")
    guest("imports-resumed", "OBLIVION_IMPORT_RESUMED")
    session_terminal("reopened")
    terminal_owner = os.pidfd_open(int(systemctl("show", "oblivion-session.service", "-p", "MainPID", "--value")))
    check("imported documents and later edits survive a fresh VM and LUKS reopening")
    send(b"\x1e", "OBLIVION - DOCUMENT TRANSFERS")
    listing = send(b"u", "OBLIVION - SESSION COPIES")
    assert b"Published, editable by the chat" in listing and copied.encode() in listing
    assert b"Private, not delivered" not in listing
    cleaned()
    send(b"b", "Archivio generale bloccato")
    assert select.select([terminal_owner], [], [], 0)[0]
    os.close(terminal_owner)
    assert not Path("/dev/mapper/oblivion-session").exists()
    check("explicit lock reaps the terminal job's VM and closes its LUKS mapping")
    send(b"\r", "Password del volume generale")
    send(GENERAL + b"\r", "Sessioni protette")
    send(b"\r", "Password della sessione")
    send(PASSWORD + b"\r", "OBLIVION_GUEST_READY")
    check("receipt and confirmed cleanup survive LUKS reopening and the recovery menu can lock both volumes")
    offer()
    frozen = int(systemctl("show", "oblivion-session.service", "-p", "MainPID", "--value"))
    os.kill(frozen, signal.SIGSTOP)
    send(b"\x1b", "Operazione non completata")
    assert status()["session_open"]
    send(b"f", "Premi F di nuovo")
    send(b"f", "Sessioni protette")
    cleaned()
    assert not status()["session_open"]
    check("an unresponsive recipient stays interlocked until explicit forced closure reaps both VMs")
    send(b"\r", "Password della sessione")
    send(PASSWORD + b"\r", "OBLIVION_GUEST_READY")
    offer()
    send(b"b", "Archivio generale bloccato")
    cleaned()
    assert not status()["general_open"] and not status()["session_open"]
    check("blocking from the approval screen revokes the copy before both LUKS volumes close")
    with Path("/data/general.luks").open("rb") as general:
        saved = hashlib.file_digest(general, "sha256").hexdigest()
    send(b"e", "Password del volume generale")
    send(GENERAL + b"\r", "Avvio effimero")
    send(b"n", "OBLIVION_GUEST_READY")
    guest("imports-empty", "OBLIVION_IMPORTS_EMPTY")
    ephemeral_copy = offer()
    send(b"i", "Import verified")
    send(b"\r", "OBLIVION | SESSION OPEN")
    cleaned()
    guest("imports-check", "OBLIVION_IMPORT_VERIFIED")
    if export_lab:
        exports(ephemeral_copy, "ephemeral")
    send(b"\x1d", "Avvio effimero")
    assert not Path("/run/oblivion/ephemeral.luks").exists()
    send(b"b", "Archivio generale bloccato")
    with Path("/data/general.luks").open("rb") as general:
        assert hashlib.file_digest(general, "sha256").hexdigest() == saved
    check("ephemeral import and edits disappear at closure with the persistent general byte-identical")
    if export_lab:
        for filesystem in ["vfat", "exfat"]:
            format_target(filesystem)
            send(b"e", "Password del volume generale")
            send(GENERAL + b"\r", "Avvio effimero")
            send(b"n", "OBLIVION_GUEST_READY")
            copied = offer()
            send(b"i", "Import verified")
            send(b"\r", "OBLIVION | SESSION OPEN")
            cleaned()
            guest("imports-check", "OBLIVION_IMPORT_VERIFIED")
            identifier = exports(copied, "ephemeral " + filesystem, filesystem)
            with Path("/dev/vdd").open("rb") as stream:
                source_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            send(b"\x1e", "OBLIVION - DOCUMENT TRANSFERS")
            send(b"j", "OBLIVION - DOCUMENT TRANSFERS")
            send(b"\r", "Relative USB path")
            send(f"Oblivion-{identifier}/files/imports/{copied}/files/documenti\r".encode(), "OBLIVION - CONFIRM IMPORT")
            send(b"i", "Import verified")
            send(b"\r", "OBLIVION | SESSION OPEN")
            cleaned()
            guest("imports-roundtrip", "OBLIVION_IMPORT_ROUNDTRIP")
            with Path("/dev/vdd").open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == source_hash
            send(b"\x1d", "Avvio effimero")
            assert not Path("/run/oblivion/ephemeral.luks").exists()
            send(b"b", "Archivio generale bloccato")
            with Path("/data/general.luks").open("rb") as general:
                assert hashlib.file_digest(general, "sha256").hexdigest() == saved
            check(f"{filesystem} roundtrip preserves UTF-8 names and bytes, leaves the source unchanged and writes no persistent general state")
    assert GENERAL not in screen and PASSWORD not in screen
    assert b"OBLIVION_USB_SELECTED_CANARY_82f1" not in screen
    check("manager output contains neither document payloads nor volume passwords")
    print("OBLIVION_VM_LAB_PASS", flush=True)
try:
    execute_test()
except BaseException:
    print(bytes(screen[-5000:]).decode(errors="replace"), flush=True)
    subprocess.run(["systemctl", "status", WORKER, "oblivion-import-vm.service", "oblivion-session.service", "--no-pager"])
    subprocess.run(["journalctl", "-u", WORKER, "--no-pager"])

    raise
finally:
    manager.kill()
    manager.wait()
    daemon.terminate()
    daemon.wait(timeout=10)
    os.close(master)
