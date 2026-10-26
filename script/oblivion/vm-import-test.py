#!/usr/bin/env python3
"""Real manager, root worker, readonly import VM and encrypted recipient VM.

Only disposable synthetic disks are attached by run-vm-lab.py.
"""
import fcntl
import hashlib
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
    send(b"\x1e", "OBLIVION - importa documenti")
    send(b"\r", "Percorso relativo sulla USB")
    send(b"documenti\r", "OBLIVION - conferma importazione")
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
        send(b"\x1e", "OBLIVION - importa documenti")
        send(b"j", "OBLIVION - importa documenti")
        send(b"e", "Percorso nella sessione")
        authorization = send(f"imports/{copied}/files/documenti\r".encode(), "OBLIVION - autorizza USB in scrittura")
        assert b"Destinazione: vdd " in authorization, authorization

    before = target_hash()
    begin()
    send(b"\x1b", "OBLIVION - importa documenti")
    send(b"\x1b", "OBLIVION | SESSIONE APERTA")
    assert target_hash() == before
    cleaned()
    check(f"{mode} export cancellation before device-write authorization leaves the target disk byte-identical")
    begin()
    send(b"e", "OBLIVION - conferma esportazione")
    identifier = json.loads(Path("/run/oblivion/transfer.json").read_text())["id"]
    writer = systemctl("show", "oblivion-export-vm.service", "-p", "MainPID", "--value")
    argv = Path(f"/proc/{writer}/cmdline").read_bytes().split(b"\0")
    assert argv[argv.index(b"-nic") + 1] == b"none"
    assert any(b"oblivion-export,format=raw" in arg for arg in argv)
    assert not any(b"virtfs" in arg or b"9p" in arg or b"oblivion-session" in arg for arg in argv)
    assert subprocess.check_output(["blockdev", "--getro", "/dev/mapper/oblivion-export"]).strip() == b"0"
    assert "/target" not in Path("/proc/self/mountinfo").read_text()
    send(b"e", "Esportazione completata")
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
    send(b"\r", "OBLIVION | SESSIONE APERTA")
    guest("imports-resumed", "OBLIVION_IMPORT_RESUMED")
    check(f"{mode} manager export reports removal only after writer detach and cleanup")
    check(f"{mode} export preserves the existing USB document and the edited session original")
    if mode == "persistent":
        begin()
        send(b"e", "OBLIVION - conferma esportazione")
        writer = int(systemctl("show", "oblivion-export-vm.service", "-p", "MainPID", "--value"))
        os.kill(writer, signal.SIGSTOP)
        offset = len(screen)
        send(b"e", "Copia e verifica in corso")
        send(b"\x1b", "Export interrotto senza conferma di smontaggio")
        cleaned()
        assert not status()["session_open"]
        assert b"Esportazione completata" not in screen[offset:]
        assert b"Puoi rimuovere il supporto" not in screen[offset:]
        send(b"\r", "Password della sessione")
        send(PASSWORD + b"\r", "OBLIVION_GUEST_READY")
        guest("imports-resumed", "OBLIVION_IMPORT_RESUMED")
        check("an interrupted writer never reports eject success and cleanup preserves the encrypted session original")
    return identifier


def export_faults():
    guest("export-faults", "OBLIVION_EXPORT_FAULTS_READY")
    for filesystem, fault, selection in [("ext4", "ENOSPC", "space"), ("vfat", "case collision", "collision"), ("exfat", "case collision", "collision")]:
        format_target(filesystem, full=fault == "ENOSPC")
        send(b"\x1e", "OBLIVION - importa documenti")
        send(b"j", "OBLIVION - importa documenti")
        send(b"e", "Percorso nella sessione")
        authorization = send(f"workspace/{selection}\r".encode(), "OBLIVION - autorizza USB in scrittura")
        assert b"Destinazione: vdd " in authorization, authorization
        send(b"e", "OBLIVION - conferma esportazione")
        offset = len(screen)
        started = time.monotonic()
        send(b"e", "Export interrotto senza conferma di smontaggio")
        assert time.monotonic() - started < 45, "writer error must not await the 300-second relay deadline"
        cleaned()
        assert not status()["session_open"]
        assert b"Esportazione completata" not in screen[offset:]
        assert b"Puoi rimuovere il supporto" not in screen[offset:]
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


print("OBLIVION_IMPORT_FIXTURE_SHA256 " + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), flush=True)
os.umask(0o077)
subprocess.run(["mkfs.ext4", "-q", "-m", "0", "/dev/vdb"], check=True)
subprocess.run(["mount", "/dev/vdb", "/data"], check=True)
vm = {"root": "/usr/lib/oblivion/vm/qemu-root", "kernel": "/usr/lib/oblivion/vm/kernel",
    "initrd": "/usr/lib/oblivion/vm/initrd", "filesystem": "/usr/lib/oblivion/vm/guest.squashfs",
    "memory_mib": 768, "cpus": 2, "accelerator": "tcg"}
export_lab = Path("/usr/lib/oblivion/vm/export-lab").exists()
Path(CONFIG).write_text(json.dumps({"general_image": "/data/general.luks", "general_mib": 768,
    "session_mib": 128, "pbkdf_memory_kib": 65536, "manager_uid": 1000, "vm": vm,
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
try:
    wait("Archivio generale bloccato")
    send(b"\r", "Password del volume generale")
    send(GENERAL + b"\r", "Nessuna sessione")
    send(b"n", "Nuova sessione - password")
    send(PASSWORD + b"\r", "Ripeti la password")
    send(PASSWORD + b"\r", "OBLIVION_GUEST_READY")
    session_pid = systemctl("show", "oblivion-session.service", "-p", "MainPID", "--value")
    send(b"\x1e", "OBLIVION - importa documenti")
    listing = send(b"u", "OBLIVION - copie della sessione")
    assert b"Privata, non consegnata" in listing and b"00000000" in listing
    cleaned()
    send(b"d", "Conferma eliminazione")
    send(b"\x1b", "OBLIVION - copie della sessione")
    send(b"d", "Conferma eliminazione")
    send(b"d", "Nessuna copia registrata")
    cleaned()
    send(b"\x1b", "OBLIVION | SESSIONE APERTA")
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
    send(b"\x1b", "OBLIVION | SESSIONE APERTA")
    cleaned()
    guest("imports-empty", "OBLIVION_IMPORTS_EMPTY")
    assert systemctl("show", "oblivion-session.service", "-p", "MainPID", "--value") == session_pid
    check("cancelling the manifest destroys the source VM and leaves the active chat unchanged")
    copied = offer()
    assert copied != first
    send(b"i", "Importazione verificata")
    print("STEP: import receipt verified", flush=True)
    send(b"\r", "OBLIVION | SESSIONE APERTA")
    cleaned()
    guest("imports-check", "OBLIVION_IMPORT_VERIFIED")
    check("confirmed files are verified, group-editable and visible only inside the session")
    send(b"\x1e", "OBLIVION - importa documenti")
    listing = send(b"u", "OBLIVION - copie della sessione")
    assert b"Pubblicata, modificabile dalla chat" in listing and copied.encode() in listing
    cleaned()
    # D is deliberately unavailable for an exposed copy, including edited files.
    listing = send(b"d", "OBLIVION - copie della sessione")
    assert b"Conferma eliminazione" not in listing
    send(b"\x1b", "OBLIVION | SESSIONE APERTA")
    guest("imports-resumed", "OBLIVION_IMPORT_RESUMED")
    check("reconciliation reads a private durable receipt without rehashing or deleting later chat edits")
    if export_lab:
        exports(copied)
        export_faults()
        format_target("ext4")
    offer()
    source_pid = int(systemctl("show", "oblivion-import-vm.service", "-p", "MainPID", "--value"))
    os.kill(source_pid, signal.SIGKILL)
    wait("Operazione non completata")
    cleaned()
    assert not status()["session_open"]
    check("source VM death invalidates approval and closes the session through the manager")
    # Reopen the same volume and verify persistence of the chat's file edit.
    send(b"\r", "Password della sessione")
    send(PASSWORD + b"\r", "OBLIVION_GUEST_READY")
    guest("imports-resumed", "OBLIVION_IMPORT_RESUMED")
    check("imported documents and later edits survive a fresh VM and LUKS reopening")
    send(b"\x1e", "OBLIVION - importa documenti")
    listing = send(b"u", "OBLIVION - copie della sessione")
    assert b"Pubblicata, modificabile dalla chat" in listing and copied.encode() in listing
    assert b"Privata, non consegnata" not in listing
    cleaned()
    send(b"b", "Archivio generale bloccato")
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
    send(b"i", "Importazione verificata")
    send(b"\r", "OBLIVION | SESSIONE APERTA")
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
            send(b"i", "Importazione verificata")
            send(b"\r", "OBLIVION | SESSIONE APERTA")
            cleaned()
            guest("imports-check", "OBLIVION_IMPORT_VERIFIED")
            identifier = exports(copied, "ephemeral " + filesystem, filesystem)
            with Path("/dev/vdd").open("rb") as stream:
                source_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            send(b"\x1e", "OBLIVION - importa documenti")
            send(b"j", "OBLIVION - importa documenti")
            send(b"\r", "Percorso relativo sulla USB")
            send(f"Oblivion-{identifier}/files/imports/{copied}/files/documenti\r".encode(), "OBLIVION - conferma importazione")
            send(b"i", "Importazione verificata")
            send(b"\r", "OBLIVION | SESSIONE APERTA")
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
