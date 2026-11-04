"""Private portable Share endpoint. Runs only in the immutable offline image."""

import fcntl
import json
import os
from pathlib import Path
import re
import resource
import select
import stat
import struct
import subprocess
import sys
import time

# -I excludes cwd, PYTHONPATH and user-site code. These are image-owned modules.
sys.path.insert(0, "/usr/lib/oblivion/history")
sys.path.insert(0, "/usr/lib/oblivion/guest")
from oblivion_history.portable import import_catalog
from share_plan import Plan

READY = b"OBSH1\n"
VAULT = Path("/vault")
COPY = "/usr/bin/oblivion-copy"
FRAME_LIMIT = 8 * 1024 * 1024


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("invalid_share_request")
        value[key] = item
    return value


def exact(fd, size, deadline):
    value = bytearray()
    while len(value) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ValueError("share_request_timeout")
        part = os.read(fd, size - len(value))
        if not part:
            raise EOFError()
        value.extend(part)
    return bytes(value)


def write(fd, value):
    view = memoryview(value)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise EOFError()
        view = view[count:]


def read_frame(fd, deadline):
    size, = struct.unpack(">I", exact(fd, 4, deadline))
    if not 0 < size <= FRAME_LIMIT:
        raise ValueError("invalid_share_frame")
    value = json.loads(exact(fd, size, deadline), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("invalid_share_request")
    return value


def frame(fd, value):
    data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if len(data) > FRAME_LIMIT:
        raise ValueError("share_plan_limit")
    write(fd, struct.pack(">I", len(data)) + data)


def cleanup_export(vault, request_id):
    directory = Path(vault) / "state/.oblivion-share" / request_id
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("share_cleanup_required")
    if any(entry.name != "chats.jsonl" for entry in directory.iterdir()):
        raise ValueError("share_cleanup_required")
    catalog = directory / "chats.jsonl"
    try:
        info = catalog.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise ValueError("share_cleanup_required")
        catalog.unlink()
    except FileNotFoundError:
        pass
    directory.rmdir()


def export(fd, vault, request_id=None, copy=COPY, runtime=None):
    plan = None
    raw = False
    try:
        request = read_frame(fd, time.monotonic() + 30)
        while True:
            if request_id is not None and request.get("request_id") != request_id:
                raise ValueError("invalid_share_request")
            plan = Plan(vault, request)
            request_id = plan.request["request_id"]
            if runtime is not None:
                target = os.open(Path(runtime) / "request_id", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    write(target, request_id.encode())
                finally:
                    os.close(target)
            frame(fd, plan.public)
            decision = read_frame(fd, time.monotonic() + 1800)
            if decision.get("operation") == "plan":
                plan.close(); plan = None
                request = decision
                continue
            if decision == {"version": 1, "operation": "cancel", "request_id": request_id} and type(decision["version"]) is int:
                plan.close(); plan = None
                frame(fd, {"version": 1, "request_id": request_id, "ok": True, "cancelled": True})
                return
            if set(decision) != {"version", "operation", "request_id", "plan_sha256"} or type(decision["version"]) is not int or decision["version"] != 1 or decision["operation"] != "confirm":
                raise ValueError("invalid_share_confirmation")
            approved = plan.approve(decision["request_id"], decision["plan_sha256"])
            descriptor = os.memfd_create("oblivion-share-plan", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                if descriptor != 4:
                    os.dup2(descriptor, 4, inheritable=False)
                    os.close(descriptor)
                data = json.dumps(approved, ensure_ascii=False, separators=(",", ":")).encode()
                write(4, data)
                os.lseek(4, 0, os.SEEK_SET)
                fcntl.fcntl(4, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                raw = True
                result = subprocess.run([copy, "share-send", str(vault), "3600000"], pass_fds=(3, 4), stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                                        timeout=3600, check=False)
                if result.returncode != 0:
                    raise ValueError("share_transfer_failed")
                plan.close(); plan = None
                write(fd, b"copied\n")
                return
            finally:
                os.close(4)
    except BaseException as error:
        if plan:
            try:
                plan.close()
            except (OSError, ValueError):
                error = ValueError("share_cleanup_required")
            plan = None
        if raw:
            write(fd, b"failed!\n")
        else:
            code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else "share_failed"
            frame(fd, {"version": 1, "request_id": request_id, "ok": False, "error": code})
        raise
    finally:
        if plan:
            plan.close()


def require_empty_import(vault):
    for name in ("workspace", "imports"):
        directory = vault / name
        if directory.is_symlink() or not directory.is_dir() or any(directory.iterdir()):
            raise ValueError("share_destination_not_empty")
    home = vault / "home"
    if home.is_symlink() or not home.is_dir():
        raise ValueError("share_destination_not_empty")
    for entry in home.iterdir():
        if entry.name not in (".oblivion-history", ".oblivion-file-staging") or entry.is_symlink() or not entry.is_dir() or any(entry.iterdir()):
            raise ValueError("share_destination_not_empty")
    for entry in (vault / "state").iterdir():
        if entry.name != ".oblivion-share":
            raise ValueError("share_destination_not_empty")
    if (vault / ".oblivion-system").exists():
        raise ValueError("share_destination_not_empty")


def ownership(directory, uid, directory_mode, file_mode):
    for parent, directories, files in os.walk(directory, followlinks=False):
        os.chown(parent, uid, 1000, follow_symlinks=False)
        os.chmod(parent, directory_mode, follow_symlinks=False)
        for name in directories + files:
            path = Path(parent) / name
            if path.is_symlink():
                raise ValueError("invalid_share_destination")
        for name in files:
            os.chown(Path(parent) / name, uid, 1000, follow_symlinks=False)
            os.chmod(Path(parent) / name, file_mode, follow_symlinks=False)


def receive(fd, vault, request_id=None, copy=COPY):
    request = read_frame(fd, time.monotonic() + 30)
    supplied = request.get("request_id")
    if not isinstance(supplied, str) or not re.fullmatch(r"[0-9a-f]{32}", supplied) or request_id is not None and request_id != supplied:
        raise ValueError("invalid_share_request")
    request_id = supplied
    if request != {"version": 1, "operation": "import", "request_id": request_id} or type(request["version"]) is not int:
        raise ValueError("invalid_share_request")
    require_empty_import(vault)
    inbox = vault / "state/.oblivion-share"
    inbox.mkdir(mode=0o700, exist_ok=True)
    info = inbox.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("share_stage_unavailable")
    result = subprocess.run([copy, "share-receive", str(inbox), request_id, "3600000"], pass_fds=(3,), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                            timeout=3600, check=False)
    if result.returncode != 0:
        raise ValueError("share_transfer_failed")
    receipt = json.loads(result.stdout, object_pairs_hook=unique)
    files = inbox / request_id / "files"
    for name in ("workspace", "imports"):
        source = files / name
        if source.exists():
            (vault / name).rmdir()
            os.rename(source, vault / name)
    history = files / "history/chats.jsonl"
    if history.exists():
        import_catalog(history, vault / "home/.oblivion-history", vault / "workspace", imports=vault / "imports")
    ownership(vault / "workspace", 1000, 0o700, 0o600)
    ownership(vault / "imports", 1001, 0o750, 0o640)
    if (vault / "home/.oblivion-history").exists():
        ownership(vault / "home/.oblivion-history", 1000, 0o700, 0o600)
    if history.exists():
        history.unlink()
        history.parent.rmdir()
    files.rmdir()
    transaction = inbox / request_id
    (transaction / "receipt.json").unlink()
    transaction.rmdir()
    os.sync()
    frame(fd, receipt)


def main():
    os.umask(0o077)
    os.chdir("/")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if len(sys.argv) == 3 and sys.argv[1] == "--cleanup-export" and re.fullmatch(r"vport[0-9]+p[0-9]+", sys.argv[2]):
        ticket = Path("/run/oblivion-share-" + sys.argv[2]) / "request_id"
        try:
            descriptor = os.open(ticket, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError("share_cleanup_required")
            request_id = source.read(33).decode("ascii")
        if not re.fullmatch(r"[0-9a-f]{32}", request_id):
            raise ValueError("share_cleanup_required")
        cleanup_export(VAULT, request_id)
        return
    if len(sys.argv) != 2 or not re.fullmatch(r"/dev/vport[0-9]+p[0-9]+", sys.argv[1]):
        raise ValueError("invalid_share_port")
    device = Path(sys.argv[1])
    name = (Path("/sys/class/virtio-ports") / device.name / "name").read_text().strip()
    match = re.fullmatch(r"oblivion\.share-(export|import)\.([0-9a-f]{32})", name)
    if not match:
        raise ValueError("invalid_share_port")
    role, request_id = match.groups()
    if os.geteuid() != (1000 if role == "export" else 0):
        raise ValueError("invalid_share_identity")
    flags = Path("/proc/cmdline").read_text().split()
    if "oblivion.share=1" not in flags or "oblivion.network=1" in flags or "oblivion.native=1" in flags:
        raise ValueError("unsafe_share_profile")
    if any(entry.name != "lo" for entry in Path("/sys/class/net").iterdir()):
        raise ValueError("unsafe_share_profile")
    root = next(line for line in Path("/proc/self/mountinfo").read_text().splitlines() if line.split()[4] == "/")
    if root.split(" - ", 1)[1].split()[0] != "squashfs":
        raise ValueError("unsafe_share_system_overlay")
    descriptor = os.open(device, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    if descriptor != 3:
        os.dup2(descriptor, 3, inheritable=False)
        os.close(descriptor)
    try:
        write(3, READY)
        if role == "export":
            export(3, VAULT, runtime=Path("/run/oblivion-share-" + device.name))
        else:
            try:
                receive(3, VAULT)
            except Exception:
                frame(3, {"version": 1, "request_id": request_id, "ok": False, "error": "share_import_failed"})
                raise
    finally:
        os.close(3)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(1)
