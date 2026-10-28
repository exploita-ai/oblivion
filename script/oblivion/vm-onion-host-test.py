#!/usr/bin/python3 -B
"""Actual Linux transfer owner, nested guests and synthetic LUKS lifecycle.

The default test has no uplink. Public Tor is a separate explicit runner mode;
it must not turn a bootstrap observation into a recipient round-trip claim.
"""
import hashlib
import io
import json
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import termios
import time
from pathlib import Path

CONFIG = "/run/oblivion-onion-host-test.json"
GENERAL = b"synthetic-general-password"
PASSWORD = b"synthetic-session-password-a"
KEY = b"OBLIVION_ONION_MODEL_KEY_42e1"
PROXY = "OBLIVION_ONION_PROXY_PASSWORD_3c11"
PAYLOAD = b"OBLIVION_ONION_PUBLIC_APPROVED_9b72\n"
OWNER = "oblivion-onion-host.service"
AUX = ["oblivion-onion-uplink.service", "oblivion-onion-gateway-vm.service", "oblivion-onion-file-vm.service"]


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=150, **kwargs)
    assert result.returncode == 0, (args, result.stderr[-2500:])
    return result.stdout.decode().strip()


def prop(unit, key):
    return run("systemctl", "show", unit, "-p", key, "--value")


def command(operation, *arguments, secret=b"", success=True):
    result = subprocess.run(["/usr/bin/oblivion-storage-lab", "--config", CONFIG, operation, *arguments],
                            input=secret, capture_output=True, timeout=150)
    if (result.returncode == 0) != success:
        print(run("journalctl", "--no-pager", "-n", "40", *sum((["-u", unit] for unit in [OWNER, *AUX]), [])), flush=True)
        raise AssertionError((operation, result.returncode, result.stderr))
    return result.stdout.decode().strip() if success else result.stderr.decode().strip()


def onion(action, **fields):
    return json.loads(ipc("onion", secret=json.dumps({"action": action, **fields}).encode()))


def ipc(operation, secret=b""):
    os.seteuid(1000)
    try:
        channel = socket.socket(socket.AF_UNIX)
        channel.settimeout(360)
        channel.connect("/run/oblivion-control.sock")
    finally:
        os.seteuid(0)
    with channel:
        header = json.dumps({"operation": operation, "session": None, "secret_len": len(secret)}).encode()
        channel.sendall(struct.pack(">I", len(header)) + header + secret)
        channel.shutdown(socket.SHUT_WR)
        response = b""
        while chunk := channel.recv(65536):
            response += chunk
            assert len(response) <= 1024**2, "Controller response limit"
        value = json.loads(response)
        if not value["ok"]:
            print(run("journalctl", "--no-pager", "-n", "40", *sum((["-u", unit] for unit in [OWNER, *AUX]), [])), flush=True)
            assert value["ok"], (operation, value["error"])
        return value["output"].strip()


def status():
    return json.loads(command("status"))


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check(label):
    print("PASS: " + label, flush=True)


def stopped(previous=()):
    deadline = time.monotonic() + 40
    while any(prop(unit, "ActiveState") not in ("inactive", "failed") for unit in [OWNER, *AUX]):
        assert time.monotonic() < deadline, "owner/guest stop deadline"
        time.sleep(0.1)
    for pid in previous:
        assert not Path(f"/proc/{pid}").exists(), "guest process survived cleanup"
    assert not Path("/run/oblivion/onion.json").exists()
    assert not Path("/run/oblivion/onion.pending").exists()
    assert not list(Path("/run/oblivion-session").glob("copy-*.sock"))
    current = onion("status")
    assert current["configured"] and not current["active"] and current["id"] is None


def prepared(ttl=300):
    result = onion("prepare", ttl_seconds=ttl)
    assert result["active"] and result["id"] and result["phase"] in ("connecting", "ready")
    processes = [int(prop(unit, "MainPID")) for unit in AUX]
    assert all(pid > 1 for pid in processes)
    for unit, pid, uid in zip(AUX, processes, [1101, 1105, 1106]):
        process = Path(f"/proc/{pid}")
        state = (process / "status").read_text()
        assert f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}" in state
        assert "CapEff:\t0000000000000000" in state and "NoNewPrivs:\t1" in state
        assert (process / "ns/pid").stat().st_ino != Path("/proc/1/ns/pid").stat().st_ino
        if uid != 1101:
            assert prop(unit, "PrivateNetwork") == "yes"
            assert (process / "ns/net").stat().st_ino != Path("/proc/1/ns/net").stat().st_ino
            assert prop(unit, "RestrictAddressFamilies") == "AF_UNIX"
        assert not (process / "root/run/oblivion/general").exists()
        assert not (process / "root/dev/oblivion-session").exists()
        for name in ["cmdline", "environ"]:
            value = (process / name).read_bytes()
            assert KEY not in value and PROXY.encode() not in value
    nat = Path(f"/proc/{processes[0]}/cmdline").read_bytes().split(b"\0")
    assert b"none" in nat and b"-kernel" not in nat and b"-drive" not in nat
    assert not Path("/run/oblivion-onion-host/copy.sock").exists()
    assert Path("/run/oblivion-onion-host/control.sock").stat().st_uid == 0
    assert Path("/run/oblivion-onion-host/control.sock").stat().st_mode & 0o777 == 0o600
    assert Path("/run/oblivion-onion-host").stat().st_mode & 0o777 == 0o711
    return result, processes


def exact(stream, length):
    value = b""
    while len(value) < length:
        chunk = stream.read(length-len(value))
        assert chunk, "Private test/copy channel closed"
        value += chunk
    return value


def write(stream, value):
    data = json.dumps(value, separators=(",", ":")).encode()
    stream.write(struct.pack(">I", len(data))+data)
    stream.flush()


def read(stream):
    length = struct.unpack(">I", exact(stream, 4))[0]
    assert 0 < length <= 65536, "Metadata reply limit"
    return json.loads(exact(stream, length))


def recipient(stream, action, **fields):
    write(stream, {"action": action, **fields})
    result = read(stream)
    assert result.get("ok") is True, "Independent recipient failed"
    return result


def browse(path):
    return json.loads(ipc("browse", secret=json.dumps({"path": path, "after": None, "limit": 100}).encode()))


def imported(id):
    current = onion("import")
    deadline = time.monotonic()+120
    while current["phase"] != "copying":
        assert current["active"] and time.monotonic() < deadline, "Sealed copy startup deadline"
        time.sleep(0.2)
        current = onion("status")
    # Peer credentials are established at connect time, exactly as for the UI.
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(120)
    os.seteuid(1000)
    try:
        stream.connect("/run/oblivion-onion-host/copy.sock")
    finally:
        os.seteuid(0)
    with stream, stream.makefile("rwb") as wire:
        pending = [""]
        files = []
        while pending:
            path = pending.pop()
            write(wire, {"browse": {"path": path, "after": None, "limit": 100}})
            page = read(wire)
            assert page["next"] is None and len(files) <= 2
            for entry in page["entries"]:
                name = path+"/"+entry["name"] if path else entry["name"]
                if entry["directory"]:
                    pending.append(name)
                else:
                    files.append(name)
        assert len(files) == 2 and {Path(name).name for name in files} == {"selected.txt", "unselected.txt"}
        selected = next(name for name in files if Path(name).name == "selected.txt")
        write(wire, {"id": id, "paths": [selected], "limits": {"entries": 1024, "bytes": 256*1024*1024}})
        assert exact(wire, 8) == b"OBLVCP01"
        length = struct.unpack(">I", exact(wire, 4))[0]
        assert 0 < length <= 65536
        encoded = exact(wire, length)
        manifest = json.loads(encoded)
        assert [entry for entry in manifest if entry["kind"] == "file"] == [
            {"kind": "file", "path": selected, "size": len(PAYLOAD), "sha256": hashlib.sha256(PAYLOAD).hexdigest()}]
        assert browse("imports")["entries"] == [], "Intake published before approval"
        check("public intake remains outside session imports until the exact selected manifest is approved")
        approval = {"id": id, "manifest_sha256": hashlib.sha256(encoded).hexdigest()}
        write(wire, approval)
        receipt = read(wire)
        assert receipt == {**approval, "entries": len(manifest), "bytes": len(PAYLOAD)}
    deadline = time.monotonic()+15
    current = onion("status")
    while current["phase"] != "imported":
        assert time.monotonic() < deadline, "Import receipt deadline"
        time.sleep(0.1)
        current = onion("status")
    assert current["receipt"] == receipt
    assert not list(Path("/run/oblivion-session").glob("copy-*.sock"))
    parent = str(Path(selected).parent)
    page = browse(f"imports/{id}/files"+("/"+parent if parent != "." else ""))
    assert page["entries"] == [{"name": "selected.txt", "directory": False, "bytes": len(PAYLOAD)}]
    check("public upload reaches the LUKS session through verified selected-only copy and confirmed port cleanup")
    return selected


def shared(path, public, peer):
    current, pids = prepared(1800)
    deadline = time.monotonic()+180
    progress = None
    while not current["tor_ready"]:
        if current["tor_progress"] != progress:
            progress = current["tor_progress"]
            print("OBLIVION_TRANSFER_BOOTSTRAP share " + str(progress), flush=True)
        assert time.monotonic() < deadline, "Sharing Tor bootstrap deadline at " + str(progress)
        time.sleep(1)
        current = onion("status")
    current = onion("stage")
    deadline = time.monotonic()+120
    while current["phase"] != "staging":
        assert current["active"] and time.monotonic() < deadline, "Sharing copy startup deadline"
        time.sleep(0.2)
        current = onion("status")
    id = current["id"]
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(120)
    os.seteuid(1000)
    try:
        stream.connect("/run/oblivion-onion-host/copy.sock")
    finally:
        os.seteuid(0)
    with stream, stream.makefile("rwb") as wire:
        write(wire, {"id": id, "paths": [path], "limits": {"entries": 1024, "bytes": 256*1024*1024}})
        assert exact(wire, 8) == b"OBLVCP01"
        length = struct.unpack(">I", exact(wire, 4))[0]
        assert 0 < length <= 65536
        encoded = exact(wire, length)
        manifest = json.loads(encoded)
        files = [entry for entry in manifest if entry["kind"] == "file"]
        assert files == [{"kind": "file", "path": path, "size": len(PAYLOAD), "sha256": hashlib.sha256(PAYLOAD).hexdigest()}]
        assert command("onion", secret=b'{"action":"access"}', success=False) == "onion_not_published"
        write(wire, {"id": id, "manifest_sha256": hashlib.sha256(encoded).hexdigest()})
        receipt = read(wire)
        assert receipt["entries"] == len(manifest) and receipt["bytes"] == len(PAYLOAD)
    current = onion("status")
    assert current["phase"] == "staged" and not list(Path("/run/oblivion-session").glob("copy-*.sock"))
    check("selected session files are copied and sealed with the approved manifest before any share URL is published")
    current = onion("share", client_auth=public)
    deadline = time.monotonic()+120
    while current["phase"] != "sharing":
        assert current["active"] and time.monotonic() < deadline, "Sharing publication deadline"
        time.sleep(0.2)
        current = onion("status")
    access = onion("access")
    result = recipient(peer, "download", url=access["url"])
    assert result["unauthenticated_refused"] and result["selected_only"]
    assert result["bytes"] == len(PAYLOAD) and result["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    check("an independent authenticated Tor recipient downloads exactly the approved content from the isolated sharing VM")
    onion("cancel"); stopped(pids)
    assert recipient(peer, "revoked")["revoked"]
    check("stopping a public share revokes its fresh URL and reaps all transfer actors while Documents stays open")


print("OBLIVION_ONION_HOST_FIXTURE_SHA256 " + digest(__file__), flush=True)
os.umask(0o077)
bundle = Path("/run/oblivion-lab-bundle")
manifest = (bundle / "SHA256SUMS").read_text()
for row in manifest.splitlines():
    expected, name = row.split()
    assert digest(bundle / name) == expected
print("OBLIVION_HOST_BUNDLE_SHA256 " + hashlib.sha256(manifest.encode()).hexdigest(), flush=True)
images = {}
for role, serial in [("gateway", "oblivion-gw-image"), ("file", "oblivion-file-image")]:
    image = Path(f"/run/oblivion-{role}-image")
    metadata = json.loads((image / "manifest.json").read_text())
    shutil.copyfile(f"/dev/disk/by-id/virtio-{serial}", image / f"{role}.squashfs")
    for name, expected in metadata.items():
        assert (image / name).stat().st_size == expected["bytes"] and digest(image / name) == expected["sha256"]
        (image / name).chmod(0o644)
    run("mount", "-o", "remount,ro", str(image))
    images[role] = image
    print(f"OBLIVION_{role.upper()}_IMAGE_SHA256 " + metadata[f"{role}.squashfs"]["sha256"], flush=True)

root = Path("/usr/lib/oblivion/vm/qemu-root")
for name in ["oblivion-session", "oblivion-onion-uplink", "oblivion-onion-gateway-vm", "oblivion-onion-file-vm"]:
    assert (root / "run" / name).is_dir(), "missing immutable runtime mount target"
for uid in [1100, 1101, 1105, 1106]:
    assert any(row.split(":")[2] == str(uid) for row in Path("/etc/passwd").read_text().splitlines())
run("mkfs.ext4", "-q", "-m", "0", "/dev/vdb")
run("mount", "/dev/vdb", "/data")
config = {"general_image": "/data/general.luks", "general_mib": 768, "session_mib": 512 if Path("/run/oblivion-onion-backup").exists() or Path("/run/oblivion-onion-backup-startup").exists() else 128,
          "pbkdf_memory_kib": 65536, "manager_uid": 1000, "gateway_network": True,
          "vm": {"root": str(root), "kernel": "/usr/lib/oblivion/vm/kernel", "initrd": "/usr/lib/oblivion/vm/initrd",
                 "filesystem": "/usr/lib/oblivion/vm/guest.squashfs", "memory_mib": 512, "cpus": 1, "accelerator": "tcg"},
          "onion": {"gateway": {"root": str(root), "kernel": str(images["gateway"] / "kernel"),
                     "initrd": str(images["gateway"] / "initrd"), "filesystem": str(images["gateway"] / "gateway.squashfs"),
                     "memory_mib": 512, "cpus": 1, "accelerator": "tcg"},
                    "files": {"root": str(root), "kernel": str(images["file"] / "kernel"),
                     "initrd": str(images["file"] / "initrd"), "filesystem": str(images["file"] / "file.squashfs"),
                     "memory_mib": 1280, "cpus": 2, "accelerator": "tcg"}}}
Path(CONFIG).write_text(json.dumps(config))
unit = (bundle / OWNER).read_text().replace("/usr/bin/oblivion-storage --config /etc/oblivion/controller.json",
                                         "/usr/bin/oblivion-storage-lab --config " + CONFIG)
Path("/run/systemd/system/" + OWNER).write_text(unit.replace("StandardError=null", "StandardError=journal"))
controller = (bundle / "oblivion-controller.service").read_text().replace(
    "/usr/bin/oblivion-storage --config /etc/oblivion/controller.json",
    "/usr/bin/oblivion-storage-lab --config " + CONFIG).replace("Wants=oblivion-manager.service\n", "")
Path("/run/systemd/system/oblivion-controller.service").write_text(controller)
run("systemctl", "daemon-reload")
run("systemctl", "start", "oblivion-controller.service")
run("nft", "-f", "/run/oblivion-onion-host.nft")
print("OBLIVION_HOST_FIREWALL_SHA256 " + digest("/run/oblivion-onion-host.nft"), flush=True)
command("init-general", secret=GENERAL)
command("unlock", secret=GENERAL)
assert status()["api_key_present"] is False
stopped()
session = command("create", secret=PASSWORD)
command("enter-documents", session, secret=PASSWORD)
assert status()["session_mode"] == "documents"
check("general unlock and offline Documents need no provider key or transfer gateway")

online = Path("/run/oblivion-tor-online").exists()
if online:
    run("busybox", "sysctl", "-q", "-w", "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1")
    interface = next(p.parent.name for p in Path("/sys/class/net").glob("*/address") if p.read_text().strip() == "52:54:00:6f:00:04")
    run("ip", "address", "add", "10.0.2.15/24", "dev", interface)
    run("ip", "link", "set", interface, "up")
    run("ip", "route", "add", "default", "via", "10.0.2.2", "dev", interface)
    console = os.open("/dev/ttyAMA0", os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    settings = termios.tcgetattr(console)
    settings[3] = (settings[3] | termios.ICANON) & ~termios.ECHO
    termios.tcsetattr(console, termios.TCSANOW, settings)
    termios.tcflush(console, termios.TCIFLUSH)
    print("OBLIVION_TOR_ENABLE_WAIT", flush=True)
    assert select.select([console], [], [], 60)[0]
    assert os.read(console, 3) == b"go\n"
    os.close(console)

if Path("/run/oblivion-onion-backup-startup").exists():
    ipc("close")
    current = onion("prepare-backup", id=session, password=PASSWORD.decode(), ttl_seconds=180)
    assert current["active"] and not current["tor_ready"] and current["progress"]["bytes"] == 512 * 1024**2
    assert not status()["session_open"] and not Path("/dev/mapper/oblivion-session").exists()
    assert command("enter-documents", session, secret=PASSWORD, success=False) == "backup_active"
    assert not Path("/run/oblivion-onion-host/copy.sock").exists()
    volume = Path("/run/oblivion/general/sessions") / (session+".luks")
    original = digest(volume)
    check("closed-backup preparation attaches one read-only ciphertext descriptor without a session VM, mapping, copy socket or permission to reopen")
    onion("cancel"); stopped()
    assert digest(volume) == original
    command("lock"); stopped()
    run("systemctl", "stop", "oblivion-controller.service")
    run("umount", "/data")
    check("offline backup cancellation releases all transfer actors before closing the unchanged archive")
    print("OBLIVION_VM_LAB_PASS", flush=True)
    raise SystemExit(0)

has_recipient = Path("/run/oblivion-onion-recipient").exists()
current, pids = prepared(1800 if has_recipient else 300)
check("the real owner launches one network-only actor and distinct-UID private-PID/AF_UNIX transfer guests")
if not online:
    assert not current["tor_ready"]
    assert command("onion", secret=json.dumps({"action": "receive", "client_auth": "A" * 52}).encode(), success=False) == "onion_not_ready"
    assert all(prop(unit, "ActiveState") == "active" for unit in AUX)
    check("offline bootstrap is not advertised ready and cannot authorize receive publication")
else:
    deadline = time.monotonic() + 180
    progress = None
    while not current["tor_ready"]:
        if current["tor_progress"] != progress:
            progress = current["tor_progress"]
            print("OBLIVION_TRANSFER_BOOTSTRAP receive " + str(progress), flush=True)
        assert time.monotonic() < deadline, "public Tor bootstrap deadline at " + str(progress)
        time.sleep(1)
        current = onion("status")
    assert current["tor_progress"] == 100
    check("public Tor bootstrap is verified through the isolated transfer owner; no recipient claim")
if has_recipient:
    run("modprobe", "virtio_console")
    run("udevadm", "settle")
    with open("/dev/virtio-ports/oblivion.onion.lab", "r+b", buffering=0) as port, io.BufferedRWPair(port, port) as peer:
        public = recipient(peer, "prepare")["public_key"]
        current = onion("receive", client_auth=public)
        deadline = time.monotonic()+120
        while current["phase"] != "receiving":
            assert current["active"] and time.monotonic() < deadline, "Receive worker startup deadline"
            time.sleep(0.2)
            current = onion("status")
        access = onion("access")
        assert set(access) == {"url"}
        report = recipient(peer, "upload", url=access["url"])
        assert report["unauthenticated_refused"] and report["wrong_key_refused"] and report["authorized_clients"] == 2
        assert report["uploaded_files"] == 2
        check("independent public Tor clients reject absent/wrong authorization and accept an authenticated multipart upload")
        current = onion("status")
        deadline = time.monotonic()+10
        while current["progress"] is None or current["progress"]["files"] != 2:
            assert time.monotonic() < deadline, "Upload observation deadline"
            time.sleep(0.2)
            current = onion("status")
        assert current["progress"]["bytes"] == report["uploaded_bytes"]
        assert browse("imports")["entries"] == []
        current = onion("freeze")
        deadline = time.monotonic()+120
        while current["phase"] != "review":
            assert current["active"] and time.monotonic() < deadline, "Sealed review deadline"
            time.sleep(0.2)
            current = onion("status")
        assert not current["tor_ready"] and current["tor_progress"] is None
        assert all(not Path(f"/proc/{pid}").exists() for pid in pids[:2])
        assert recipient(peer, "revoked")["revoked"]
        check("freezing public receive revokes the URL and reaps both network actors before sealed file review")
        selected = imported(current["id"])
        imported_id = current["id"]
        onion("cancel"); stopped(pids)
        ipc("close")
        command("enter-documents", session, secret=PASSWORD)
        parent = str(Path(selected).parent)
        page = browse(f"imports/{imported_id}/files"+("/"+parent if parent != "." else ""))
        assert page["entries"] == [{"name": "selected.txt", "directory": False, "bytes": len(PAYLOAD)}]
        check("approved public upload persists across session close and encrypted-volume reopening; unselected upload is absent")
        if Path("/run/oblivion-onion-share").exists():
            guard = Path("/run/oblivion/general/profile/onion-tor-state")
            assert guard.stat().st_mode & 0o777 == 0o600 and "Guard " in guard.read_text()
            assert not Path("/run/oblivion/general/profile/tor-state").exists()
            shared(f"imports/{imported_id}/files/{selected}", public, peer)
        if Path("/run/oblivion-onion-backup").exists():
            ipc("close")
            current = onion("prepare-backup", id=session, password=PASSWORD.decode(), ttl_seconds=3600)
            assert not status()["session_open"] and not Path("/dev/mapper/oblivion-session").exists()
            volume = Path("/run/oblivion/general/sessions") / (session+".luks")
            assert command("enter-documents", session, secret=PASSWORD, success=False) == "backup_active"
            original = digest(volume)
            size = volume.stat().st_size
            assert size == 512 * 1024 ** 2
            with volume.open("rb") as source:
                first = hashlib.sha256(source.read(1024**2)).hexdigest()
                source.seek(size-1024**2)
                last = hashlib.sha256(source.read(1024**2)).hexdigest()
            deadline = time.monotonic()+180
            while not current["tor_ready"]:
                assert current["active"] and time.monotonic() < deadline, "Backup Tor bootstrap deadline"
                time.sleep(0.5)
                current = onion("status")
            assert current["phase"] == "ready" and current["progress"]["bytes"] == size
            assert not Path("/run/oblivion-onion-host/copy.sock").exists()
            current = onion("share", client_auth=public)
            deadline = time.monotonic()+120
            while current["phase"] != "sharing":
                assert current["active"] and time.monotonic() < deadline, "Backup HTTP startup deadline"
                time.sleep(0.2)
                current = onion("status")
            access = onion("access")
            report = recipient(peer, "backup", url=access["url"], bytes=size, first_sha256=first, last_sha256=last, sha256=original)
            assert report["first_and_last_ranges_match"] and report["unauthenticated_refused"]
            assert report["downloaded_bytes"] == size and report["full_sha256_match"]
            check("an authenticated public recipient streams the complete 512 MiB LUKS2 backup with an identical hash; first/last Range downloads also match")
            onion("cancel"); stopped()
            assert digest(volume) == original and not status()["session_open"]
            assert recipient(peer, "revoked")["revoked"]
            command("enter-documents", session, secret=PASSWORD)
            assert browse(f"imports/{imported_id}/files"+("/"+parent if parent != "." else ""))["entries"] == page["entries"]
            check("backup sharing revokes its URL and releases its read-only descriptor without changing the archive or session files")
        assert recipient(peer, "finish")["closed"]
    command("lock"); stopped()
    if Path("/run/oblivion-onion-share").exists():
        before = digest("/data/general.luks")
        command("unlock-ephemeral", secret=GENERAL)
        command("enter-documents-ephemeral")
        _, pids = prepared()
        onion("cancel"); stopped(pids)
        command("lock"); stopped()
        assert digest("/data/general.luks") == before
        check("transfer guards are separate from model state and ephemeral transfer use leaves the persistent archive byte-identical")
    run("systemctl", "stop", "oblivion-controller.service")
    run("umount", "/data")
    check("public receive leaves no active transfer, session/general mapping or independent recipient")
    print("OBLIVION_VM_LAB_PASS", flush=True)
    raise SystemExit(0)
onion("cancel"); stopped(pids)
assert status()["session_open"] and status()["session_mode"] == "documents"
check("explicit cancellation reaps every auxiliary process and preserves the offline session")

command("api-keys", secret=json.dumps({"action": "add", "name": "Synthetic model key", "key": KEY.decode()}).encode())
command("egress", secret=json.dumps({"action": "save", "transport": {"mode": "socks5", "endpoint": "192.0.2.10:1080",
        "authentication": {"username": "synthetic", "password": PROXY}}}).encode())
profile = Path("/run/oblivion/general/profile")
preserved = {name: (profile / name).read_bytes() for name in ["provider.keys.json", "transport.json"]}
_, pids = prepared()
ipc("close"); stopped(pids)
assert not Path("/dev/mapper/oblivion-session").exists()
assert all((profile / name).read_bytes() == data for name, data in preserved.items())
assert not Path("/run/oblivion-gateway-vm").exists()
check("session close reaps transfer guests before LUKS closure without changing model proxy/key profiles")

command("enter-documents", session, secret=PASSWORD)
_, pids = prepared()
run("systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", OWNER)
stopped(pids)
assert status()["session_open"]
check("owner SIGKILL triggers systemd cleanup without leaving auxiliary processes or a dangling transfer job")

_, pids = prepared()
session_pid = int(prop("oblivion-session.service", "MainPID"))
os.kill(session_pid, signal.SIGKILL)
stopped(pids)
command("lock")
assert not Path("/dev/mapper/oblivion-session").exists() and not Path("/dev/mapper/oblivion-general").exists()
check("session process death revokes the transfer; lock still confirms both encrypted mappings closed")

command("unlock", secret=GENERAL)
command("enter-documents", session, secret=PASSWORD)
result = onion("prepare", ttl_seconds=90)
assert result["active"]
pids = [int(prop(unit, "MainPID")) for unit in AUX]
deadline = time.monotonic() + 100
while Path("/run/oblivion/onion.json").exists():
    assert time.monotonic() < deadline, "transfer expiry deadline"
    time.sleep(0.2)
stopped(pids)
assert status()["session_open"]
check("operation expiry reaps the auxiliary guests while keeping Documents open")

_, pids = prepared()
command("lock"); stopped(pids)
assert not status()["general_open"] and not status()["session_open"]
run("systemctl", "stop", "oblivion-controller.service")
run("umount", "/data")
check("general lock confirms owner/guest teardown before encrypted storage is closed")
print("OBLIVION_VM_LAB_PASS", flush=True)
