#!/usr/bin/env python3
"""Actual file VM, systemd/HTTP/copy lifecycles on a private two-VM wire.

There is no external network, Tor, provider key or user disk. Backup cases
attach only a disposable sparse block fixture, never a user archive. A fixed peer
replaces only the remote HTTP caller; it does not assert public onion readiness.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import queue
import socket
import struct
import subprocess
import tempfile
import threading
import time

ID = "0123456789abcdef0123456789abcdef"
PAYLOAD = b"Oblivion file VM synthetic payload\n"
FILES = {"z.txt": b"second fixture", "a.txt": PAYLOAD}
LIMITS = {"entries": 1024, "bytes": 256 * 1024 * 1024}


def exact(stream, length):
    result = b""
    while len(result) < length:
        data = stream.recv(length - len(result))
        assert data, "Private file channel closed"
        result += data
    return result


def write(stream, value):
    data = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    stream.sendall(struct.pack(">I", len(data)) + data)


def read(stream):
    length = struct.unpack(">I", exact(stream, 4))[0]
    assert 0 < length <= 512 * 1024
    return json.loads(exact(stream, length))


class VM:
    def __init__(self, image, output, runtime, accelerator, mode, keepalive=None, backup=None, writable=False):
        self.mode = mode
        self.messages = queue.Queue()
        self.ports = {}
        runtime.mkdir()
        ports = ("file", "stage", "source") if mode == "file" else ()
        network = (f"stream,id=wire,server=on,addr.type=unix,addr.path={runtime.parent}/wire.sock" if mode == "file"
                   else f"stream,id=wire,server=off,addr.type=unix,addr.path={runtime.parent}/wire.sock")
        command = ["qemu-system-aarch64", "-machine", "virt", "-accel", accelerator,
            "-cpu", "host" if accelerator == "hvf" else "max", "-m", "1280" if mode == "file" else "256", "-smp", "2",
            "-S", "-nodefaults", "-no-user-config", "-no-reboot", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-qmp", f"unix:{runtime}/qmp,server=on,wait=off",
            "-object", "rng-random,filename=/dev/urandom,id=rng", "-device", "virtio-rng-pci,rng=rng",
            "-kernel", str(image / "kernel"), "-initrd", str(image / ("initrd" if mode == "file" else "peer-initrd")),
            "-append", "console=ttyAMA0 root=/dev/vda rootfstype=squashfs ro loglevel=3 systemd.show_status=false "
                + f"systemd.unit=oblivion-onion-file-{'lab' if mode == 'file' else 'peer'}.target panic=-1",
            "-drive", f"file={image}/{'laboratory' if mode == 'file' else 'peer'}.squashfs,format=raw,if=none,id=root,readonly=on",
            "-device", "virtio-blk-pci,drive=root", "-device", "virtio-serial-pci", "-netdev", network,
            "-device", f"virtio-net-pci,romfile=,netdev=wire,mac=52:54:00:6f:00:{'04' if mode == 'file' else '05'}"]
        if backup is not None:
            command += ["-drive", f"file={backup},format=raw,if=none,id=backup,readonly={'off' if writable else 'on'}", "-device", "virtio-blk-pci,drive=backup,serial=oblivion-backup"]
        for port in ports:
            command += ["-chardev", f"socket,id={port},path={runtime}/{port},server=on,wait=off",
                        "-device", f"virtserialport,chardev={port},name=oblivion.onion.{port}"]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, bufsize=0)
        self.reader = threading.Thread(target=self.read_console, args=(output,), daemon=True)
        self.reader.start()
        try:
            deadline = time.monotonic() + 15
            while not (runtime / "qmp").is_socket() or any(not (runtime / port).is_socket() for port in ports):
                assert self.process.poll() is None and time.monotonic() < deadline, "QEMU did not start"
                time.sleep(0.02)
            for port in ports:
                stream = socket.socket(socket.AF_UNIX)
                stream.settimeout(30)
                stream.connect(str(runtime / port))
                self.ports[port] = stream
            with socket.socket(socket.AF_UNIX) as qmp:
                qmp.settimeout(5)
                qmp.connect(str(runtime / "qmp"))
                with qmp.makefile("rwb", buffering=0) as stream:
                    assert "QMP" in json.loads(stream.readline())
                    for operation in ("qmp_capabilities", "cont"):
                        stream.write(json.dumps({"execute": operation}).encode() + b"\n")
                        while "return" not in json.loads(stream.readline()):
                            pass
            if mode == "file":
                # Match the controller's 120s cold-worker startup budget as
                # well as emulated boot. Copy ports retain their 30s cap.
                self.ports["file"].settimeout(120)
                assert read(self.ports["file"]) == {"ready": True, "version": 1, "role": "onion-file"}
            deadline = time.monotonic() + 120
            while True:
                remaining = deadline - time.monotonic()
                assert remaining > 0, "Guest fixture did not start"
                try:
                    ready = self.messages.get(timeout=min(3, remaining))
                    break
                except queue.Empty:
                    if keepalive is not None:
                        # The product controller also observes a transfer at
                        # least every five seconds. Peer boot under TCG must
                        # not consume the already running owner's heartbeat.
                        assert keepalive().get("ok")
            assert ready == {"ready": True, "mode": mode}
        except BaseException:
            self.stop()
            raise

    def read_console(self, output):
        pending = b""
        with output.open("xb") as log:
            while chunk := self.process.stdout.read(65536):
                log.write(chunk)
                log.flush()
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    if b"OBLIVION_ONION_FILE_LAB " in line:
                        self.messages.put(json.loads(line.split(b"OBLIVION_ONION_FILE_LAB ", 1)[1]))
        self.messages.put({"exited": True})

    def command(self, operation, **fields):
        write(self.ports["file"], {"operation": operation, **fields})
        return read(self.ports["file"])

    def diagnostic(self, operation, keepalive=None, timeout=30):
        self.process.stdin.write(json.dumps({"operation": operation}).encode() + b"\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "Guest diagnostic did not complete"
            try:
                value = self.messages.get(timeout=min(3, remaining))
                break
            except queue.Empty:
                if keepalive is not None:
                    assert keepalive().get("ok")
        assert value.get("ok"), value
        return value

    def stopped(self):
        assert self.process.wait(timeout=30) == 0
        self.reader.join(timeout=5)

    def completed(self, name):
        deadline = time.monotonic() + 10
        while True:
            value = next(value for value in self.diagnostic("info")["units"] if value["name"] == name)
            if value["pid"] == 0 and value["active"] == "inactive" and value["result"] == "success":
                return
            assert time.monotonic() < deadline, value
            time.sleep(0.02)

    def stop(self):
        for stream in self.ports.values():
            stream.close()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=5)


def stage(vm):
    assert vm.command("prepare-share") == {"ok": True, "phase": "staging"}
    stream = vm.ports["stage"]
    assert exact(stream, 6) == b"ready\n"
    manifest = [{"kind": "file", "path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                for name, data in FILES.items()]
    encoded = json.dumps(manifest, separators=(",", ":")).encode()
    approval = {"id": ID, "manifest_sha256": hashlib.sha256(encoded).hexdigest()}
    write(stream, {"approval": approval, "limits": LIMITS})
    stream.sendall(b"OBLVCP01" + struct.pack(">I", len(encoded)) + encoded)
    assert exact(stream, 8) == b"receive\n"
    stream.sendall(b"".join(FILES.values()) + b"OBLVEND1")
    receipt = read(stream)
    assert receipt == {**approval, "entries": 2, "bytes": sum(map(len, FILES.values()))}
    vm.completed("oblivion-onion-stage.service")
    return receipt


def receive_frozen(vm):
    assert vm.command("source") == {"ok": True, "phase": "copying"}
    stream = vm.ports["source"]
    assert exact(stream, 6) == b"ready\n"
    write(stream, {"browse": {"path": "../../vault", "after": None, "limit": 10}})
    assert read(stream) == {"error": "directory_unavailable"}
    write(stream, {"browse": {"path": "", "after": None, "limit": 100}})
    page = read(stream)
    assert page["entries"] and page["next"] is None
    write(stream, {"id": ID, "limits": LIMITS, "paths": [value["name"] for value in page["entries"]]})
    assert exact(stream, 8) == b"OBLVCP01"
    length = struct.unpack(">I", exact(stream, 4))[0]
    assert 0 < length <= 1024 * 1024
    encoded = exact(stream, length)
    manifest = json.loads(encoded)
    files = [value for value in manifest if value["kind"] == "file"]
    assert len(files) == 1 and files[0]["path"].endswith("/citta.txt")
    assert files[0]["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    approval = {"id": ID, "manifest_sha256": hashlib.sha256(encoded).hexdigest()}
    write(stream, approval)
    assert exact(stream, len(PAYLOAD)) == PAYLOAD and exact(stream, 8) == b"OBLVEND1"
    write(stream, {**approval, "entries": len(manifest), "bytes": len(PAYLOAD)})
    assert exact(stream, 7) == b"copied\n"
    vm.completed("oblivion-onion-source.service")


def verify(image):
    manifest = (image / "SHA256SUMS").read_text()
    for line in manifest.splitlines():
        expected, filename = line.split(maxsplit=1)
        with (image / filename).open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == expected, filename
    repository = Path(__file__).resolve().parents[2]
    for line in (image / "sources.sha256").read_text().splitlines():
        expected, filename = line.split(maxsplit=1)
        path = Path(filename.removeprefix("./"))
        if path == Path("transfer-sources.sha256"):
            continue
        source = repository / {"onion": "packages/oblivion-onion", "transfer": "packages/oblivion-transfer",
                               "lab": "script/oblivion"}[path.parts[0]] / Path(*path.parts[1:])
        assert source.is_relative_to(repository) and hashlib.sha256(source.read_bytes()).hexdigest() == expected, source
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", choices=("share", "receive", "owner-death", "disconnect", "malformed", "partial", "expiry", "backup", "backup-writable", "backup-invalid"))
    parser.add_argument("--accelerator", choices=("hvf", "tcg"), default="hvf")
    args = parser.parse_args()
    assert (platform.system(), platform.machine()) == ("Darwin", "arm64") if args.accelerator == "hvf" else platform.system() == "Linux"
    args.image = args.image.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = verify(args.image)
    (args.output / "image-SHA256SUMS").write_text(manifest)
    checks = []
    started = time.monotonic()
    success = False
    try:
        for scenario in ([args.scenario] if args.scenario else ("share", "receive", "owner-death", "disconnect", "malformed", "partial", "expiry", "backup", "backup-writable", "backup-invalid")):
            with tempfile.TemporaryDirectory(prefix="onion-file-", dir="/tmp") as directory:
                runtime = Path(directory)
                backup = runtime / "ciphertext-fixture.raw" if scenario.startswith("backup") else None
                if backup is not None:
                    with backup.open("xb") as target:
                        target.truncate(512 * 1024**2)
                        target.write(b"LUKS\xba\xbe\0\x02" if scenario != "backup-invalid" else b"INVALID!")
                        target.seek(512 * 1024**2-32)
                        target.write(b"OBLIVION_BACKUP_FIXTURE_12345678")
                    original = hashlib.file_digest(backup.open("rb"), "sha256").hexdigest()
                vm = VM(args.image, args.output / f"{scenario}-file.log", runtime / "file", args.accelerator, "file", backup=backup, writable=scenario == "backup-writable")
                peer = None
                try:
                    peer = VM(args.image, args.output / f"{scenario}-peer.log", runtime / "peer", args.accelerator, "peer",
                              keepalive=lambda: vm.command("observe"))
                    before = vm.diagnostic("info")
                    assert before["controller_sha256"] == (args.image / "binaries.sha256").read_text().split()[0]
                    assert vm.command("observe") == {"ok": True, "phase": "fresh", "worker": None}
                    assert peer.diagnostic("refused")["refused"]
                    if scenario.startswith("backup"):
                        result = vm.command("backup", ttl_seconds=180)
                        if scenario != "backup":
                            assert result["ok"] is False
                            assert peer.diagnostic("refused")["refused"]
                        else:
                            assert result == {"ok": True, "phase": "sharing"}
                            # Full ciphertext streaming under TCG can exceed
                            # the 15s idle watchdog. Observe the owner as the
                            # production host does, without extending its limit.
                            assert peer.diagnostic("backup-ranges", timeout=180,
                                keepalive=lambda: vm.command("observe"))["raw_ranges_verified"]
                            state = vm.command("observe")["worker"]
                            assert state["mode"] == "backup" and state["bytes"] == 512 * 1024**2
                            assert vm.command("shutdown") == {"ok": True, "phase": "closed"}
                    elif scenario == "share":
                        receipt = stage(vm)
                        assert vm.command("share", receipt=receipt, paths=list(FILES), ttl_seconds=60) == {"ok": True, "phase": "sharing"}
                        assert vm.diagnostic("share-seal")["read_only"]
                        assert peer.diagnostic("download")["downloaded"] > 0
                        assert vm.command("observe")["worker"]["mode"] == "share"
                        assert vm.command("shutdown") == {"ok": True, "phase": "closed"}
                    elif scenario == "malformed":
                        assert vm.command("receive", ttl_seconds=60, root="/vault")["ok"] is False
                    elif scenario == "partial":
                        vm.ports["file"].sendall(b"\x00")
                        assert read(vm.ports["file"])["ok"] is False
                    else:
                        assert vm.command("receive", ttl_seconds=1 if scenario == "expiry" else 60) == {"ok": True, "phase": "receiving"}
                        if scenario == "receive":
                            assert peer.diagnostic("upload")["uploaded"] == len(PAYLOAD)
                            assert vm.command("freeze") == {"ok": True, "phase": "review"}
                            assert peer.diagnostic("refused")["refused"]
                            frozen = vm.diagnostic("frozen")
                            assert len(frozen["files"]) == 1 and frozen["files"][0]["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
                            receive_frozen(vm)
                            assert vm.command("shutdown") == {"ok": True, "phase": "closed"}
                        elif scenario == "owner-death":
                            vm.diagnostic("kill-owner")
                        elif scenario == "disconnect":
                            vm.ports["file"].close()
                    vm.stopped()
                    assert peer.diagnostic("refused")["refused"]
                    if backup is not None:
                        with backup.open("rb") as target:
                            assert hashlib.file_digest(target, "sha256").hexdigest() == original
                    checks.append({"scenario": scenario, "passed": True, "isolation": before})
                    print(f"Passed: {scenario}", flush=True)
                finally:
                    if peer is not None:
                        peer.stop()
                    vm.stop()
        success = True
    finally:
        (args.output / "summary.json").write_text(json.dumps({"passed": success, "checks": checks,
            "image_manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "seconds": round(time.monotonic() - started, 2), "accelerator": args.accelerator,
            "scope": "Production file VM units, read-only share snapshot, HTTP upload/freeze, approved copy protocol and teardown on a private two-VM wire. Backup cases verify raw read-only block streaming and refusal of writable/invalid inputs, using synthetic sparse bytes with a LUKS magic marker, not a real encrypted archive. No public Tor, provider or supported-image acceptance."}, indent=2) + "\n")


if __name__ == "__main__":
    main()
