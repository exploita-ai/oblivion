#!/usr/bin/env python3
"""Copy synthetic documents between two networkless VMs through private ports."""
import argparse
import fcntl
import hashlib
import json
import os
import platform
import resource
import socket
import struct
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from transfer_fixture import CANARY, FILES, ID


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def verify(directory):
    manifest = (directory / "SHA256SUMS").read_text()
    for line in manifest.splitlines():
        expected, name = line.split()
        assert Path(name).name == name and digest(directory / name) == expected, name
    return manifest


def read_exact(peer, size):
    data = bytearray()
    while len(data) < size:
        chunk = peer.recv(min(65536, size - len(data)))
        assert chunk, "endpoint disconnected"
        data.extend(chunk)
    return bytes(data)


def write_message(peer, message):
    data = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode()
    peer.sendall(struct.pack(">I", len(data)) + data)


def read_message(peer):
    length = struct.unpack(">I", read_exact(peer, 4))[0]
    assert 0 < length <= 1024
    return json.loads(read_exact(peer, length))


class VM:
    def __init__(self, args, sockets, role, case):
        self.name = role + "-" + case
        self.log_path = args.output / (self.name + ".log")
        self.log = self.log_path.open("xb")
        self.disk = args.image / "source.raw" if role == "send" else args.output / (self.name + ".luks")
        if role == "receive":
            with self.disk.open("xb") as file:
                file.truncate(96 * 1024 * 1024)
        endpoint = sockets / (self.name + ".sock")
        self.peer = None
        self.process = subprocess.Popen([
            "qemu-system-" + args.architecture,
            # QEMU's per-mapping DONTDUMP flag is Linux-only. The Mac laboratory
            # still inherits RLIMIT_CORE=0; it is not a production isolation proof.
            "-machine", ("virt" if args.architecture == "aarch64" else "q35") + (",dump-guest-core=off,mem-merge=off" if platform.system() == "Linux" else ""),
            "-accel", args.accelerator,
            "-cpu", "host" if args.accelerator in ("hvf", "kvm") else "cortex-a72" if args.architecture == "aarch64" else "max",
            "-m", "512", "-smp", "1", "-nodefaults", "-no-reboot", "-display", "none", "-monitor", "none", "-nic", "none", "-serial", "stdio",
            "-object", "rng-random,filename=/dev/urandom,id=rng", "-device", "virtio-rng-pci,rng=rng",
            "-kernel", str(args.image / "kernel"), "-initrd", str(args.image / "initrd"),
            "-append", "root=/dev/vda ro rootfstype=squashfs console=" + ("ttyAMA0" if args.architecture == "aarch64" else "ttyS0") + f" loglevel=4 panic=-1 oblivion.copy={role} oblivion.case={case}",
            "-drive", f"file={args.image / 'guest.squashfs'},format=raw,if=none,id=root,readonly=on",
            "-device", "virtio-blk-pci,drive=root,serial=oblivion-root",
            "-drive", f"file={self.disk},format=raw,if=none,id=data,cache=none" + (",readonly=on" if role == "send" else ""),
            "-device", "virtio-blk-pci,drive=data,serial=copy-data",
            "-device", "virtio-serial-pci",
            "-chardev", f"socket,id=copy,path={endpoint},server=on,wait=off",
            "-device", "virtserialport,chardev=copy,name=oblivion.copy",
        ], stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 90
            while not endpoint.exists():
                assert self.process.poll() is None and time.monotonic() < deadline, self.name
                time.sleep(0.05)
            self.peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.peer.settimeout(30)
            while True:
                try:
                    self.peer.connect(str(endpoint))
                    break
                except ConnectionRefusedError:
                    assert self.process.poll() is None and time.monotonic() < deadline, self.log_path.read_text(errors="replace")[-3000:]
                    time.sleep(0.05)
            while b"OBLIVION_COPY_READY" not in self.log_path.read_bytes():
                assert self.process.poll() is None and time.monotonic() < deadline, self.log_path.read_text(errors="replace")[-3000:]
                time.sleep(0.05)
        except BaseException:
            self.close()
            raise

    def finish(self):
        if self.peer:
            self.peer.close()
            self.peer = None
        assert self.process.wait(timeout=45) == 0, self.name
        data = self.log_path.read_bytes()
        assert b"OBLIVION_COPY_PASS" in data and b"OBLIVION_COPY_FAIL" not in data, data[-4000:]

    def close(self):
        if self.peer:
            self.peer.close()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


class Relay:
    """Run the Linux product relay with private QEMU ports and a control socket."""
    def __init__(self, args, sender, receiver, case):
        self.peer, controller = socket.socketpair()
        self.peer.settimeout(30)
        self.log = (args.output / ("relay-" + case + ".log")).open("xb")
        fds = [fcntl.fcntl(peer.fileno(), fcntl.F_DUPFD_CLOEXEC, 10) for peer in (sender.peer, receiver.peer, controller)]
        # The shell only duplicates numeric descriptors; it never sees selected
        # filenames, approval or content. Close the originals before exec so
        # relay exit really disconnects both ports. No preexec_fn/FD-order race.
        script = f'exec 3<&{fds[0]} 4<&{fds[1]} 5<&{fds[2]}; exec {fds[0]}<&- {fds[1]}<&- {fds[2]}<&-; exec "$@"'
        try:
            self.process = subprocess.Popen(["/bin/bash", "-c", script, "oblivion-relay", str(args.bundle / "oblivion-copy-relay"), "30000"],
                pass_fds=fds, env={}, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self.log)
        finally:
            for fd in fds:
                os.close(fd)
            controller.close()
        sender.peer.close()
        sender.peer = None
        receiver.peer.close()
        receiver.peer = None

    def finish(self, success):
        assert self.process.wait(timeout=10) == (0 if success else 1)
        self.log.flush()
        assert Path(self.log.name).read_bytes() == (b"" if success else b"transfer_failed\n")

    def close(self):
        self.peer.close()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


def run(args, checks):
    original = digest(args.image / "source.raw")
    with ExitStack() as resources:
        sockets = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="obl-copy-", dir="/tmp")))
        sender = VM(args, sockets, "send", "success")
        resources.callback(sender.close)
        receiver = VM(args, sockets, "receive", "success")
        resources.callback(receiver.close)
        sender.peer.sendall(b"G")
        receiver.peer.sendall(b"G")
        relay = Relay(args, sender, receiver, "success") if platform.system() == "Linux" else None
        if relay:
            resources.callback(relay.close)
        offer = relay.peer if relay else sender.peer
        limits = {"entries": 64, "bytes": 1024 * 1024}
        write_message(offer, {"id": ID, "limits": limits, "paths": ["documents"]})
        assert read_exact(offer, 8) == b"OBLVCP01"
        length = struct.unpack(">I", read_exact(offer, 4))[0]
        assert 0 < length <= 1024 * 1024
        encoded = read_exact(offer, length)
        manifest = json.loads(encoded)
        files = {item["path"]: item for item in manifest if item["kind"] == "file"}
        assert set(files) == set(FILES)
        for name, data in FILES.items():
            assert files[name]["size"] == len(data) and files[name]["sha256"] == hashlib.sha256(data).hexdigest()
        approval = {"id": ID, "manifest_sha256": hashlib.sha256(encoded).hexdigest()}
        if relay:
            write_message(relay.peer, approval)
            receipt = read_message(relay.peer)
            relay.finish(True)
        else:
            write_message(receiver.peer, {"approval": approval, "limits": limits})
            receiver.peer.sendall(b"OBLVCP01" + struct.pack(">I", len(encoded)) + encoded)
            assert read_exact(receiver.peer, 8) == b"receive\n"
            write_message(sender.peer, approval)
            remaining = sum(map(len, FILES.values())) + 8
            while remaining:
                data = read_exact(sender.peer, min(65536, remaining))
                receiver.peer.sendall(data)
                remaining -= len(data)
            receipt = read_message(receiver.peer)
            write_message(sender.peer, receipt)
            assert read_exact(sender.peer, 7) == b"copied\n"
        assert receipt == {"id": ID, "manifest_sha256": approval["manifest_sha256"], "entries": len(manifest), "bytes": sum(map(len, FILES.values()))}
        sender.finish()
        receiver.finish()
        checks.append("Real compiled endpoints copy only selected files through separate virtio-serial ports and a bounded host relay; the receiver verifies bytes and the sender verifies its receipt.")
        checks.append("Both guests verify readonly system images, no network interface beyond loopback, no swap and no shared filesystem mount.")
        checks.append("The receiver publishes the verified tree inside its LUKS2 volume, flushes, unmounts and closes the mapping before normal VM shutdown.")
        assert digest(args.image / "source.raw") == original
        checks.append("The synthetic external source disk is passed readonly and remains byte-identical after the transfer.")

        cancelled = VM(args, sockets, "receive", "cancel")
        resources.callback(cancelled.close)
        cancelled.peer.sendall(b"G")
        write_message(cancelled.peer, {"approval": approval, "limits": limits})
        cancelled.peer.sendall(b"OBLVCP01" + struct.pack(">I", len(encoded)) + encoded)
        assert read_exact(cancelled.peer, 8) == b"receive\n"
        cancelled.peer.sendall(b"x")
        cancelled.peer.close()
        cancelled.peer = None
        cancelled.finish()
        checks.append("Disconnecting a real virtio-serial transfer leaves no partial transaction; the receiver closes its encrypted volume and powers down.")

        if relay:
            for case in ("control-cancel", "owner-death"):
                sender = VM(args, sockets, "send", case)
                resources.callback(sender.close)
                receiver = VM(args, sockets, "receive", case)
                resources.callback(receiver.close)
                sender.peer.sendall(b"G")
                receiver.peer.sendall(b"G")
                worker = Relay(args, sender, receiver, case)
                resources.callback(worker.close)
                write_message(worker.peer, {"id": ID, "limits": limits, "paths": ["documents"]})
                assert read_exact(worker.peer, 8) == b"OBLVCP01"
                size = struct.unpack(">I", read_exact(worker.peer, 4))[0]
                assert size == len(encoded) and read_exact(worker.peer, size) == encoded
                if case == "control-cancel":
                    worker.peer.shutdown(socket.SHUT_WR)
                if case == "owner-death":
                    receiver.process.kill()
                    receiver.process.wait(timeout=5)
                assert worker.peer.recv(1) == b""
                worker.finish(False)
                sender.finish()
                if case == "control-cancel":
                    receiver.finish()
            checks.append("The compiled Linux relay transfers only metadata on its control channel and verifies hashes and receipts before reporting success.")
            checks.append("Closing the control connection before approval disconnects both real VM ports; neither endpoint reports a completed copy.")
            checks.append("SIGKILL of the destination QEMU revokes the relay through its socket-bound pidfd while the source VM remains live; the source endpoint fails and shuts down normally.")

    for path in args.output.glob("*.luks"):
        with path.open("rb") as file:
            assert file.read(6) == b"LUKS\xba\xbe"
            file.seek(0)
            tail = b""
            while chunk := file.read(8 * 1024 * 1024):
                assert CANARY not in tail + chunk, path.name
                tail = chunk[-len(CANARY):]
    checks.append("The synthetic document canary is absent from every recipient disk image after its VM exits; the source fixture intentionally retains its plaintext original.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--architecture", choices=["aarch64", "x86_64"], default="aarch64")
    parser.add_argument("--accelerator", choices=["hvf", "kvm", "tcg"], default="hvf")
    args = parser.parse_args()
    if args.accelerator == "hvf" and (platform.system(), platform.machine(), args.architecture) != ("Darwin", "arm64", "aarch64"):
        parser.error("HVF requires macOS ARM64")
    if args.accelerator == "kvm" and (platform.system() != "Linux" or platform.machine() != args.architecture or not os.access("/dev/kvm", os.R_OK | os.W_OK)):
        parser.error("Requested KVM unavailable; no fallback")
    args.image = args.image.resolve()
    args.bundle = args.bundle.resolve()
    args.output = args.output.resolve()
    assert not any("," in str(p) for p in (args.image, args.output)), "QEMU option separator in path"
    manifest = verify(args.image)
    bundle = verify(args.bundle)
    endpoint = digest(args.bundle / "oblivion-copy")
    assert endpoint == (args.image / "endpoint.sha256").read_text().split()[0]
    args.output.mkdir(parents=True, exist_ok=False)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    started = time.monotonic()
    checks = []
    summary = {"passed": False, "architecture": args.architecture, "accelerator": args.accelerator,
               "scope": "Synthetic virtual disks and separate VM endpoints; no physical USB, trusted manager, production controller grant or chat delivery tested.",
               "endpoint_sha256": endpoint, "bundle_manifest": bundle, "image_manifest": manifest,
               "relay": {"kind": "compiled-linux", "sha256": digest(args.bundle / "oblivion-copy-relay")} if platform.system() == "Linux" else {"kind": "python-laboratory"},
               "source_manifest": (args.bundle / "sources.sha256").read_text(),
               "runner_sha256": digest(Path(__file__)), "checks": checks}
    try:
        run(args, checks)
        summary["passed"] = True
    finally:
        summary["seconds"] = round(time.monotonic() - started, 2)
        summary["disks"] = {p.name: digest(p) for p in args.output.glob("*.luks")}
        (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps({k: summary[k] for k in ("passed", "seconds", "checks")}, indent=2))


if __name__ == "__main__":
    main()
