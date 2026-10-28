#!/usr/bin/env python3
"""Boot the actual isolated onion gateway, with no allowed external network.

No session disk, provider key or secret input. The production private virtio
protocol is exercised directly; an image-only root diagnostic checks teardown.
This is control/profile evidence, not a real Tor sender/recipient round trip.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import queue
import secrets
import socket
import struct
import subprocess
import tempfile
import threading
import time


class VM:
    def __init__(self, image, output, runtime, accelerator):
        self.messages = queue.Queue()
        self.sequence = 0
        self.control = socket.socket(socket.AF_UNIX)
        self.control.settimeout(60)
        self.process = subprocess.Popen([
            "qemu-system-aarch64", "-machine", "virt", "-accel", accelerator,
            "-cpu", "host" if accelerator == "hvf" else "max", "-m", "512", "-smp", "2",
            "-S", "-nodefaults", "-no-user-config", "-no-reboot", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-qmp", f"unix:{runtime}/qmp.sock,server=on,wait=off",
            "-object", "rng-random,filename=/dev/urandom,id=rng", "-device", "virtio-rng-pci,rng=rng",
            "-kernel", str(image / "kernel"), "-initrd", str(image / "initrd"),
            "-append", "console=ttyAMA0 root=/dev/vda rootfstype=squashfs ro loglevel=3 systemd.show_status=false systemd.unit=oblivion-onion-lab.target panic=-1",
            "-drive", f"file={image}/laboratory.squashfs,format=raw,if=none,id=root,readonly=on",
            "-device", "virtio-blk-pci,drive=root", "-device", "virtio-serial-pci",
            "-chardev", f"socket,id=control,path={runtime}/control.sock,server=on,wait=off",
            "-device", "virtserialport,chardev=control,name=oblivion.onion-gateway",
            "-netdev", f"stream,id=inside,server=on,addr.type=unix,addr.path={runtime}/inside.sock",
            "-device", "virtio-net-pci,romfile=,netdev=inside,mac=52:54:00:6f:00:01",
            "-netdev", "user,id=outside,ipv6=off,restrict=on",
            "-device", "virtio-net-pci,romfile=,netdev=outside,mac=52:54:00:6f:00:02",
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        self.reader = threading.Thread(target=self.read, args=(output,), daemon=True)
        self.reader.start()
        try:
            self.boot(runtime)
        except BaseException:
            self.stop()
            raise

    def boot(self, runtime):
        deadline = time.monotonic() + 15
        while not (runtime / "control.sock").is_socket() or not (runtime / "qmp.sock").is_socket():
            assert self.process.poll() is None and time.monotonic() < deadline, "QEMU did not start"
            time.sleep(0.02)
        self.control.connect(str(runtime / "control.sock"))
        with socket.socket(socket.AF_UNIX) as qmp:
            qmp.settimeout(5)
            qmp.connect(str(runtime / "qmp.sock"))
            with qmp.makefile("rwb", buffering=0) as stream:
                assert "QMP" in json.loads(stream.readline())
                for command in ("qmp_capabilities", "cont"):
                    stream.write(json.dumps({"execute": command}).encode() + b"\n")
                    while "return" not in json.loads(stream.readline()):
                        pass
        # The initial greeting includes Debian boot under software emulation.
        # Restore the control-operation deadline once the owner is available.
        self.control.settimeout(120)
        self.hello = self.receive()
        self.control.settimeout(60)
        assert self.hello == {"ready": True, "version": 1, "role": "onion-gateway"}, self.hello
        assert self.messages.get(timeout=60) == {"ready": True}

    def read(self, output):
        pending = b""
        with output.open("xb") as log:
            while chunk := self.process.stdout.read(65536):
                log.write(chunk)
                log.flush()
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    if b"OBLIVION_ONION_LAB " in line:
                        self.messages.put(json.loads(line.split(b"OBLIVION_ONION_LAB ", 1)[1]))
        self.messages.put({"exited": True})

    def exact(self, length):
        data = b""
        while len(data) < length:
            chunk = self.control.recv(length - len(data))
            assert chunk, "Private gateway channel closed"
            data += chunk
        return data

    def receive(self):
        length = struct.unpack(">I", self.exact(4))[0]
        assert 0 < length <= 512 * 1024
        return json.loads(self.exact(length))

    def command(self, operation, **fields):
        data = json.dumps({"operation": operation, **fields}).encode()
        self.control.sendall(struct.pack(">I", len(data)) + data)
        return self.receive()

    def diagnostic(self, operation):
        self.process.stdin.write(json.dumps({"operation": operation}).encode() + b"\n")
        self.process.stdin.flush()
        response = self.messages.get(timeout=30)
        assert response.get("ok"), response
        return response

    def stopped(self, expected_policy):
        deadline = time.monotonic() + 30
        while True:
            info = self.diagnostic("info")
            if (info["owner"]["pid"] == 0 and info["tor"]["pid"] == 0
                and info["owner"]["active"] in ("inactive", "failed")
                and info["tor"]["active"] in ("inactive", "failed")
                and info["policy_sha256"] == expected_policy):
                assert info["selectors"] == {"tor_owners": [], "file_ports": []}
                return info
            assert time.monotonic() < deadline, "Gateway cleanup did not complete"
            time.sleep(0.05)

    def stop(self):
        self.control.close()
        if self.process.poll() is None:
            try:
                self.diagnostic("shutdown")
                self.process.wait(timeout=30)
            except Exception:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        self.reader.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--accelerator", choices=("hvf", "tcg"), default="hvf")
    args = parser.parse_args()
    assert (platform.system(), platform.machine()) == ("Darwin", "arm64") if args.accelerator == "hvf" else platform.system() == "Linux"
    args.image = args.image.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = (args.image / "SHA256SUMS").read_text()
    (args.output / "image-SHA256SUMS").write_text(manifest)
    for line in manifest.splitlines():
        expected, filename = line.split(maxsplit=1)
        with (args.image / filename).open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == expected
    checks = []
    started = time.monotonic()
    success = False
    try:
        for scenario in ("clean", "killed-owner", "disconnected-owner", "malformed-command", "partial-frame", "tampered-firewall"):
            with tempfile.TemporaryDirectory(prefix="onion-", dir="/tmp") as directory:
                vm = VM(args.image, args.output / f"{scenario}.log", Path(directory), args.accelerator)
                try:
                    before = vm.diagnostic("info")
                    assert before["controller_sha256"] == (args.image / "controller.sha256").read_text().split()[0]
                    assert before["interfaces"] == ["inside0", "lo", "outside0"]
                    assert before["tor"]["pid"] == 0 and before["selectors"] == {"tor_owners": [], "file_ports": []}
                    initial = vm.command("observe")
                    assert initial == {"ok": True, "isolated": True, "tor_progress": None, "tor_ready": False, "active": False}
                    initialized = vm.command("initialize", state=None)
                    if not initialized.get("initialized"):
                        raise AssertionError({"initialization": initialized, "diagnostic": vm.diagnostic("info")})
                    observed = vm.command("observe")
                    assert observed["tor_progress"] == 0 and observed["isolated"] and not observed["tor_ready"]
                    assert vm.diagnostic("info")["tor"]["pid"] > 1
                    if scenario == "clean":
                        assert vm.command("publish", client_auth="A" * 52, ttl_seconds=30) == {"ok": False, "error": "tor_not_ready"}
                        assert not vm.command("observe")["active"]
                        state = vm.command("snapshot")["state"]
                        assert f"TorVersion Tor {VERSION}" in state and "Guard " not in state
                        assert not any(word in state for word in ("ServiceID", "PrivateKey", "ClientAuth", "Onion"))
                        reply = vm.command("shutdown")
                        assert reply["ok"] and reply["closed"]
                    else:
                        assert vm.command("enable")["ok"]
                        selectors = vm.diagnostic("info")["selectors"]
                        assert selectors == {"tor_owners": [1200], "file_ports": []}
                        if scenario == "killed-owner":
                            vm.diagnostic("kill-owner")
                        elif scenario == "disconnected-owner":
                            vm.control.close()
                        elif scenario == "partial-frame":
                            vm.control.sendall(b"\x00")
                            assert not vm.receive()["ok"]
                        elif scenario == "malformed-command":
                            reply = vm.command("observe", command="SETCONF DisableNetwork=0", nonce=secrets.token_hex(16))
                            assert reply["ok"] is False and reply["error"] == "control_failed"
                        elif scenario == "tampered-firewall":
                            vm.diagnostic("tamper")
                            assert vm.command("observe")["ok"] is False
                    after = vm.stopped(before["policy_sha256"])
                    checks.append({"scenario": scenario, "passed": True, "final": after})
                    print(f"Passed: {scenario}", flush=True)
                finally:
                    vm.stop()
        success = True
    finally:
        (args.output / "summary.json").write_text(json.dumps({"passed": success, "checks": checks,
            "image_manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "seconds": round(time.monotonic() - started, 2), "accelerator": args.accelerator,
            "scope": "Actual production gateway, Tor, systemd and virtio control in a read-only ARM64 VM. External network blocked by QEMU. No file VM, public onion reachability, provider or supported-image qualification."}, indent=2) + "\n")
    return 0


VERSION = "0.4.9.14"
if __name__ == "__main__":
    raise SystemExit(main())
