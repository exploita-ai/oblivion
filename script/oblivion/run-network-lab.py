#!/usr/bin/env python3
"""Two disposable ARM VMs; packet capture outside the untrusted guest."""
import argparse
import gzip
import hashlib
import json
import platform
import queue
import re
import resource
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import zlib
from pathlib import Path
from packet_capture import capture


def validate_accelerator(accelerator):
    if accelerator == "hvf":
        assert (platform.system(), platform.machine()) == ("Darwin", "arm64"), "HVF requires an ARM Mac"
        return
    assert accelerator == "tcg" and platform.system() == "Linux", "TCG laboratory requires Linux"


class VM:
    def __init__(self, role, image, output, wire, online, accelerator="hvf"):
        validate_accelerator(accelerator)
        self.role = role
        self.output = output
        self.messages = queue.Queue()
        self.sequence = 0
        # Stream reconnection is disabled by default in QEMU 8.2 and 10.x.
        # Direct kernel boot needs no PXE ROM (absent on minimal CI runners).
        network = ["-netdev", f"stream,id=inside,server={'on' if role == 'gateway' else 'off'},addr.type=unix,addr.path={wire}",
            "-device", "virtio-net-pci,romfile=,netdev=inside,mac=52:54:00:6f:00:" + ("01" if role == "gateway" else "03"),
            "-object", f"filter-dump,id=inside-capture,netdev=inside,file={output / (role + '-inside.pcap')}"]
        if role == "gateway":
            network += ["-netdev", f"user,id=outside,ipv6=off,restrict={'off' if online else 'on'}",
                "-device", "virtio-net-pci,romfile=,netdev=outside,mac=52:54:00:6f:00:02",
                "-object", f"filter-dump,id=outside-capture,netdev=outside,file={output / 'gateway-outside.pcap'}",
                "-device", "virtio-serial-pci",
                "-chardev", f"socket,id=control,path={wire.parent / 'control.sock'},server=on,wait=off",
                "-device", "virtserialport,chardev=control,name=oblivion.gateway"]
        self.process = subprocess.Popen([
            "qemu-system-aarch64", "-machine", "virt", "-accel", accelerator,
            "-cpu", "host" if accelerator == "hvf" else "max", "-m", "1024" if role == "gateway" else "512", "-smp", "2",
            "-nodefaults", "-no-reboot", "-display", "none", "-monitor", "none", "-serial", "stdio",
            "-object", "rng-random,filename=/dev/urandom,id=rng", "-device", "virtio-rng-pci,rng=rng",
            "-kernel", str(image / "kernel"), "-initrd", str(output / "lab-initrd"),
            "-append", f"console=ttyAMA0 root=/dev/vda rootfstype=squashfs ro loglevel=4 systemd.show_status=true systemd.unit=oblivion-{role}-lab.target panic=-1",
            "-drive", f"file={image / 'laboratory.squashfs'},format=raw,if=none,id=root,readonly=on",
            "-device", "virtio-blk-pci,drive=root", *network,
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        with (self.output / f"{self.role}.log").open("xb") as log:
            for line in self.process.stdout:
                log.write(line)
                log.flush()
                text = line.decode(errors="replace").strip()
                if "OBLIVION_NET " in text:
                    self.messages.put(json.loads(text.split("OBLIVION_NET ", 1)[1]))
        self.messages.put({"exited": True})

    def receive(self, timeout=120):
        message = self.messages.get(timeout=timeout)
        assert "exited" not in message, f"{self.role} exited; inspect its laboratory log"
        return message

    def ready(self, fixture_hash):
        value = self.receive()
        assert value == {"ready": self.role, "fixture_sha256": fixture_hash}, value

    def call(self, operation, **configuration):
        self.sequence += 1
        message = {"id": self.sequence, "operation": operation, **configuration}
        self.process.stdin.write((json.dumps(message) + "\n").encode())
        self.process.stdin.flush()
        value = self.receive()
        if not value.get("ok"):
            # A failed fixture exits and powers off. Drain its diagnostic before
            # cleanup can terminate QEMU and lose the actual assertion reason.
            self.reader.join(timeout=10)
        assert value.get("id") == self.sequence and value.get("ok"), value
        return value.get("result")

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.reader.join(timeout=10)


class Control:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(15)
        self.socket.connect(str(path))

    def receive(self):
        def read(length):
            chunks = bytearray()
            while len(chunks) < length:
                part = self.socket.recv(length - len(chunks))
                assert part, "private control stream closed"
                chunks.extend(part)
            return chunks
        length = struct.unpack("!I", read(4))[0]
        assert 0 < length <= 512 * 1024
        return json.loads(read(length))

    def call(self, operation, **fields):
        body = json.dumps({"operation": operation, **fields}).encode()
        self.socket.sendall(struct.pack("!I", len(body)) + body)
        reply = self.receive()
        assert reply.get("ok"), reply
        return reply

    def close(self):
        self.socket.close()


def drops(snapshot, chain, owner=False):
    total = 0
    for item in snapshot["nftables"]:
        rule = item.get("rule", {})
        if rule.get("chain") != chain or not any("drop" in part for part in rule["expr"]):
            continue
        if owner and not any(part.get("match", {}).get("left", {}).get("meta", {}).get("key") == "skuid" for part in rule["expr"]):
            continue
        total += sum(part.get("counter", {}).get("packets", 0) for part in rule["expr"])
    return total


def overlay_fixture(image, output):
    original = (image / "initrd").read_bytes()
    order = None
    for header in re.finditer(b"\x1f\x8b\x08", original):
        try:
            archive = gzip.decompress(original[header.start():])
        except (zlib.error, EOFError, gzip.BadGzipFile):
            continue
        order = subprocess.check_output(["bsdtar", "-xOf", "-", "scripts/init-bottom/ORDER"], input=archive)
        break
    assert order is not None
    with tempfile.TemporaryDirectory(prefix="oblivion-net-initrd-") as temporary:
        root = Path(temporary)
        (root / "scripts/init-bottom").mkdir(parents=True)
        shutil.copyfile(Path(__file__).with_name("vm-network-fixture.py"), root / "scripts/oblivion-network-fixture")
        shutil.copyfile(Path(__file__).resolve().parents[2] / "packages/oblivion-gateway/guest/network.sh", root / "scripts/oblivion-gateway-network")
        (root / "scripts/network-debug.conf").write_text('[Unit]\nOnFailure=poweroff.target\n'
            '[Service]\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n')
        hook = root / "scripts/init-bottom/zz-oblivion-network-fixture"
        hook.write_text('#!/bin/sh\nset -eu\ncase "${1:-}" in prereqs) exit 0;; esac\n'
            'mount --bind /scripts/oblivion-network-fixture "${rootmnt:-/root}/usr/libexec/oblivion-network-fixture"\n'
            'chmod 0755 /scripts/oblivion-gateway-network\n'
            'mount --bind /scripts/oblivion-gateway-network "${rootmnt:-/root}/usr/libexec/oblivion-gateway-network"\n'
            'mkdir -p /run/systemd/system/oblivion-gateway-network.service.d\n'
            'cp /scripts/network-debug.conf /run/systemd/system/oblivion-gateway-network.service.d/lab.conf\n')
        hook.chmod(0o755)
        (hook.parent / "ORDER").write_bytes(order + b'\n/scripts/init-bottom/zz-oblivion-network-fixture "$@"\n')
        archive = subprocess.check_output(["bsdtar", "--format=newc", "--uid=0", "--gid=0", "-cf", "-", "scripts"], cwd=root)
    (output / "lab-initrd").write_bytes(original + gzip.compress(archive, mtime=0))


def verify_image(image, overlay=False):
    for line in (image / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split()
        assert Path(name).name == name and hashlib.sha256((image / name).read_bytes()).hexdigest() == digest
    repository = Path(__file__).resolve().parents[2]
    for line in (image / "broker-sources.sha256").read_text().splitlines():
        digest, name = line.split()
        source = repository / "packages/oblivion-gateway" / name
        assert hashlib.sha256(source.read_bytes()).hexdigest() == digest, f"rebuild broker: {source}"
    # By default test the exact built image. Development overlays are explicit
    # and cannot hide an old firewall, Tor policy or service configuration.
    for line in (image / "sources.sha256").read_text().splitlines():
        digest, name = line.split()
        if name.startswith("./guest/"):
            if overlay and Path(name).name == "network.sh":
                continue
            source = repository / "packages/oblivion-gateway/guest" / Path(name).name
            assert hashlib.sha256(source.read_bytes()).hexdigest() == digest, f"rebuild image: {source}"
        if name.startswith("./lab/"):
            if overlay and Path(name).name == "vm-network-fixture.py":
                continue
            source = Path(__file__).with_name(Path(name).name)
            assert hashlib.sha256(source.read_bytes()).hexdigest() == digest, f"rebuild image: {source}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--accelerator", choices=["hvf", "tcg"], default="hvf", help="Explicit lab backend: Mac HVF or Linux software emulation; never falls back")
    parser.add_argument("--overlay", action="store_true", help="Development only: load the current fixture and network script in RAM")
    parser.add_argument("--tor-online", action="store_true", help="Allow Tor to bootstrap and check HTTPS via check.torproject.org; no provider requests")
    parser.add_argument("--control-fault", choices=["disconnect", "shutdown", "malformed", "oversized", "partial", "duplicate-grant", "supervisor-crash", "broker-crash", "egress-crash"], default="disconnect")
    args = parser.parse_args()
    validate_accelerator(args.accelerator)
    # Linux's dump-guest-core property is unavailable with HVF. Suppress core
    # dumps for this runner and its QEMU children on either lab backend.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    image = args.image.resolve()
    output = args.output.resolve()
    assert all("," not in str(path) for path in [image, output])
    verify_image(image, args.overlay)
    output.mkdir(parents=True, exist_ok=False)
    if args.overlay:
        overlay_fixture(image, output)
    else:
        shutil.copyfile(image / "initrd", output / "lab-initrd")
    checks = []
    started = time.monotonic()
    fixture_hash = hashlib.sha256(Path(__file__).with_name("vm-network-fixture.py").read_bytes()).hexdigest()
    summary = {"scope": "two independent Debian ARM VMs; synthetic API credentials; no LUKS lifecycle or OpenCode integration",
        "accelerator": args.accelerator, "host_system": platform.system(), "hardware_isolation_verified": False,
        "online_tor_requested": args.tor_online, "provider_requests": False, "checks": checks, "passed": False,
        "image_manifest": (image / "SHA256SUMS").read_text(), "fixture_sha256": fixture_hash,
        "runtime_overlays": ["fixture", "network script", "error console"] if args.overlay else [],
        "control_fault": args.control_fault,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    summary["runtime_initrd_sha256"] = hashlib.sha256((output / "lab-initrd").read_bytes()).hexdigest()
    summary["runtime_network_script_sha256"] = hashlib.sha256((Path(__file__).resolve().parents[2] / "packages/oblivion-gateway/guest/network.sh").read_bytes()).hexdigest()

    def check(message):
        checks.append(message)
        print("PASS: " + message, flush=True)

    vms = []
    control = None
    try:
        with tempfile.TemporaryDirectory(prefix="oblivion-net-", dir="/tmp") as temporary:
            wire = Path(temporary) / "inside.sock"
            gateway = VM("gateway", image, output, wire, args.tor_online, args.accelerator)
            vms.append(gateway)
            deadline = time.monotonic() + 10
            while not wire.exists() or not (wire.parent / "control.sock").exists():
                assert gateway.process.poll() is None and time.monotonic() < deadline
                time.sleep(0.01)
            control = Control(wire.parent / "control.sock")
            chat = VM("chat", image, output, wire, args.tor_online, args.accelerator)
            vms.append(chat)
            gateway.ready(fixture_hash)
            chat.ready(fixture_hash)
            assert control.receive() == {"ready": True, "version": 1}
            assert control.call("status") == {"ok": True, "configured": False, "active": False}
            check("separate VMs boot read-only with no shared filesystem; Tor is not started before a transport is selected")
            key = "synthetic-" + secrets.token_hex(32)
            token = secrets.token_hex(32)
            assert control.call("configure", api_key=key) == {"ok": True, "configured": True, "active": False}
            control.call("tor-initialize", state=None)
            assert control.call("grant", token=token) == {"ok": True, "configured": True, "active": True}
            summary["processes"] = gateway.call("supervisor-info")
            check("private virtio control configures the production supervisor; API and egress children use distinct UIDs, no capabilities, no environment and no core dumps")
            assert chat.call("request", token="invalid")["status"] == 401
            assert chat.call("request", token=token)["status"] == 502
            check("chat reaches the production API broker; token checked; disabled Tor fails closed")
            gateway.call("forwarding-on")
            probes = chat.call("probes")
            assert probes["interfaces"] == ["chat0", "lo"] and probes["ipv6_denied"]
            rules = gateway.call("rules")
            assert drops(rules, "input") > 0 and drops(rules, "forward") > 0
            (output / "rules-after-probes.json").write_text(json.dumps(rules, indent=2) + "\n")
            check("root in the chat cannot reach listening administration/SOCKS sockets or forward TCP, DNS, UDP/QUIC and IPv6")
            before = drops(rules, "output", owner=True)
            gateway.call("direct-denied")
            assert drops(gateway.call("rules"), "output", owner=True) > before
            check("API process UID cannot connect directly to a public IP")
            shutil.copyfile(output / "gateway-outside.pcap", output / "before-tor-outside.pcap")
            summary["before_tor"] = capture(output / "before-tor-outside.pcap")
            assert summary["before_tor"]["ipv4"] == 0 and summary["before_tor"]["ipv6"] == 0
            check("external packet capture sees zero IP packets before Tor activation, including startup and bypass probes")
            gateway.call("forwarding-off")
            if args.tor_online:
                gateway.call("tor-enable")
                deadline = time.monotonic() + 240
                while not gateway.call("tor-status")["bootstrapped"]:
                    assert time.monotonic() < deadline, "Tor bootstrap deadline"
                    time.sleep(1)
                assert gateway.call("tor-check") == {"is_tor": True, "verified_tls": True}
                check("real Tor bootstraps and Tor Project confirms an HTTPS request exits through Tor")
            gateway.call("tor-crash")
            assert chat.call("request", token=token)["status"] == 502
            check("crashing Tor makes API calls fail without a direct fallback")
            assert not control.call("revoke")["active"]
            assert chat.call("disconnected")["disconnected"]
            assert not control.call("revoke")["active"]
            next_token = secrets.token_hex(32)
            assert control.call("grant", token=next_token)["active"]
            assert chat.call("request", token=token)["status"] == 401
            assert chat.call("request", token=next_token)["status"] == 502
            check("revocation closes the listener and the next API instance rejects the previous token")
            # Restore a live (offline) Tor process: cleanup must kill it, not
            # merely observe the earlier deliberate Tor crash.
            assert gateway.call("tor-restart-disabled") == {"active": True, "network_disabled": True}
            if args.control_fault == "disconnect":
                control.close()
            elif args.control_fault == "shutdown":
                assert not control.call("shutdown")["active"]
            elif args.control_fault in ["supervisor-crash", "broker-crash", "egress-crash"]:
                gateway.call(args.control_fault)
            else:
                body = json.dumps({"operation": "status", "api_key": key}).encode()
                if args.control_fault == "duplicate-grant":
                    body = json.dumps({"operation": "grant", "token": secrets.token_hex(32)}).encode()
                payload = struct.pack("!I", len(body)) + body
                if args.control_fault == "oversized":
                    payload = struct.pack("!I", 512 * 1024 + 1)
                if args.control_fault == "partial":
                    payload = struct.pack("!I", 64) + b"{"
                control.socket.sendall(payload)
                assert control.receive() == {"ok": False, "error": "control_failed"}
            summary["stopped"] = gateway.call("supervisor-stopped")
            assert chat.call("disconnected")["disconnected"]
            check("control fault " + args.control_fault + " removes broker and connector, clears route selectors and stops Tor without automatic restart")
            gateway.stop()
            assert chat.call("disconnected")["disconnected"]
            check("gateway termination leaves the chat without an alternative network path")
            chat.call("poweroff")
            chat.process.wait(timeout=30)
            chat.reader.join(timeout=10)
            for role in ["chat", "gateway"]:
                assert key.encode() not in (output / f"{role}.log").read_bytes()
            check("synthetic provider credential never appears in either VM console log")
            summary["captures"] = {path.name: capture(path) for path in output.glob("*.pcap")}
            outside = summary["captures"]["gateway-outside.pcap"]
            assert outside["udp"] == 0 and outside["ipv6"] == 0 and outside["ipv4"] == outside["tcp"]
            assert (outside["tcp"] > 0) == args.tor_online
            check("complete external capture contains only TCP after Tor activation and no UDP or IPv6")
            summary["passed"] = True
    finally:
        if control is not None:
            control.close()
        for vm in vms:
            vm.stop()
        summary["seconds"] = round(time.monotonic() - started, 2)
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps({"passed": summary["passed"], "checks": len(checks), "seconds": summary["seconds"]}), flush=True)


if __name__ == "__main__":
    main()
