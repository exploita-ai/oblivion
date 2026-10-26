#!/usr/bin/env python3
"""Disposable Debian host + nested session VMs with synthetic data; never physical disks."""
import argparse
import base64
import gzip
import hashlib
import json
import os
import selectors
import platform
import re
import resource
import shutil
import subprocess
import tempfile
import time
import zlib
from pathlib import Path
from packet_capture import capture

def online_vm(command, log, output):
    # The guest waits for our acknowledgement before starting the online
    # gateway. Snapshot bytes at that barrier; PCAP and guest clocks differ.
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0) as process:
        deadline = time.monotonic() + 900
        pending = b""
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    assert time.monotonic() < deadline, "VM deadline"
                    if not selector.select(timeout=1):
                        continue
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    log.write(chunk)
                    log.flush()
                    pending += chunk
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        if line.strip() != b"OBLIVION_TOR_ENABLE_WAIT":
                            continue
                        before = output / "before-enable.pcap"
                        assert not before.exists()
                        shutil.copyfile(output / "uplink.pcap", before)
                        packets = capture(before)
                        assert packets["ipv4"] == 0 and packets["ipv6"] == 0
                        process.stdin.write(b"go\n")
                        process.stdin.flush()
            process.wait(timeout=max(1, deadline - time.monotonic()))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        return process


parser = argparse.ArgumentParser()
parser.add_argument("--image", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--architecture", choices=["aarch64", "x86_64"], default="aarch64")
parser.add_argument("--accelerator", choices=["hvf", "kvm", "tcg"], default="hvf",
    help="Explicit laboratory backend: ARM Mac HVF, Linux KVM or Linux software emulation")
parser.add_argument("--refresh-tui-test", action="store_true",
    help="Load the current synthetic TUI test into the lab initramfs, without rebuilding Debian")
parser.add_argument("--refresh-import-test", action="store_true",
    help="Load the current synthetic manager import test into the lab initramfs")
parser.add_argument("--services-bundle", type=Path,
    help="Load compiled host binaries, service units and the crash fixture into laboratory RAM")
parser.add_argument("--gateway-bundle", type=Path,
    help="Run gateway component tests in a swap-free Debian VM with loopback only")
parser.add_argument("--adapter-binary", type=Path,
    help="With --gateway-bundle, copy a compiled Linux ARM CLI into verified read-only laboratory RAM")
parser.add_argument("--gateway-image", type=Path,
    help="With --services-bundle, exercise the real host owner and a nested gateway VM")
parser.add_argument("--session-image", type=Path,
    help="With --gateway-image, exercise a networked session and grant rotation")
parser.add_argument("--tor-state", action="store_true", help="Exercise selective Tor state persistence in real LUKS")
parser.add_argument("--stream", action="store_true", help="With laboratory gateway/session images, verify active streams through real storage revocation")
parser.add_argument("--stream-socks", action="store_true", help="With --stream and stream-host, use an external synthetic SOCKS proxy in the offline host")
parser.add_argument("--tor-online", action="store_true", help="With --tor-state, allow Tor bootstrap and capture the outer uplink")
args = parser.parse_args()
if args.stream_socks and not args.stream:
    parser.error("--stream-socks requires --stream")
if args.stream and (not args.session_image or args.tor_state):
    parser.error("--stream requires --session-image and excludes --tor-state")
if args.adapter_binary and not args.gateway_bundle:
    parser.error("--adapter-binary requires --gateway-bundle")
adapter = args.adapter_binary.resolve() if args.adapter_binary else None
adapter_manifest = None
if adapter:
    if "," in str(adapter):
        parser.error("Adapter path contains a QEMU option separator")
    with adapter.open("rb") as file:
        adapter_manifest = {"sha256": hashlib.file_digest(file, "sha256").hexdigest(), "bytes": adapter.stat().st_size}
if args.tor_state and not args.gateway_image:
    parser.error("--tor-state requires --gateway-image")
if args.tor_online and not args.tor_state:
    parser.error("--tor-online requires --tor-state")
if args.session_image and not args.gateway_image:
    parser.error("--session-image requires --gateway-image")
session_image = args.session_image.resolve() if args.session_image else None
session_manifest = None
if session_image:
    session_manifest = (session_image / "SHA256SUMS").read_text()
    for line in session_manifest.splitlines():
        digest, name = line.split()
        if Path(name).name != name or hashlib.sha256((session_image / name).read_bytes()).hexdigest() != digest:
            raise SystemExit("Session image integrity check failed")
if args.gateway_image and not args.services_bundle:
    parser.error("--gateway-image requires --services-bundle")
gateway_image = args.gateway_image.resolve() if args.gateway_image else None
gateway_manifest = None
if gateway_image:
    gateway_manifest = (gateway_image / "SHA256SUMS").read_text()
    for line in gateway_manifest.splitlines():
        digest, name = line.split()
        if Path(name).name != name or hashlib.sha256((gateway_image / name).read_bytes()).hexdigest() != digest:
            raise SystemExit("Gateway image integrity check failed")
if args.accelerator == "hvf" and ((platform.system(), platform.machine()) != ("Darwin", "arm64") or args.architecture != "aarch64"):
    raise SystemExit("HVF requires macOS ARM64.")
if args.accelerator == "tcg" and platform.system() != "Linux":
    raise SystemExit("The TCG laboratory backend requires Linux.")
if args.accelerator == "kvm" and (platform.system() != "Linux" or platform.machine() != args.architecture
        or not os.access("/dev/kvm", os.R_OK | os.W_OK)):
    raise SystemExit(f"KVM unavailable: system={platform.system()}, host={platform.machine()}, target={args.architecture}, "
        f"readable={os.access('/dev/kvm', os.R_OK)}, writable={os.access('/dev/kvm', os.W_OK)}; no fallback.")
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
image = args.image.resolve()
for line in (image / "SHA256SUMS").read_text().splitlines():
    expected, name = line.split()
    if Path(name).name != name or hashlib.sha256((image / name).read_bytes()).hexdigest() != expected:
        raise SystemExit("Host image integrity check failed.")
output = args.output.resolve()
if any("," in str(path) for path in (image, output)):
    raise SystemExit("Paths containing QEMU option separators are unsupported.")
output.mkdir(parents=True, exist_ok=False)
initrd = image / "initrd"
fixture = None
bundle_manifest = None
bundle = args.services_bundle or args.gateway_bundle
fixture_name = "vm-import-test.py" if args.refresh_import_test else "vm-tor-state-test.py" if args.tor_state else "vm-session-network-test.py" if session_image else "vm-gateway-host-test.py" if gateway_image else "vm-gateway-test.py" if args.gateway_bundle else "vm-services-test.py" if args.services_bundle else "vm-tui-test.py"
if sum(bool(option) for option in (args.refresh_tui_test, args.refresh_import_test, args.services_bundle, args.gateway_bundle)) > 1:
    raise SystemExit("Choose one laboratory fixture override.")
if args.refresh_tui_test or args.refresh_import_test or bundle:
    if not (image / ("import-lab" if args.refresh_import_test else "tui-lab")).exists():
        raise SystemExit("The fixture override requires a tui-host laboratory image.")
    fixture = Path(__file__).with_name(fixture_name).read_bytes()
    if bundle:
        bundle_manifest = (bundle / "SHA256SUMS").read_text()
        for line in bundle_manifest.splitlines():
            digest, name = line.split()
            if Path(name).name != name or hashlib.sha256((bundle / name).read_bytes()).hexdigest() != digest:
                raise SystemExit("Laboratory bundle integrity check failed.")
    # Debian's initramfs-tools executes its generated ORDER file, not every
    # executable in init-bottom. Preserve that order and append the lab hook.
    order = None
    for header in re.finditer(b"\x1f\x8b\x08", initrd.read_bytes()):
        try:
            archive = gzip.decompress(initrd.read_bytes()[header.start():])
        except (zlib.error, EOFError, gzip.BadGzipFile):
            continue
        result = subprocess.run(["bsdtar", "-xOf", "-", "scripts/init-bottom/ORDER"],
            input=archive, capture_output=True, check=True)
        order = result.stdout
        break
    if order is None:
        raise SystemExit("Cannot find the Debian initramfs hook order; refusing fixture override.")
    with tempfile.TemporaryDirectory(prefix="oblivion-lab-initrd-") as temporary:
        root = Path(temporary)
        (root / "scripts/init-bottom").mkdir(parents=True)
        (root / "scripts/oblivion-lab-test.py").write_bytes(fixture)
        bundle_hook = ""
        if bundle:
            (root / "scripts/oblivion-host").mkdir()
            # Copy only manifest-covered inputs; a previous export may have left
            # stale units in the output directory after a source file was removed.
            for name in [line.split()[1] for line in bundle_manifest.splitlines()] + ["SHA256SUMS"]:
                shutil.copy2(bundle / name, root / "scripts/oblivion-host" / name)
            bundle_hook = ('mkdir /run/oblivion-lab-bundle\n'
                'mount -t tmpfs -o mode=0755,nodev,nosuid,size=64m tmpfs /run/oblivion-lab-bundle\n'
                'cp -a /scripts/oblivion-host/. /run/oblivion-lab-bundle/\n'
                'mount -o remount,ro /run/oblivion-lab-bundle\n')
            if args.services_bundle:
                bundle_hook += ('for binary in oblivion-storage oblivion-storage-lab oblivion-control oblivion-manager; do\n'
                    ' mount --bind "/run/oblivion-lab-bundle/$binary" "${rootmnt:-/root}/usr/bin/$binary"\n'
                    'done\n')
        for role, source in [("gateway", gateway_image), ("session", session_image)]:
            if not source:
                continue
            (root / ("scripts/" + role + "-image")).mkdir()
            for name in ["kernel", "initrd"]:
                shutil.copy2(source / name, root / ("scripts/" + role + "-image") / name)
            if args.stream and role == "gateway":
                shutil.copy2(source / "stream.json", root / "scripts/gateway-image/stream.json")
            if role == "session":
                shutil.copy2(source / "opencode.sha256", root / "scripts/session-image/opencode.sha256")
            metadata = {name: {"sha256": hashlib.sha256((source / name).read_bytes()).hexdigest(),
                "bytes": (source / name).stat().st_size} for name in ["kernel", "initrd", role + ".squashfs"]}
            (root / ("scripts/" + role + "-image/manifest.json")).write_text(json.dumps(metadata))
            bundle_hook += (f'mkdir /run/oblivion-{role}-image\n'
                f'mount -t tmpfs -o mode=0755,nodev,nosuid,size=512m tmpfs /run/oblivion-{role}-image\n'
                f'cp -a /scripts/{role}-image/. /run/oblivion-{role}-image/\n')
        if args.tor_online:
            bundle_hook += "touch /run/oblivion-tor-online\n"
        if args.stream:
            bundle_hook += "touch /run/oblivion-stream-lab\n"
        if args.stream_socks:
            bundle_hook += "touch /run/oblivion-stream-socks\n"
        if adapter_manifest:
            (root / "scripts/adapter.json").write_text(json.dumps(adapter_manifest))
            bundle_hook += ('mkdir /run/oblivion-adapter\n'
                'mount -t tmpfs -o mode=0755,nodev,nosuid,size=512m tmpfs /run/oblivion-adapter\n'
                'cp /scripts/adapter.json /run/oblivion-adapter/manifest.json\n')
        hook = root / "scripts/init-bottom/zz-oblivion-lab-fixture"
        hook.write_text('#!/bin/sh\nset -eu\ncase "${1:-}" in prereqs) exit 0;; esac\n'
            'mount --bind /scripts/oblivion-lab-test.py "${rootmnt:-/root}/usr/libexec/oblivion-vm-test"\n' + bundle_hook)
        hook.chmod(0o755)
        (hook.parent / "ORDER").write_bytes(order + b'\n/scripts/init-bottom/zz-oblivion-lab-fixture "$@"\n')
        archive = subprocess.check_output(["bsdtar", "--format=newc", "--uid=0", "--gid=0",
            "-cf", "-", "scripts"], cwd=root)
    initrd = output / "lab-initrd"
    # Linux accepts concatenated compressed initramfs archives. Only the
    # test and optional host bundle are overlaid; guest filesystems stay fixed.
    initrd.write_bytes((image / "initrd").read_bytes() + gzip.compress(archive, mtime=0))
disk = None if args.gateway_bundle else output / "data.raw"
if disk:
    with disk.open("xb") as stream:
        stream.truncate(1024 * 1024 * 1024)
import_source = output / "import-source.raw" if (image / "import-lab").exists() else None
if import_source:
    # Each fault-injection run owns its media. A mistaken test selection must
    # fail the hash assertion without corrupting a reusable image template.
    shutil.copyfile(image / "import-source.raw", import_source)
import_digest = hashlib.sha256(import_source.read_bytes()).hexdigest() if import_source else None
export_target = output / "export-target.raw" if (image / "export-lab").exists() else None
if export_target:
    shutil.copyfile(image / "export-target.raw", export_target)
started = time.monotonic()
with (output / "serial.log").open("xb") as log:
    command = [
        "qemu-system-" + args.architecture, "-machine", "virt" if args.architecture == "aarch64" else "q35", "-accel", args.accelerator,
        "-cpu", "max" if args.accelerator == "tcg" else "host",
        "-m", "2048" if args.gateway_bundle else "4096", "-smp", "4", "-nodefaults", "-no-reboot", "-display", "none",
        "-monitor", "none", "-serial", "stdio", "-nic", "none",
        "-kernel", str(image / "kernel"), "-initrd", str(initrd),
        "-append", "console=" + ("ttyAMA0" if args.architecture == "aarch64" else "ttyS0") + " root=/dev/vda rootfstype=squashfs ro panic=-1 systemd.getty_auto=no systemd.show_status=false",
        "-drive", f"file={image / 'host.squashfs'},format=raw,if=none,id=root,readonly=on",
        "-device", "virtio-blk-pci,drive=root",
    ] + ([
        "-drive", f"file={disk},format=raw,if=none,id=data,cache=none",
        "-device", "virtio-blk-pci,drive=data",
    ] if disk else []) + ([
        "-drive", f"file={import_source},format=raw,if=none,id=import-source,cache=none",
        "-device", "virtio-blk-pci,drive=import-source,serial=oblivion-import",
    ] if import_source else []) + ([
        "-drive", f"file={export_target},format=raw,if=none,id=export-target,cache=none",
        "-device", "virtio-blk-pci,drive=export-target,serial=oblivion-export",
    ] if export_target else []) + ([
        "-drive", f"file={gateway_image / 'gateway.squashfs'},format=raw,if=none,id=gateway-image,readonly=on",
        "-device", "virtio-blk-pci,drive=gateway-image,serial=oblivion-gw-image",
    ] if gateway_image else []) + ([
        "-drive", f"file={session_image / 'session.squashfs'},format=raw,if=none,id=session-image,readonly=on",
        "-device", "virtio-blk-pci,drive=session-image,serial=oblivion-ss-image",
    ] if session_image else []) + ([
        "-drive", f"file={adapter},format=raw,if=none,id=adapter,readonly=on",
        "-device", "virtio-blk-pci,drive=adapter,serial=oblivion-adapter",
    ] if adapter else []) + ([
        "-netdev", "user,id=uplink,ipv6=off", "-device", "virtio-net-pci,netdev=uplink,mac=52:54:00:6f:00:04",
        "-object", f"filter-dump,id=uplink-capture,netdev=uplink,file={output / 'uplink.pcap'}",
    ] if args.tor_online else [])
    result = online_vm(command, log, output) if args.tor_online else subprocess.run(
        # The expanded 31-check stream lifecycle took 870 seconds on CI x86;
        # keep room for real VM startups without changing any per-operation check.
        command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
        timeout=1200 if args.stream else 900)
serial = (output / "serial.log").read_text(errors="replace")
fixture_prefix = "OBLIVION_IMPORT_FIXTURE_SHA256 " if args.refresh_import_test else "OBLIVION_TOR_STATE_FIXTURE_SHA256 " if args.tor_state else "OBLIVION_SESSION_NETWORK_FIXTURE_SHA256 " if session_image else "OBLIVION_GATEWAY_HOST_FIXTURE_SHA256 " if gateway_image else "OBLIVION_GATEWAY_FIXTURE_SHA256 " if args.gateway_bundle else "OBLIVION_SERVICES_FIXTURE_SHA256 " if args.services_bundle else "OBLIVION_TUI_FIXTURE_SHA256 "
fixture_verified = fixture is None or (fixture_prefix + hashlib.sha256(fixture).hexdigest()) in serial.splitlines()
bundle_prefix = "OBLIVION_GATEWAY_BUNDLE_SHA256 " if args.gateway_bundle else "OBLIVION_HOST_BUNDLE_SHA256 "
bundle_verified = bundle_manifest is None or (bundle_prefix + hashlib.sha256(bundle_manifest.encode()).hexdigest()) in serial.splitlines()
adapter_digest = adapter_manifest["sha256"] if adapter_manifest else (image / "opencode.sha256").read_text().split()[0] if (image / "opencode.sha256").exists() else None
adapter_verified = not args.gateway_bundle or ("OBLIVION_ADAPTER_BINARY_SHA256 " + str(adapter_digest)) in serial.splitlines()
adapter_capture = next((json.loads(line.removeprefix("OBLIVION_ADAPTER_CAPTURE ")) for line in serial.splitlines() if line.startswith("OBLIVION_ADAPTER_CAPTURE ")), None)
markers = [b"OBLIVION_VM_A_CANARY_4d02", b"OBLIVION_VM_B_CANARY_b0ca", b"OBLIVION_VM_TEMP_CANARY_d9ae",
           b"OBLIVION_API_KEY_CANARY_5c91", b"OBLIVION_API_NEXT_CANARY_86ab", b"OBLIVION_API_RAM_CANARY_a13e",
           b"OBLIVION_PROXY_USER_CANARY_31d2", b"OBLIVION_PROXY_PASSWORD_CANARY_72a4",
           b"synthetic-general-password", b"synthetic-session-password-a", b"synthetic-session-password-b"]
if import_source:
    assert hashlib.sha256(import_source.read_bytes()).hexdigest() == import_digest, "Import source changed"
    markers.extend([b"OBLIVION_USB_SELECTED_CANARY_82f1", b"OBLIVION_USB_EDIT_CANARY_1b72", b"OBLIVION_USB_UNSELECTED_CANARY_29a1", b"OBLIVION_IMPORT_PARTIAL_CANARY_c26a"])
if export_target:
    markers.append(b"OBLIVION_EXPORT_EXISTING_CANARY_f4a8")
if args.stream:
    markers.extend([b"OBLIVION_STREAM_REQUEST", b"Synthetic open stream"])
    markers.extend([b"OBLIVION_WEB_TOOLS_REQUEST", b"OBLIVION_WEB_TOOLS_VERIFIED", b"OBLIVION_WEB_HTTP", b"OBLIVION_WEB_HTTPS"])
if (image / "opencode.sha256").exists():
    markers.append(b"OBLIVION_GUEST_CHAT_CANARY_7eaf")
if (image / "tui-lab").exists():
    markers.append(b"OBLIVION_TUI_CANARY_8ac4")
    for line in serial.splitlines():
        if not line.startswith("OBLIVION_SCREENSHOT "):
            continue
        _, name, data = line.split()
        assert name in {"home", "conversation-a", "trusted-confirmation", "resumed-a"}
        (output / f"{name}.png").write_bytes(base64.b64decode(data, validate=True))
found = set()
digest = hashlib.sha256()
if disk:
    with disk.open("rb") as stream:
        overlap = b""
        while chunk := stream.read(4 * 1024 * 1024):
            digest.update(chunk)
            found.update(marker.decode() for marker in markers if marker in overlap + chunk)
            overlap = chunk[-128:]
captures = None
if args.tor_online:
    captures = {"uplink": capture(output / "uplink.pcap"), "before_enable": capture(output / "before-enable.pcap") if (output / "before-enable.pcap").exists() else None}
webtools = None
if args.stream_socks:
    recorded = [line.removeprefix("OBLIVION_WEBTOOLS_PCAP ") for line in serial.splitlines() if line.startswith("OBLIVION_WEBTOOLS_PCAP ")]
    if recorded:
        assert len(recorded) == 1
        path = output / "webtools-outside.pcap"
        path.write_bytes(base64.b64decode(recorded[0], validate=True))
        webtools = capture(path)
        assert webtools["tcp"] > 0 and webtools["tcp"] == webtools["ipv4"]
        assert webtools["udp"] == webtools["ipv6"] == webtools["ipv4_fragments"] == 0
        for source, source_port, destination, destination_port in webtools["tcp_flows"]:
            assert (source == "10.0.2.15" and destination == "10.0.2.2" and destination_port == 9050) or (
                source == "10.0.2.2" and source_port == 9050 and destination == "10.0.2.15")
summary = {
    "scope": "gateway component tests over synthetic loopback SOCKS/TLS; no Tor or provider connection" if args.gateway_bundle else "real LUKS/systemd/QEMU lifecycle with synthetic data; nested TCG is NOT an isolation guarantee",
    "workload": "selective Tor state persistence and bootstrap" if args.tor_state else "session gateway grant, private token delivery and network isolation" if session_image else "general LUKS credentials and real host gateway lifecycle" if gateway_image else "gateway API validation, transport, revocation and Linux activation" if args.gateway_bundle else "systemd service crash/recovery with real manager and VM" if args.services_bundle else ("trusted manager TUI + " if (image / "manager.sha256").exists() else "") + ("compiled interactive OpenCode TUI" if (image / "tui-lab").exists() else "compiled OpenCode CLI" if (image / "opencode.sha256").exists() else "synthetic shell"),
    "import_source_sha256": import_digest,
    "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "export_target_sha256": hashlib.sha256(export_target.read_bytes()).hexdigest() if export_target else None,
    "export_target_plaintext_expected": bool(export_target),
    "outer_accelerator": args.accelerator, "host_system": platform.system(), "architecture": args.architecture,
    "inner_accelerator": None if args.gateway_bundle else "tcg", "production_kvm_tested": False,
    "seconds": round(time.monotonic() - started, 2), "qemu_exit": result.returncode,
    "checks": [line.strip() for line in serial.splitlines() if line.startswith("PASS:")],
    "guest_pass": "OBLIVION_VM_LAB_PASS" in serial, "plaintext_markers_on_disk": sorted(found),
    "disk_scan_canaries": [marker.decode() for marker in markers],
    "disk_sha256": digest.hexdigest() if disk else None, "image_manifest": (image / "SHA256SUMS").read_text(),
    "compiled_sources": (image / "sources.sha256").read_text(),
    "opencode_sha256": adapter_digest,
    "adapter_override": adapter_manifest,
    "adapter_verified": adapter_verified if args.gateway_bundle else None,
    "adapter_capture": adapter_capture,
    "lab_initrd_sha256": hashlib.sha256(initrd.read_bytes()).hexdigest(),
    "runtime_fixture_override": {"file": fixture_name, "sha256": hashlib.sha256(fixture).hexdigest()} if fixture is not None else None,
    "runtime_host_bundle": {"manifest": bundle_manifest, "sources": (bundle / "sources.sha256").read_text(), "verified_in_guest": bundle_verified} if args.services_bundle else None,
    "runtime_gateway_bundle": {"manifest": bundle_manifest, "sources": (bundle / "sources.sha256").read_text(), "verified_in_guest": bundle_verified} if args.gateway_bundle else None,
    "fixture_verified": fixture_verified,
    "gateway_image_manifest": gateway_manifest,
    "session_image_manifest": session_manifest,
    "tor_online": args.tor_online,
    "synthetic_streams": args.stream,
    "external_socks_streams": args.stream_socks,
    "session_opencode_sha256": (session_image / "opencode.sha256").read_text().split()[0] if session_image else None,
    "captures": captures,
    "webtools_outside_capture": webtools,
}
(output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
if result.returncode or not summary["guest_pass"] or found or not fixture_verified or not bundle_verified or not adapter_verified or (args.stream_socks and webtools is None):
    raise SystemExit(1)
if captures:
    assert captures["before_enable"] is not None
    assert captures["before_enable"]["ipv4"] == 0 and captures["before_enable"]["ipv6"] == 0
    assert captures["uplink"]["tcp"] > 0 and captures["uplink"]["tcp"] == captures["uplink"]["ipv4"]
    assert captures["uplink"]["udp"] == 0 and captures["uplink"]["ipv6"] == 0
