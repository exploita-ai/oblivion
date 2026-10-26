#!/usr/bin/env python3
"""Boot the exact CI chat image once, without nested CPU emulation or host services."""
import argparse
import hashlib
import json
import os
import platform
import re
import resource
import selectors
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--image", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--architecture", choices=["aarch64", "x86_64"], default="aarch64")
parser.add_argument("--accelerator", choices=["tcg", "kvm"], default="tcg")
args = parser.parse_args()
if platform.system() != "Linux":
    parser.error("This CI diagnostic requires Linux")
if args.accelerator == "kvm" and (platform.machine() != args.architecture or not os.access("/dev/kvm", os.R_OK | os.W_OK)):
    parser.error(f"KVM unavailable: host={platform.machine()}, target={args.architecture}, "
        f"readable={os.access('/dev/kvm', os.R_OK)}, writable={os.access('/dev/kvm', os.W_OK)}; no fallback")
image = args.image.resolve()
output = args.output.resolve()
if any("," in str(path) for path in [image, output]):
    parser.error("Paths must not contain QEMU option separators")
for line in (image / "SHA256SUMS").read_text().splitlines():
    expected, name = line.split()
    assert Path(name).name == name
    with (image / name).open("rb") as file:
        assert hashlib.file_digest(file, "sha256").hexdigest() == expected, name
output.mkdir(parents=True, exist_ok=False)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
subprocess.run(["unsquashfs", "-no-progress", "-d", str(output / "extracted"),
    str(image / "host.squashfs"), "usr/lib/oblivion/vm/guest.squashfs",
    "usr/lib/oblivion/vm/kernel", "usr/lib/oblivion/vm/initrd"], check=True)
guest = output / "extracted/usr/lib/oblivion/vm"
# A fresh, synthetic filesystem file: this diagnostic never opens a host device.
vault = output / "vault.raw"
with vault.open("xb") as file:
    file.truncate(128 * 1024 * 1024)
subprocess.run(["mkfs.ext4", "-q", "-m", "0", str(vault)], check=True)
started = time.monotonic()
markers = [b"Conversazioni e documenti", b"/exit blocca"]
received = bytearray()
with (output / "serial.log").open("xb") as log:
    with subprocess.Popen([
        "qemu-system-" + args.architecture, "-machine", ("virt" if args.architecture == "aarch64" else "q35") + ",dump-guest-core=off,mem-merge=off",
        "-accel", args.accelerator, "-cpu", "host" if args.accelerator == "kvm" else "cortex-a72" if args.architecture == "aarch64" else "max",
        "-m", "1536", "-smp", "2",
        "-nodefaults", "-no-reboot", "-display", "none", "-monitor", "none",
        "-nic", "none", "-serial", "stdio",
        "-object", "rng-random,filename=/dev/urandom,id=rng", "-device", "virtio-rng-pci,rng=rng",
        "-kernel", str(guest / "kernel"), "-initrd", str(guest / "initrd"),
        "-append", "root=/dev/vda ro rootfstype=squashfs console=" + ("ttyAMA0" if args.architecture == "aarch64" else "ttyS0") + " loglevel=4 systemd.show_status=true panic=-1",
        "-drive", f"file={guest / 'guest.squashfs'},format=raw,if=none,id=root,readonly=on",
        "-device", "virtio-blk-pci,drive=root,serial=oblivion-root",
        "-drive", f"file={vault},format=raw,if=none,id=vault,cache=none",
        "-device", "virtio-blk-pci,drive=vault,serial=oblivion-vault",
    ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0) as process:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while time.monotonic() - started < 180:
                    if not selector.select(timeout=1):
                        continue
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    log.write(chunk)
                    log.flush()
                    received.extend(chunk)
                    assert len(received) <= 4 * 1024 * 1024, "boot output limit"
                    plain = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", received)
                    if all(marker in plain for marker in markers):
                        break
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
plain = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", received)
summary = {
    "scope": "compiled chat TUI boot only; synthetic plaintext vault, no LUKS or host lifecycle assertion",
    "accelerator": args.accelerator, "architecture": args.architecture, "nested": False, "network_interfaces": 0,
    "seconds": round(time.monotonic() - started, 2),
    "markers": {marker.decode(): marker in plain for marker in markers},
    "passed": all(marker in plain for marker in markers),
    "termination": "QEMU terminated by diagnostic after observation; not a shutdown test",
    "opencode_sha256": (image / "opencode.sha256").read_text().split()[0],
    "image_manifest": (image / "SHA256SUMS").read_text(),
}
(output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
if not summary["passed"]:
    raise SystemExit(1)
