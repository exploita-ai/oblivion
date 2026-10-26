#!/usr/bin/env python3
"""Run the storage implementation in a disposable, networkless Linux VM.

Only files in a newly created output directory are writable VM disks. No host
directory, physical device, credential, clipboard or network is passed through.
This ARM/HVF lab verifies storage behavior, not x86/KVM session isolation.
"""
import argparse
import hashlib
import json
import platform
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--image", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
if platform.system() != "Darwin" or platform.machine() != "arm64":
    raise SystemExit("This lab runner requires macOS arm64 with HVF.")
image = args.image.resolve()
output = args.output.resolve()
if "," in str(output):
    raise SystemExit("Output paths containing a QEMU option separator are unsupported.")
output.mkdir(parents=True, exist_ok=False)
disk = output / "data.raw"
with disk.open("xb") as stream:
    stream.truncate(1024 * 1024 * 1024)
started = time.monotonic()
with (output / "serial.log").open("xb") as log:
    result = subprocess.run([
        "qemu-system-aarch64", "-machine", "virt", "-accel", "hvf", "-cpu", "host",
        "-m", "1536", "-smp", "2", "-nodefaults", "-no-reboot", "-display", "none",
        "-monitor", "none", "-serial", "stdio", "-nic", "none",
        "-kernel", str(image / "kernel"), "-initrd", str(image / "initramfs.gz"),
        "-append", "console=ttyAMA0 panic=-1 rdinit=/init",
        "-drive", f"file={disk},format=raw,if=none,id=data,cache=none",
        "-device", "virtio-blk-pci,drive=data",
    ], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=600)
serial = (output / "serial.log").read_text(errors="replace")
markers = [b"OBLIVION_PROFILE_CANARY_b3de", b"OBLIVION_SESSION_A_CANARY_a67c",
           b"OBLIVION_SESSION_B_CANARY_b98d", b"OBLIVION_CHAT_CANARY_c92e",
           b"synthetic-general-password", b"synthetic-session-password-a",
           b"synthetic-session-password-b"]
found = set()
digest = hashlib.sha256()
with disk.open("rb") as stream:
    overlap = b""
    while chunk := stream.read(4 * 1024 * 1024):
        digest.update(chunk)
        for marker in markers:
            if marker in overlap + chunk:
                found.add(marker.decode())
        overlap = chunk[-128:]
summary = {
    "scope": "real LUKS2 storage in disposable Debian arm64 VM; no product VM isolation claim",
    "accelerator": "hvf", "seconds": round(time.monotonic() - started, 2),
    "qemu_exit": result.returncode,
    "checks": [line.strip() for line in serial.splitlines() if line.startswith("PASS:")],
    "guest_pass": "OBLIVION_STORAGE_LAB_PASS" in serial,
    "plaintext_markers_on_disk": sorted(found), "disk_sha256": digest.hexdigest(),
    "image_manifest": (image / "SHA256SUMS").read_text(),
    "compiled_sources": (image / "sources.sha256").read_text(),
}
(output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
if result.returncode or not summary["guest_pass"] or found:
    raise SystemExit(1)
