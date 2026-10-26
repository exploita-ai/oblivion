#!/usr/bin/env python3
"""Boot the ARM ISO as a writable virtual USB; never attach physical disks."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--image", type=Path, required=True)
parser.add_argument("--directory", type=Path, required=True)
parser.add_argument("--device", type=Path, action="append", default=[], help="Additional synthetic USB image")
parser.add_argument("--clipboard-host", help="Explicit clipboard SSH target for this lab VM, for example oblivion-test@192.168.64.25")
parser.add_argument("--clipboard-identity", type=Path)
parser.add_argument("--clipboard-known-hosts", type=Path)
args = parser.parse_args()
environment = os.environ.copy()
if args.clipboard_host:
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+@[a-zA-Z0-9.:-]+", args.clipboard_host) or not args.clipboard_identity or not args.clipboard_known_hosts:
        parser.error("Clipboard requires a user@host, identity and verified known-hosts file")
    environment.update(OBLIVION_CLIPBOARD_HOST=args.clipboard_host,
        OBLIVION_CLIPBOARD_IDENTITY=str(args.clipboard_identity.resolve(strict=True)),
        OBLIVION_CLIPBOARD_KNOWN_HOSTS=str(args.clipboard_known_hosts.resolve(strict=True)))
root = Path(__file__).resolve().parents[3]
image = args.image.resolve(strict=True)
directory = args.directory.resolve()
digest = hashlib.sha256(image.read_bytes()).hexdigest()
if directory.exists():
    metadata = json.loads((directory / "image.json").read_text())
    if metadata["iso_sha256"] != digest:
        parser.error("This VM directory belongs to another ISO. Use a new directory; existing persistence is preserved.")
else:
    directory.mkdir(parents=True)
    with image.open("rb") as source, (directory / "usb.raw").open("xb") as target:
        while data := source.read(4 * 1024 * 1024):
            target.write(data)
        target.truncate(8 * 1024 ** 3)
    (directory / "image.json").write_text(json.dumps({"iso_sha256": digest, "usb_bytes": 8 * 1024 ** 3}, indent=2) + "\n")
command = [str(root / "artifacts/oblivion-mac-lab/OblivionLab.app/Contents/MacOS/OblivionLab"),
    "--usb", str(directory / "usb.raw"), str(directory / "efi.store")]
for device in args.device:
    device = device.resolve(strict=True)
    if not device.is_file():
        parser.error("Only regular synthetic device images are supported")
    command.append(str(device))
# No console capture in interactive runs. Probe capture is a separate,
# synthetic-only workflow in probe.py.
subprocess.run(command, stdin=subprocess.DEVNULL, env=environment, check=True)
