#!/usr/bin/env python3
"""Copy an Oblivion hybrid ISO into a larger writable virtual USB image."""

import argparse
import os
import shutil
from pathlib import Path


parser = argparse.ArgumentParser(
    description="Prepare a writable raw disk from an Oblivion ISO without touching a physical device."
)
parser.add_argument("--image", required=True, type=Path, help="Oblivion amd64 or arm64 ISO")
parser.add_argument("--output", required=True, type=Path, help="New raw disk image to create")
parser.add_argument("--size-gib", type=int, default=16, help="Virtual disk capacity (default: 16 GiB)")
args = parser.parse_args()

source = args.image.resolve(strict=True)
output = args.output.resolve(strict=False)
if not source.is_file():
    parser.error("--image must be a regular file")
if args.size_gib < 4:
    parser.error("--size-gib must be at least 4")
if output.exists() or output.is_symlink():
    parser.error("--output already exists; refusing to overwrite it")
if not output.parent.is_dir():
    parser.error("the output directory does not exist")

with source.open("rb") as image:
    image.seek(32768)
    if image.read(7) != b"\x01CD001\x01":
        parser.error("--image is not an ISO 9660 image")

capacity = args.size_gib * 1024**3
if source.stat().st_size >= capacity:
    parser.error("the requested disk must be larger than the ISO")

try:
    with source.open("rb") as incoming, output.open("xb") as disk:
        shutil.copyfileobj(incoming, disk, 4 * 1024 * 1024)
        disk.truncate(capacity)
    os.chmod(output, 0o600)
except BaseException:
    output.unlink(missing_ok=True)
    raise

print(f"Writable virtual USB: {output}")
print(f"Capacity: {args.size_gib} GiB")
