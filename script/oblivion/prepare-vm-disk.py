#!/usr/bin/env python3
"""Copy an Oblivion hybrid ISO into a larger writable virtual disk image."""

import argparse
import os
import shutil
import struct
import zlib
from pathlib import Path


SECTOR_BYTES = 512
GPT_HEADER = struct.Struct("<8sIIIIQQQQ16sQIII")
GPT_SIGNATURE = b"EFI PART"


def relocate_gpt(disk, capacity: int) -> None:
    """Move the backup GPT to the end of the expanded virtual disk."""
    disk.seek(SECTOR_BYTES)
    primary_sector = bytearray(disk.read(SECTOR_BYTES))
    if len(primary_sector) != SECTOR_BYTES:
        raise ValueError("the image has no complete primary GPT header")
    primary = list(GPT_HEADER.unpack_from(primary_sector))
    if primary[0] != GPT_SIGNATURE or primary[5] != 1:
        raise ValueError("the image has no supported primary GPT")
    header_bytes = primary[2]
    if not GPT_HEADER.size <= header_bytes <= SECTOR_BYTES:
        raise ValueError("the image has an invalid GPT header size")
    header_crc = primary[3]
    struct.pack_into("<I", primary_sector, 16, 0)
    if zlib.crc32(primary_sector[:header_bytes]) & 0xFFFFFFFF != header_crc:
        raise ValueError("the image has an invalid GPT header checksum")

    entries_lba = primary[10]
    entries_count = primary[11]
    entry_bytes = primary[12]
    array_bytes = entries_count * entry_bytes
    if entries_count == 0 or entry_bytes < 128 or array_bytes > 16 * 1024 * 1024:
        raise ValueError("the image has an invalid GPT partition array")
    disk.seek(entries_lba * SECTOR_BYTES)
    entries = disk.read(array_bytes)
    if len(entries) != array_bytes or zlib.crc32(entries) & 0xFFFFFFFF != primary[13]:
        raise ValueError("the image has an invalid GPT partition checksum")

    final_lba = capacity // SECTOR_BYTES - 1
    array_sectors = (array_bytes + SECTOR_BYTES - 1) // SECTOR_BYTES
    backup_entries_lba = final_lba - array_sectors
    last_usable_lba = backup_entries_lba - 1
    if final_lba <= primary[8] or last_usable_lba < primary[7]:
        raise ValueError("the expanded disk is too small for this GPT")

    def header(values: list) -> bytes:
        sector = bytearray(SECTOR_BYTES)
        values[3] = 0
        GPT_HEADER.pack_into(sector, 0, *values)
        values[3] = zlib.crc32(sector[:header_bytes]) & 0xFFFFFFFF
        GPT_HEADER.pack_into(sector, 0, *values)
        return sector

    primary[6] = final_lba
    primary[8] = last_usable_lba
    backup = primary.copy()
    backup[5] = final_lba
    backup[6] = 1
    backup[10] = backup_entries_lba

    disk.seek(backup_entries_lba * SECTOR_BYTES)
    disk.write(entries)
    disk.write(b"\0" * (array_sectors * SECTOR_BYTES - array_bytes))
    disk.seek(final_lba * SECTOR_BYTES)
    disk.write(header(backup))
    disk.seek(SECTOR_BYTES)
    disk.write(header(primary))

    disk.seek(446)
    mbr = bytearray(disk.read(64))
    for offset in range(0, len(mbr), 16):
        if mbr[offset + 4] == 0xEE and struct.unpack_from("<I", mbr, offset + 8)[0] == 1:
            struct.pack_into("<I", mbr, offset + 12, min(final_lba, 0xFFFFFFFF))
    disk.seek(446)
    disk.write(mbr)
    disk.flush()
    os.fsync(disk.fileno())


parser = argparse.ArgumentParser(
    description="Prepare a writable raw disk from an Oblivion ISO without touching a physical device."
)
parser.add_argument("--image", required=True, type=Path, help="Oblivion amd64 or arm64 ISO")
parser.add_argument("--output", required=True, type=Path, help="New raw disk image to create")
parser.add_argument("--size-gib", type=int, default=8, help="Virtual disk capacity (default: 8 GiB)")
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
    with source.open("rb") as incoming, output.open("x+b") as disk:
        shutil.copyfileobj(incoming, disk, 4 * 1024 * 1024)
        disk.truncate(capacity)
        relocate_gpt(disk, capacity)
    os.chmod(output, 0o600)
except BaseException:
    output.unlink(missing_ok=True)
    raise

print(f"Writable virtual disk: {output}")
print(f"Capacity: {args.size_gib} GiB")
