#!/usr/bin/env python3
"""Stage unchanged product bytes within GitHub's per-asset size limit."""
import argparse
from contextlib import nullcontext
import hashlib
from pathlib import Path
import re
import stat


def stage(source: Path, directory: Path, part_bytes=1900 * 1024 * 1024) -> None:
    if type(part_bytes) is not int or not 0 < part_bytes < 2**31:
        raise ValueError("invalid_release_part_size")
    metadata = source.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        raise ValueError("release_input_must_be_nonempty_regular_file")
    # GitHub normalizes '~' in uploaded names, breaking checksum references.
    name = source.name.replace("~", "-")
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9_-])?", name) is None:
        raise ValueError("unsafe_release_asset_name")
    split = metadata.st_size > part_bytes
    count = (metadata.st_size + part_bytes - 1) // part_bytes

    def filename(index):
        return name + f".part{index:02d}" if split else name

    sidecars = [name + ".sha256"]
    if split:
        sidecars.extend([name + ".parts.sha256", name + ".reassemble.txt"])
    # Refuse known collisions before writing any bytes; exclusive opens also
    # protect each individual file if another creator arrives after this check.
    for index in range(1, count + 1):
        target = directory / filename(index)
        if target.exists() or target.is_symlink():
            raise FileExistsError(target)
    for sidecar in sidecars:
        target = directory / sidecar
        if target.exists() or target.is_symlink():
            raise FileExistsError(target)
    directory.mkdir(parents=True, exist_ok=True)
    full = hashlib.sha256()
    with source.open("rb") as data, (
        (directory / (name + ".parts.sha256")).open("x", encoding="ascii", newline="\n")
        if split else nullcontext()
    ) as checksums:
        for index in range(1, count + 1):
            remaining = min(part_bytes, metadata.st_size - (index - 1) * part_bytes)
            part = hashlib.sha256() if split else None
            with (directory / filename(index)).open("xb") as output:
                while remaining:
                    block = data.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ValueError("release_input_size_changed")
                    output.write(block)
                    full.update(block)
                    if part is not None:
                        part.update(block)
                    remaining -= len(block)
            if checksums is not None:
                checksums.write(part.hexdigest() + "  " + filename(index) + "\n")
        if data.read(1):
            raise ValueError("release_input_size_changed")
    with (directory / (name + ".sha256")).open("x", encoding="ascii", newline="\n") as output:
        output.write(full.hexdigest() + "  " + name + "\n")
    if not split:
        return
    with (directory / (name + ".reassemble.txt")).open("x", encoding="ascii", newline="\n") as output:
        output.write(
            "Download every part and both checksum files into one directory, then open a terminal there.\n"
            f"The output file {name} must not already exist.\n"
            "Parts are raw consecutive bytes, not separate images or compressed archives.\n"
            "Reconstruct the complete file and verify its SHA-256 before using it.\n"
        )
        for system, verifier in [("Linux", "sha256sum"), ("macOS", "shasum -a 256")]:
            output.write(f'\n{system}:\n{verifier} --check "{name}.parts.sha256"\ncat ')
            for index in range(1, count + 1):
                if index > 1:
                    output.write(" ")
                output.write('"' + filename(index) + '"')
            output.write(f' > "{name}"\n{verifier} --check "{name}.sha256"\n')
        output.write("\nWindows Command Prompt (cmd.exe):\ncopy /b ")
        for index in range(1, count + 1):
            if index > 1:
                output.write("+")
            output.write('"' + filename(index) + '"')
        output.write(
            f' "{name}"\n\nThen verify in PowerShell:\n'
            f"$expected = (Get-Content -LiteralPath '{name}.sha256').Split(' ')[0]\n"
            f"if ((Get-FileHash -LiteralPath '{name}' -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) "
            "{ throw 'SHA-256 mismatch' }\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        stage(args.input, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
