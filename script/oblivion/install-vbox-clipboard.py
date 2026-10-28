#!/usr/bin/python3 -B
"""Build-only: extract the pinned, unmodified clipboard client, never its installer."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


def install(architecture, destination):
    destination.mkdir(parents=True, exist_ok=False)
    if architecture == "arm64":
        return
    if architecture != "amd64":
        raise ValueError("Unsupported clipboard architecture")
    lock = json.loads(Path(__file__).with_name("vbox-clipboard.json").read_text())
    with tempfile.TemporaryDirectory(prefix="oblivion-vbox-build-") as directory:
        root = Path(directory)
        iso = root / "guest.iso"
        with urllib.request.urlopen(lock["url"], timeout=60) as response, iso.open("xb") as target:
            shutil.copyfileobj(response, target)
        with iso.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != lock["sha256"]:
                raise ValueError("VirtualBox source checksum mismatch")
        archive = root / "additions.run"
        subprocess.run(["xorriso", "-osirrox", "on", "-indev", str(iso), "-extract", "/VBoxLinuxAdditions.run", str(archive)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Only the verified self-extractor runs in the build container. No
        # install.sh, kernel module build, service or guest-control daemon runs.
        subprocess.run(["/bin/sh", str(archive), "--noexec", "--target", str(root / "unpacked")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with tarfile.open(root / "unpacked/VBoxGuestAdditions-amd64.tar.bz2") as members:
            binary = members.extractfile("bin/VBoxClient").read()
            if hashlib.sha256(binary).hexdigest() != lock["binary_sha256"]:
                raise ValueError("VirtualBox clipboard binary checksum mismatch")
            (destination / "VBoxClient").write_bytes(binary)
            (destination / "VBoxClient").chmod(0o755)
            (destination / "LICENSE").write_bytes(members.extractfile("LICENSE").read())
    (destination / "provenance.json").write_text(json.dumps(lock, indent=2) + "\n")


if __name__ == "__main__":
    install(sys.argv[1], Path(sys.argv[2]))
