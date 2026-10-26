#!/usr/bin/env python3
"""Probe Apple nested virtualization with a disposable Debian ARM initramfs."""
import argparse
import gzip
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--image", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
with tempfile.TemporaryDirectory(prefix="oblivion-vz-probe-") as temporary:
    probe = Path(temporary) / "oblivion-probe"
    probe.write_bytes(Path(__file__).with_name("probe.sh").read_bytes())
    probe.chmod(0o755)
    archive = subprocess.run(["/usr/bin/cpio", "-o", "-H", "newc"], input=b"oblivion-probe\n", cwd=temporary, capture_output=True, check=True).stdout
    (output / "initrd").write_bytes((args.image / "initrd").read_bytes() + gzip.compress(archive, mtime=0))
command = [str(root / "artifacts/oblivion-mac-lab/OblivionLab.app/Contents/MacOS/OblivionLab"),
    str((args.image / "kernel").resolve()), str(output / "initrd"), str((args.image / "host.squashfs").resolve()),
    "console=hvc0 rdinit=/oblivion-probe panic=0"]
with (output / "probe.log").open("xb") as log:
    subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=120, check=True)
lines = (output / "probe.log").read_text(errors="replace").splitlines()
results = [json.loads(line.removeprefix("OBLIVION_VZ_KVM ")) for line in lines if line.startswith("OBLIVION_VZ_KVM ")]
assert len(results) == 1, "Linux KVM probe did not pass; inspect probe.log"
result = {"scope": "Apple Virtualization ARM64 -> Linux KVM VM/vCPU creation; no session, network or provider test", **results[0],
    "kernel_sha256": hashlib.sha256((args.image / "kernel").read_bytes()).hexdigest(),
    "initrd_sha256": hashlib.sha256((output / "initrd").read_bytes()).hexdigest()}
(output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
