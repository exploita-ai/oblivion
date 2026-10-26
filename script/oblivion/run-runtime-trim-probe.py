#!/usr/bin/env python3
"""Boot synthetic before/after fixtures, without shared folders or Internet."""
import argparse
import hashlib
import json
import platform
import re
import resource
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--architecture", choices=["arm64", "amd64"], required=True)
    args = parser.parse_args()
    root = args.directory.resolve()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    accelerator = "hvf" if platform.system() == "Darwin" and args.architecture == "arm64" else "tcg"
    results = []
    with tempfile.TemporaryDirectory(prefix="oblivion-probe-") as directory:
        for role in ("session", "gateway", "import", "export"):
            for variant in ("before", "after"):
                with tempfile.TemporaryDirectory(dir=directory) as runtime:
                    runtime = Path(runtime)
                    image = root / role / f"{variant}.squashfs"
                    data = runtime / "data.ext4"
                    shutil.copyfile(root / "synthetic.ext4", data)
                    qmp = runtime / "qmp"
                    command = ["qemu-system-aarch64" if args.architecture == "arm64" else "qemu-system-x86_64",
                               "-machine", "virt" if args.architecture == "arm64" else "q35", "-accel", accelerator,
                               "-cpu", "host" if accelerator == "hvf" else "max", "-m", "768", "-smp", "2",
                               "-nodefaults", "-no-reboot", "-display", "none", "-monitor", "none", "-nic", "none",
                               "-serial", "stdio", "-qmp", f"unix:{qmp},server=on,wait=off",
                               "-object", "rng-random,filename=/dev/urandom,id=rng", "-device", "virtio-rng-pci,rng=rng",
                               "-kernel", str(root / role / "kernel"), "-initrd", str(root / role / "initrd"),
                               "-append", "root=/dev/vda ro rootfstype=squashfs console=" + ("ttyAMA0" if args.architecture == "arm64" else "ttyS0") + " panic=-1 loglevel=4 oblivion.documents=1",
                               "-drive", f"file={image},format=raw,if=none,id=root,readonly=on", "-device", "virtio-blk-pci,drive=root",
                               "-drive", f"file={data},format=raw,if=none,id=data", "-device", "virtio-blk-pci,drive=data",
                               "-device", "virtio-serial-pci",
                               "-chardev", f"file,id=ready,path={runtime / 'ready'}", "-device", "virtserialport,chardev=ready,name=oblivion.documents"]
                    if role == "gateway":
                        # Two disconnected virtual hubs; no user/NAT/tap backend.
                        command += ["-netdev", "hubport,id=inside,hubid=1", "-device", "virtio-net-pci,netdev=inside,mac=52:54:00:6f:00:01,romfile=",
                                    "-netdev", "hubport,id=outside,hubid=2", "-device", "virtio-net-pci,netdev=outside,mac=52:54:00:6f:00:02,romfile="]
                    log = root / f"{role}-{variant}.log"
                    with log.open("wb") as stream:
                        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT)
                        try:
                            deadline = time.monotonic() + 150
                            while b"OBLIVION_TRIM_PASS" not in log.read_bytes():
                                if child.poll() is not None or time.monotonic() >= deadline or b"OBLIVION_TRIM_FAIL" in log.read_bytes():
                                    raise RuntimeError(f"{role}/{variant} failed; inspect {log}")
                                time.sleep(0.1)
                            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                                peer.settimeout(5)
                                peer.connect(str(qmp))
                                with peer.makefile("rwb", buffering=0) as channel:
                                    json.loads(channel.readline())
                                    for operation in ("qmp_capabilities", "system_powerdown"):
                                        channel.write(json.dumps({"execute": operation}).encode() + b"\n")
                                        while True:
                                            reply = json.loads(channel.readline())
                                            if "error" in reply:
                                                raise RuntimeError(reply)
                                            if "return" in reply:
                                                break
                            if child.wait(timeout=30) != 0:
                                raise RuntimeError(f"{role}/{variant} shutdown failed")
                            with image.open("rb") as source:
                                digest = hashlib.file_digest(source, "sha256").hexdigest()
                            lines = log.read_text(errors="replace").splitlines()
                            failures = [line for line in lines if "[FAILED]" in re.sub(r"\x1b\[[0-9;]*m", "", line)
                                        or "Failed to find module" in line]
                            if failures:
                                raise RuntimeError(f"{role}/{variant} has boot failures: {failures}")
                            results.append({"role": role, "variant": variant, "passed": True, "acpi_shutdown": True,
                                            "boot_failure_scan_passed": True,
                                            "image_sha256": digest,
                                            "running_services": sorted(line.split()[1] for line in lines if line.startswith("OBLIVION_SERVICE ")),
                                            "active_sockets_timers": sorted(line.split()[1] for line in lines if line.startswith("OBLIVION_ACTIVATION ")),
                                            "loaded_modules": sorted(line.split()[1] for line in lines if line.startswith("OBLIVION_MODULE "))})
                            print(f"PASS {role}/{variant}: boot, probe, ACPI shutdown", flush=True)
                        finally:
                            if child.poll() is None:
                                child.terminate()
                                try:
                                    child.wait(timeout=5)
                                except subprocess.TimeoutExpired:
                                    child.kill()
                                    child.wait()
                            (root / "boot-results.json").write_text(json.dumps({"accelerator": accelerator, "results": results,
                                "limits": ["Synthetic isolated fixtures; no real API, complete transfer protocol or physical hardware validation.",
                                           "No network backend reaches the host or Internet. No shared host filesystem. Logs contain synthetic boot/test data only."]}, indent=2) + "\n")


if __name__ == "__main__":
    main()
