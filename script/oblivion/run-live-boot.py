#!/usr/bin/env python3
"""Boot the shipped ISO through UEFI; inspect the real VGA manager without a guest test hook."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


parser = argparse.ArgumentParser()
parser.add_argument("--iso", type=Path, required=True)
parser.add_argument("--firmware", type=Path, required=True)
parser.add_argument("--variables", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--media", choices=["cdrom", "usb"], default="cdrom")
args = parser.parse_args()
iso = args.iso.resolve(strict=True)
firmware = args.firmware.resolve(strict=True)
variables = args.variables.resolve(strict=True)
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
if any("," in str(path) for path in [iso, firmware, output]):
    raise SystemExit("QEMU option separators are not supported in paths")
for binary in ["qemu-system-x86_64", "tesseract"]:
    if not shutil.which(binary):
        raise SystemExit("Required program missing: " + binary)
shutil.copyfile(variables, output / "uefi-vars.fd")
# Unrelated synthetic disk: only files created in this fresh output directory
# are writable by QEMU. No host disks or directory shares are attached.
disk = output / "unrelated.raw"
with disk.open("xb") as file:
    file.write(b"OBLIVION_BOOT_UNRELATED_DISK\n")
    file.truncate(32 * 1024 * 1024)
before = digest(disk)
summary = {"passed": False, "iso_sha256": digest(iso), "firmware_sha256": digest(firmware),
    "boot": "UEFI", "media": args.media, "outer_accelerator": "tcg", "session_kvm_tested": False,
    "scope": "Unmodified ISO boot and real manager keyboard input; no guest diagnostic hooks, network, physical USB or session workload."}
started = time.monotonic()

with tempfile.TemporaryDirectory(prefix="oblivion-iso-") as runtime:
    qmp_path = str(Path(runtime) / "qmp.sock")
    command = ["qemu-system-x86_64", "-machine", "q35", "-accel", "tcg", "-cpu", "max",
        "-m", "2048", "-smp", "2", "-display", "none", "-monitor", "none", "-nic", "none",
        "-serial", "file:" + str(output / "serial.log"), "-no-reboot",
        "-qmp", "unix:" + qmp_path + ",server=on,wait=off",
        "-drive", "if=pflash,format=raw,readonly=on,file=" + str(firmware),
        "-drive", "if=pflash,format=raw,file=" + str(output / "uefi-vars.fd"),
        "-drive", "file=" + str(disk) + ",format=raw,if=virtio",
        *(["-cdrom", str(iso), "-boot", "order=d"] if args.media == "cdrom" else [
            "-device", "qemu-xhci,id=usb",
            "-drive", "file=" + str(iso) + ",format=raw,if=none,id=boot-media,readonly=on",
            "-device", "usb-storage,drive=boot-media,bootindex=1,removable=true"]),
        "-device", "virtio-rng-pci"]
    (output / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    with (output / "qemu.log").open("wb") as log, subprocess.Popen(command, stdout=log, stderr=log) as process:
        try:
            deadline = time.monotonic() + 30
            while not Path(qmp_path).exists():
                assert process.poll() is None, "QEMU stopped before QMP"
                assert time.monotonic() < deadline, "QMP unavailable"
                time.sleep(0.1)
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(20)
                client.connect(qmp_path)
                with client.makefile("rwb", buffering=0) as channel:
                    assert "QMP" in json.loads(channel.readline())

                    def qmp(operation, arguments=None):
                        channel.write(json.dumps({"execute": operation, "arguments": arguments or {}}).encode() + b"\n")
                        while True:
                            reply = json.loads(channel.readline())
                            if "event" in reply:
                                continue
                            assert "return" in reply, reply
                            return reply["return"]

                    def screen(name):
                        path = output / (name + ".png")
                        qmp("screendump", {"filename": str(path), "format": "png"})
                        text = subprocess.run(["tesseract", str(path), "stdout", "--psm", "6"],
                            check=True, capture_output=True, timeout=30).stdout.decode()
                        (output / (name + ".txt")).write_text(text)
                        return text

                    def manager(text):
                        return "OBLIVION" in text and "Supporto dati USB" in text and "disabilitata" in text

                    qmp("qmp_capabilities")
                    deadline = time.monotonic() + 300
                    while not manager(screen("boot")):
                        assert process.poll() is None, "QEMU stopped before the manager"
                        assert time.monotonic() < deadline, "Manager did not appear"
                        time.sleep(3)
                    summary["manager_seconds"] = round(time.monotonic() - started, 2)
                    print("PASS: the unmodified ISO boots through UEFI to the real manager", flush=True)
                    # Enter must not offer to create a durable vault in the live
                    # overlay. The root-side /persist mount is read-only as well.
                    qmp("send-key", {"keys": [{"type": "qcode", "data": "ret"}]})
                    time.sleep(1)
                    assert manager(screen("enter")), "Unconfigured persistence accepted Enter"
                    print("PASS: Enter leaves archive creation disabled until USB provisioning exists", flush=True)
                    qmp("send-key", {"keys": [{"type": "qcode", "data": "q"}]})
                    deadline = time.monotonic() + 20
                    while manager(screen("exiting")):
                        assert time.monotonic() < deadline, "Manager did not handle lock and exit"
                        time.sleep(0.1)
                    while not manager(screen("manager")):
                        assert time.monotonic() < deadline, "Manager failed to return after lock and exit"
                        time.sleep(0.2)
                    print("PASS: the manager remains available after lock and exit", flush=True)
                    qmp("system_powerdown")
                process.wait(timeout=90)
            assert process.returncode == 0, "QEMU exit failure"
            assert digest(disk) == before, "Unrelated synthetic disk changed"
            summary["unrelated_disk_unchanged"] = True
            summary["clean_acpi_poweroff"] = True
            summary["passed"] = True
            print("PASS: ACPI shutdown completes and the unrelated synthetic disk is byte-identical", flush=True)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            summary["seconds"] = round(time.monotonic() - started, 2)
            (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
