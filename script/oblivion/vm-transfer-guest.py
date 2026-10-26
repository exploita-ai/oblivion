#!/usr/bin/env python3
"""One endpoint in a networkless VM. Fixed public fixture, never real devices."""
import os
import select
import subprocess
import time
import traceback
from pathlib import Path
from transfer_fixture import FILES, ID


def run():
    os.umask(0o077)
    parameters = dict(part.split("=", 1) for part in Path("/proc/cmdline").read_text().split() if "=" in part)
    role = parameters["oblivion.copy"]
    case = parameters.get("oblivion.case", "success")
    assert role in ("send", "receive") and case in ("success", "cancel", "control-cancel", "owner-death")
    assert len(Path("/proc/swaps").read_text().splitlines()) == 1
    assert sorted(p.name for p in Path("/sys/class/net").iterdir()) == ["lo"]
    mounts = Path("/proc/mounts").read_text()
    assert " / squashfs ro," in mounts and "virtiofs" not in mounts and " 9p " not in mounts
    subprocess.run(["modprobe", "virtio_console"], check=True)
    if role == "send":
        subprocess.run(["mount", "-o", "ro,nodev,nosuid,noexec", "/dev/vdb", "/source"], check=True)
        assert Path("/sys/block/vdb/ro").read_text().strip() == "1"
        root = "/source"
    else:
        # A deliberately cheap synthetic KDF for this disposable laboratory only.
        key = b"synthetic-copy-lab-password"
        subprocess.run(["cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-", "/dev/vdb"], input=key, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["cryptsetup", "open", "--key-file", "-", "/dev/vdb", "copy-vault"], input=key, check=True)
        subprocess.run(["mkfs.ext4", "-q", "-m", "0", "/dev/mapper/copy-vault"], check=True)
        subprocess.run(["mount", "-o", "nodev,nosuid,noexec", "/dev/mapper/copy-vault", "/destination"], check=True)
        root = "/destination/inbox"
        Path(root).mkdir(mode=0o700)
    port = Path("/dev/virtio-ports/oblivion.copy")
    deadline = time.monotonic() + 20
    while not port.exists():
        assert time.monotonic() < deadline, "missing private port"
        time.sleep(0.05)
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY)
    os.dup2(fd, 3, inheritable=True)
    if fd != 3:
        os.close(fd)
    print("OBLIVION_COPY_READY", flush=True)
    # VM boot is outside the endpoint's transfer budget. The laboratory starts
    # both endpoints only after both private ports and filesystems are ready.
    assert select.select([3], [], [], 120)[0], "missing laboratory start signal"
    assert os.read(3, 1) == b"G", "invalid laboratory start signal"
    result = subprocess.run(["/usr/bin/oblivion-copy", role, root, "30000"], pass_fds=(3,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=35)
    os.close(3)
    assert result.returncode == (0 if case == "success" else 1), (role, case, result.returncode)
    if role == "receive":
        if case == "success":
            final = Path(root) / ID / "files"
            actual = {str(p.relative_to(final)) for p in final.rglob("*") if p.is_file()}
            assert actual == set(FILES)
            for name, data in FILES.items():
                assert (final / name).read_bytes() == data, name
            assert (final / "documents/empty-directory").is_dir()
            assert not (Path(root) / ID / "pending").exists()
        else:
            assert list(Path(root).iterdir()) == []
        subprocess.run(["umount", "/destination"], check=True)
        subprocess.run(["cryptsetup", "close", "copy-vault"], check=True)
        assert not Path("/dev/mapper/copy-vault").exists()
    if role == "send":
        subprocess.run(["umount", "/source"], check=True)
    print("OBLIVION_COPY_PASS", flush=True)


try:
    run()
except BaseException:
    traceback.print_exc()
    print("OBLIVION_COPY_FAIL", flush=True)
finally:
    subprocess.run(["systemctl", "poweroff"], check=False)
