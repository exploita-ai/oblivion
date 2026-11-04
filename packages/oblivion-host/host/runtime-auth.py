#!/usr/bin/python3
"""Per-boot control token provisioning over one private virtio serial port."""

import os
from pathlib import Path
import re
import resource
import select
import stat
import sys
import time

DEVICE = Path("/dev/virtio-ports/oblivion.runtime-auth")
TOKEN = Path("/run/oblivion-runtime-auth/control-token")
READY = b"OBLVPRV1"
SET = b"OBLVSET1"


def profile(arguments):
    if "oblivion.runtime=1" not in arguments:
        raise ValueError("native_runtime_required")
    selected = [value.split("=", 1)[1] for value in arguments if value.startswith("oblivion.runtime-backend=")]
    if len(selected) != 1 or selected[0] not in ("apple-vz", "qemu-kvm"):
        raise ValueError("runtime_backend_profile_required")
    return selected[0]


def provision(fd, destination, uid, gid):
    # The host must wait for READY. Virtio discards bytes written before the
    # guest opens a port, so sending the token on host startup is insufficient.
    os.write(fd, READY)
    token = bytearray(32)
    view = memoryview(token)
    deadline = time.monotonic() + 30
    output = None
    created = False
    try:
        while view:
            if not select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
                raise ValueError("runtime_control_authentication_timeout")
            data = os.read(fd, len(view))
            if not data:
                raise ValueError("runtime_control_authentication_disconnected")
            view[:len(data)] = data
            view = view[len(data):]
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        created = True
        os.fchmod(output, 0o600)
        os.fchown(output, uid, gid)
        written = 0
        while written < len(token):
            written += os.write(output, memoryview(token)[written:])
        os.fsync(output)
        os.close(output)
        output = None
        os.write(fd, SET)
    except BaseException:
        if output is not None:
            os.close(output)
        if created:
            try:
                os.unlink(destination)
            except FileNotFoundError:
                pass
        raise
    finally:
        token[:] = bytes(32)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    backend = profile(Path("/proc/cmdline").read_text().split())
    if backend == "apple-vz":
        return
    if os.geteuid() != 0:
        raise ValueError("root_required")
    deadline = time.monotonic() + 30
    while not DEVICE.exists():
        if time.monotonic() >= deadline:
            raise ValueError("runtime_auth_port_unavailable")
        time.sleep(0.05)
    resolved = DEVICE.resolve(strict=True)
    if not re.fullmatch(r"vport[0-9]+p[0-9]+", resolved.name):
        raise ValueError("invalid_runtime_auth_port")
    name = Path("/sys/class/virtio-ports", resolved.name, "name").read_text().strip()
    if name != "oblivion.runtime-auth":
        raise ValueError("invalid_runtime_auth_port")
    fd = os.open(resolved, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISCHR(info.st_mode) or info.st_uid != 0:
            raise ValueError("invalid_runtime_auth_port")
        os.fchmod(fd, 0o600)
        parent = TOKEN.parent.stat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != 1000 or parent.st_mode & 0o007:
            raise ValueError("private_runtime_auth_directory_required")
        provision(fd, TOKEN, 1000, 1000)
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        # Never include a token, guest output, path or exception detail.
        print("runtime_control_authentication_failed", file=sys.stderr)
        sys.exit(1)
