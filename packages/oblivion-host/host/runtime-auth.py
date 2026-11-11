#!/usr/bin/python3
"""Per-boot control token provisioning over one private virtio serial port."""

import os
import json
from pathlib import Path
import re
import resource
import select
import stat
import struct
import sys
import time

DEVICE = Path("/dev/virtio-ports/oblivion.runtime-auth")
TOKEN = Path("/run/oblivion-runtime-auth/control-token")
INITIALIZATION = TOKEN.parent / "new-disk"
READY = b"OBLVPRV2"
SET = b"OBLVSET2"
DATA_LIMIT = 512


def profile(arguments):
    if "oblivion.runtime=1" not in arguments:
        raise ValueError("native_runtime_required")
    selected = [value.split("=", 1)[1] for value in arguments if value.startswith("oblivion.runtime-backend=")]
    if len(selected) != 1 or selected[0] not in ("apple-vz", "qemu-kvm", "hcs-hyperv"):
        raise ValueError("runtime_backend_profile_required")
    return selected[0]


def receive(fd, length, deadline):
    output = bytearray()
    while len(output) < length:
        if not select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
            raise ValueError("runtime_control_authentication_timeout")
        chunk = os.read(fd, length - len(output))
        if not chunk:
            raise ValueError("runtime_control_authentication_disconnected")
        output.extend(chunk)
    return output


def unique_fields(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("invalid_runtime_data_authority")
    return result


def data_authority(encoded, backend, runtime_id):
    data = json.loads(encoded, object_pairs_hook=unique_fields)
    if data == {"kind": "existing"}:
        return None
    if (type(data) is not dict or set(data) != {"kind", "runtime_id", "bytes"}
            or data["kind"] != "new-disk" or backend != "hcs-hyperv"
            or type(data["runtime_id"]) is not str
            or not re.fullmatch(r"[0-9a-f]{32}", data["runtime_id"])
            or data["runtime_id"] == "0" * 32 or data["runtime_id"] != runtime_id
            or type(data["bytes"]) is not int or not 4 * 1024**3 <= data["bytes"] <= 1024**4
            or data["bytes"] % (1024 * 1024)):
        raise ValueError("invalid_runtime_data_authority")
    return data


def provision(fd, destination, uid, gid, authority, backend, runtime_id):
    # The host must wait for READY. Virtio discards bytes written before the
    # guest opens a port, so sending the token on host startup is insufficient.
    os.write(fd, READY)
    token = bytearray(32)
    view = memoryview(token)
    deadline = time.monotonic() + 30
    output = None
    created = False
    authority_output = None
    authority_created = False
    try:
        while view:
            if not select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
                raise ValueError("runtime_control_authentication_timeout")
            data = os.read(fd, len(view))
            if not data:
                raise ValueError("runtime_control_authentication_disconnected")
            view[:len(data)] = data
            view = view[len(data):]
        length = struct.unpack(">I", receive(fd, 4, deadline))[0]
        if not 1 <= length <= DATA_LIMIT:
            raise ValueError("invalid_runtime_data_authority")
        data = data_authority(receive(fd, length, deadline), backend, runtime_id)
        if authority.exists() or authority.is_symlink():
            raise ValueError("runtime_data_authority_already_present")
        if data is not None:
            authority_output = os.open(authority, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            authority_created = True
            encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("ascii")
            written = 0
            while written < len(encoded):
                written += os.write(authority_output, encoded[written:])
            os.fsync(authority_output)
            os.close(authority_output)
            authority_output = None
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
        if authority_output is not None:
            os.close(authority_output)
        if output is not None:
            os.close(output)
        if created:
            try:
                os.unlink(destination)
            except FileNotFoundError:
                pass
        if authority_created:
            os.unlink(authority)
        raise
    finally:
        token[:] = bytes(32)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    arguments = Path("/proc/cmdline").read_text().split()
    backend = profile(arguments)
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
        identities = [value.split("=", 1)[1] for value in arguments if value.startswith("oblivion.runtime-id=")]
        if len(identities) != 1:
            raise ValueError("runtime_identity_required")
        provision(fd, TOKEN, 1000, 1000, INITIALIZATION, backend, identities[0])
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        # Never include a token, guest output, path or exception detail.
        print("runtime_control_authentication_failed", file=sys.stderr)
        sys.exit(1)
