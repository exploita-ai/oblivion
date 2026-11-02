#!/usr/bin/python3
"""Offline growth of a candidate vault. Never mount it or start session services."""
import fcntl
import os
import struct
import subprocess
import time


def resize(device):
    if os.path.ismount("/vault") or set(os.listdir("/sys/class/net")) != {"lo"}:
        raise ValueError("maintenance_isolation_required")
    for command, accepted in [
        (["/usr/sbin/e2fsck", "-p", "-f", device], (0, 1)),
        (["/usr/sbin/resize2fs", device], (0,)),
        (["/usr/sbin/e2fsck", "-p", "-f", device], (0, 1)),
    ]:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=360, check=False)
        if result.returncode not in accepted:
            raise ValueError(f"filesystem_resize_failed:{os.path.basename(command[0])}:{result.returncode}")
    with open(device, "rb", buffering=0) as handle:
        device_bytes = struct.unpack("Q", fcntl.ioctl(handle, 0x80081272, bytes(8)))[0]
        handle.seek(1024)
        superblock = handle.read(1024)
        if struct.unpack_from("<H", superblock, 0x38)[0] != 0xEF53:
            raise ValueError("invalid_filesystem")
        blocks = struct.unpack_from("<I", superblock, 4)[0]
        if struct.unpack_from("<I", superblock, 0x60)[0] & 0x80:
            blocks += struct.unpack_from("<I", superblock, 0x150)[0] << 32
        block_size = 1024 << struct.unpack_from("<I", superblock, 0x18)[0]
        filesystem_bytes = blocks * block_size
        if not 0 <= device_bytes - filesystem_bytes < block_size:
            raise ValueError("incomplete_resize")
        os.fsync(handle.fileno())
        return struct.pack("!QQ", device_bytes, filesystem_bytes)


if __name__ == "__main__":
    port = "/dev/virtio-ports/oblivion.resize"
    for _ in range(600):
        if os.path.exists(port):
            break
        time.sleep(0.1)
    with open(port, "wb", buffering=0) as channel:
        try:
            result = resize("/dev/vdb")
        except (OSError, ValueError, struct.error, subprocess.TimeoutExpired):
            result = bytes(16)
        channel.write(result)
