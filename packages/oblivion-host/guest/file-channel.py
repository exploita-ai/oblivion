"""Stream an explicitly selected desktop copy through a dedicated virtio port.

Only workspace and imports are export roots. Import publication always targets
workspace, with private staging on the same encrypted filesystem. The Rust copy
endpoint validates every relative path, manifest, hash and publication receipt.
"""
import json
import os
import re
import select
import struct
import subprocess
import sys
import time


def command(fd):
    deadline = time.monotonic() + 30

    def read(size):
        result = bytearray()
        while len(result) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise ValueError("file_request_timeout")
            chunk = os.read(fd, size - len(result))
            if not chunk:
                raise EOFError()
            result.extend(chunk)
        return result

    size, = struct.unpack(">I", read(4))
    if not 0 < size <= 4096:
        raise ValueError("invalid_file_request")
    value = json.loads(read(size))
    if not isinstance(value, dict):
        raise ValueError("invalid_file_request")
    if value.get("operation") == "import" and set(value) == {"operation", "name"}:
        name = value["name"]
        if not isinstance(name, str) or not name or len(name.encode()) > 255 or any(char in name for char in "/\\\0") or name in (".", ".."):
            raise ValueError("invalid_import_name")
        return ["/usr/bin/oblivion-copy", "stream-receive", "/vault/home/.oblivion-file-staging", "/vault/workspace", name, "3600000"]
    if value.get("operation") == "export" and set(value) == {"operation", "root"} and value["root"] in ("workspace", "imports"):
        return ["/usr/bin/oblivion-copy", "send", "/vault/" + value["root"], "3600000"]
    raise ValueError("invalid_file_request")


def main():
    if os.geteuid() != 1000 or len(sys.argv) != 2:
        raise ValueError("invalid_file_service")
    path = sys.argv[1]
    if not re.fullmatch(r"/dev/vport[0-9]+p[0-9]+", path):
        raise ValueError("invalid_file_port")
    name = os.path.basename(os.path.realpath(path))
    with open(f"/sys/class/virtio-ports/{name}/name", encoding="ascii") as source:
        if not re.fullmatch(r"oblivion\.file\.[0-9a-f]{32}", source.read().strip()):
            raise ValueError("invalid_file_port")
    with open(path, "r+b", buffering=0) as stream:
        fd = stream.fileno()
        try:
            # Opening the guest port precedes this acknowledgement. QEMU must
            # not discard the initial request while systemd starts the worker.
            stream.write(b"ready\n")
            args = command(fd)
            if fd != 3:
                os.dup2(fd, 3)
            os.set_inheritable(3, True)
            result = subprocess.run(args, pass_fds=(3,), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    check=False)
            if result.returncode == 0:
                return
        except (ValueError, EOFError, OSError):
            pass
        # Both import acceptance and export manifest framing reject these fixed
        # bytes promptly, even though QEMU keeps the host socket connected.
        try:
            stream.write(b"failed!\n")
        except OSError:
            pass


if __name__ == "__main__":
    main()
