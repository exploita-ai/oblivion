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
    operation = value.get("operation")
    if operation == "transfers":
        if set(value) != {"operation", "safe_id", "opening", "after", "limit"} or any(not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{32}", value[key]) for key in ("safe_id", "opening")):
            raise ValueError("invalid_file_request")
        if value["after"] is not None and (not isinstance(value["after"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["after"])) or type(value["limit"]) is not int or not 1 <= value["limit"] <= 8:
            raise ValueError("invalid_file_request")
        return (["/usr/bin/oblivion-copy", "native-files", "/vault/home/.oblivion-file-staging", "/vault/workspace", "3600000"], json.dumps(value).encode())
    if operation in ("import", "status", "recover", "discard"):
        expected = {"operation", "id", "safe_id", "opening"} | ({"name"} if operation == "import" else set())
        if set(value) != expected or any(not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{32}", value[key]) for key in ("id", "safe_id", "opening")):
            raise ValueError("invalid_file_request")
        if operation == "import":
            name = value["name"]
            if not isinstance(name, str) or not name or len(name.encode()) > 255 or any(char in name for char in "/\\\0") or name in (".", ".."):
                raise ValueError("invalid_import_name")
        return (["/usr/bin/oblivion-copy", "native-files", "/vault/home/.oblivion-file-staging", "/vault/workspace", "3600000"], json.dumps(value).encode())
    if operation == "export" and set(value) == {"operation"}:
        return (["/usr/bin/oblivion-copy", "documents", "/vault", "3600000"], None)
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
            args, metadata = command(fd)
            # Only a new import prepares its receiver. Inventory and status
            # remain read-only when no staging directory exists yet.
            if metadata is not None and json.loads(metadata)["operation"] == "import":
                os.makedirs("/vault/home/.oblivion-file-staging", mode=0o700, exist_ok=True)
            if fd != 3:
                os.dup2(fd, 3)
            os.set_inheritable(3, True)
            result = subprocess.run(args, input=metadata, pass_fds=(3,),
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
