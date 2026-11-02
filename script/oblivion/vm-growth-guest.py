#!/usr/bin/python3
"""Test-only diagnostics around the production resize implementation."""
import importlib.util
import subprocess
import time
import traceback
from pathlib import Path

spec = importlib.util.spec_from_file_location("resize", "/usr/lib/oblivion/guest/resize.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
port = Path("/dev/virtio-ports/oblivion.resize")
deadline = time.monotonic() + 60
while not port.exists():
    assert time.monotonic() < deadline
    time.sleep(0.1)
with port.open("wb", buffering=0) as channel:
    try:
        result = module.resize("/dev/vdb")
        assert not Path("/vault").is_mount()
        assert sorted(item.name for item in Path("/sys/class/net").iterdir()) == ["lo"]
    except BaseException:
        with open("/dev/hvc0", "w") as console:
            traceback.print_exc(file=console)
            subprocess.run(["resize2fs", "/dev/vdb"], stdout=console, stderr=console, timeout=30)
        result = bytes(16)
    channel.write(result)
