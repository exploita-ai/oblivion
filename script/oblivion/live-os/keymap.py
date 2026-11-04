#!/usr/bin/env python3
"""Apply Debian's OS keyboard preferences to the fullscreen Cage terminal."""

import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile
import time

CONFIG = Path("/etc/default/keyboard")
OUTPUT = Path("/run/oblivion-keymap.xkb")
ACK = Path("/run/oblivion-keymap-applied")
FIELDS = {"XKBMODEL": "pc105", "XKBLAYOUT": "us", "XKBVARIANT": "", "XKBOPTIONS": ""}


def settings(data):
    if len(data.encode()) > 16384 or "\0" in data:
        raise ValueError("invalid_debian_keyboard_configuration")
    result = FIELDS.copy()
    for line in data.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key.strip() not in FIELDS:
            continue
        parts = shlex.split(value, comments=True, posix=True) or [""]
        if len(parts) != 1 or len(parts[0]) > 1024 or parts[0].startswith("-") or not re.fullmatch(r"[a-zA-Z0-9_+.,:()\-]*", parts[0]):
            raise ValueError("invalid_debian_keyboard_configuration")
        result[key.strip()] = parts[0]
    return result


def update():
    descriptor = os.open(CONFIG, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 16384:
            raise ValueError("invalid_debian_keyboard_configuration")
        values = settings(source.read(16385).decode("utf-8"))
    command = ["/usr/bin/xkbcli", "compile-keymap", "--include", "/usr/share/X11/xkb", "--rules", "evdev"]
    for key, option in (("XKBMODEL", "--model"), ("XKBLAYOUT", "--layout"), ("XKBVARIANT", "--variant"), ("XKBOPTIONS", "--options")):
        command.extend((option, values[key]))
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            cwd="/", env={"PATH": "/usr/bin:/bin", "HOME": "/", "LANG": "C.UTF-8"}, timeout=15, check=False)
    if result.returncode != 0 or not result.stdout or len(result.stdout) >= 1024 * 1024:
        raise ValueError("debian_keyboard_compile_failed")
    with tempfile.NamedTemporaryFile(dir="/run", prefix=".oblivion-keymap-", delete=False) as output:
        temporary = Path(output.name)
        output.write(result.stdout)
        output.flush()
        os.fchmod(output.fileno(), 0o644)
        os.fsync(output.fileno())
    try:
        os.replace(temporary, OUTPUT)
    finally:
        temporary.unlink(missing_ok=True)
    generation = OUTPUT.stat().st_ino
    active = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "oblivion-display.service"], check=False)
    if active.returncode != 0:
        return
    subprocess.run(["/usr/bin/systemctl", "kill", "--kill-whom=main", "--signal=HUP", "oblivion-display.service"], check=True)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            applied = ACK.read_text().strip()
        except FileNotFoundError:
            applied = ""
        if applied == str(generation):
            return
        time.sleep(0.05)
    raise ValueError("debian_keyboard_apply_pending")


if __name__ == "__main__":
    update()
