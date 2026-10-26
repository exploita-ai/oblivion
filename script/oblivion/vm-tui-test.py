#!/usr/bin/env python3
"""Real manager PTY + real controller/VMs; only public synthetic credentials."""
import base64
import codecs
import io
import hashlib
import pyte
from PIL import Image, ImageDraw, ImageFont
import fcntl
import json
import os
import re
import select
import signal
import struct
import subprocess
import termios
import time
from pathlib import Path

CONFIG = "/run/oblivion-manager-test.json"
GENERAL = b"synthetic-general-password"
PASSWORD = b"synthetic-session-password-a"
screen = bytearray()
terminal = pyte.Screen(100, 30)
stream = pyte.Stream(terminal)
decoder = codecs.getincrementaldecoder("utf-8")("replace")


def check(label):
    print("PASS: " + label, flush=True)


def command(operation, *arguments, secret=b""):
    result = subprocess.run(["/usr/bin/oblivion-storage-lab", "--config", CONFIG, operation, *arguments],
        input=secret, capture_output=True, timeout=90)
    assert result.returncode == 0, (operation, result.stderr)
    return result.stdout.decode().strip()


def wait(marker):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        assert manager.poll() is None, ("manager exited", manager.returncode)
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            chunk = os.read(master, 65536)
            screen.extend(chunk)
            stream.feed(decoder.decode(chunk))
            if marker in "\n".join(terminal.display):
                return
    raise AssertionError(("screen timeout", marker, "\n".join(terminal.display)))


def screenshot(name):
    if name != "trusted-confirmation":
        # The host paints a whole screen, but PTY reads split it into chunks.
        # Wait for its generated final cursor sequence instead of capturing the
        # first chunk that happens to contain the expected text.
        deadline = time.monotonic() + 5
        marker = {"home": "/exit blocca", "conversation-a": "OBLIVION_TUI_A_REPLY",
            "resumed-a": "OBLIVION_TUI_A_RESUMED"}[name]
        while not (re.search(rb"\x1b\[\d+;\d+H\x1b\[\?25[hl]$", screen[-64:])
                and marker in "\n".join(terminal.display) and "commands" in "\n".join(terminal.display)):
            assert time.monotonic() < deadline, "incomplete host frame"
            if select.select([master], [], [], 0.1)[0]:
                chunk = os.read(master, 65536)
                screen.extend(chunk)
                stream.feed(decoder.decode(chunk))
    image = Image.new("RGB", (1000, 600), "#111111")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 16)
    palette = {"black": "#111111", "red": "#cc5555", "green": "#55bb66", "brown": "#c5a555",
        "blue": "#6688cc", "magenta": "#bb88dd", "cyan": "#66cccc", "white": "#eeeeee", "default": "#dddddd"}
    for row in range(30):
        for col in range(100):
            cell = terminal.buffer[row][col]
            foreground = palette.get(cell.fg, "#" + cell.fg)
            background = "#111111" if cell.bg == "default" else palette.get(cell.bg, "#" + cell.bg)
            if cell.reverse:
                foreground, background = background, foreground
            draw.rectangle((col * 10, row * 20, col * 10 + 9, row * 20 + 19), fill=background)
            draw.text((col * 10, row * 20), cell.data, font=font, fill=foreground)
    data = io.BytesIO()
    image.save(data, format="PNG")
    print("OBLIVION_SCREENSHOT " + name + " " + base64.b64encode(data.getvalue()).decode(), flush=True)
    # Synthetic cells let reviewers distinguish terminal rendering from PNG
    # rasterization when checking the limited-color Linux-console palette.
    cells = [[[terminal.buffer[row][col].data, terminal.buffer[row][col].fg,
        terminal.buffer[row][col].bg, terminal.buffer[row][col].reverse]
        for col in range(100)] for row in range(30)]
    print("OBLIVION_SCREEN_CELLS " + name + " " + base64.b64encode(json.dumps(cells).encode()).decode(), flush=True)


def send(value, marker):
    os.write(master, value)
    wait(marker)


def status():
    return json.loads(command("status"))


def session_create(password):
    send(b"n", "Nuova sessione - password")
    send(password + b"\r", "Ripeti la password")
    send(password + b"\r", "Conversazioni e documenti")
    wait("/exit blocca")


print("OBLIVION_TUI_FIXTURE_SHA256 " + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), flush=True)
os.umask(0o077)
subprocess.run(["mkfs.ext4", "-q", "-m", "0", "/dev/vdb"], check=True)
subprocess.run(["mount", "/dev/vdb", "/data"], check=True)
Path(CONFIG).write_text(json.dumps({"general_image": "/data/general.luks", "general_mib": 768,
    "session_mib": 128, "pbkdf_memory_kib": 65536, "manager_uid": 1000,
    "vm": {"root": "/usr/lib/oblivion/vm/qemu-root", "kernel": "/usr/lib/oblivion/vm/kernel",
           "initrd": "/usr/lib/oblivion/vm/initrd", "filesystem": "/usr/lib/oblivion/vm/guest.squashfs",
           "memory_mib": 1536, "cpus": 2, "accelerator": "tcg"}}))
command("init-general", secret=GENERAL)
daemon = subprocess.Popen(["/usr/bin/oblivion-storage-lab", "--config", CONFIG, "serve"],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
deadline = time.monotonic() + 10
while not Path("/run/oblivion-control.sock").exists():
    assert daemon.poll() is None and time.monotonic() < deadline
    time.sleep(0.01)
master, slave = os.openpty()
os.chown(os.ttyname(slave), 1000, 1000)
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))


def terminal_session():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


manager = subprocess.Popen(["/usr/bin/oblivion-manager"], stdin=slave, stdout=slave, stderr=slave,
    user=1000, group=1000, extra_groups=[], preexec_fn=terminal_session,
    env={"TERM": "linux", "PATH": "/usr/bin:/bin", "HOME": "/run/oblivion-manager-home"})
os.close(slave)
try:
    wait("Archivio generale bloccato")
    send(b"\r", "Password del volume generale")
    send(b"incorrect-synthetic-password\r", "Operazione non completata")
    assert not status()["general_open"]
    check("wrong password in the nonroot TUI leaves the general volume locked")
    send(b"\r", "Password del volume generale")
    send(GENERAL + b"\r", "Nessuna sessione")
    assert status()["general_open"] and not status()["session_open"]
    check("trusted TUI unlocks general storage without opening a session")
    session_create(PASSWORD)
    a = status()["sessions"][0]
    screenshot("home")
    send(b"OBLIVION_TUI_A_REQUEST", "OBLIVION_TUI_A_REQUEST")
    send(b"\r", "OBLIVION_TUI_A_REPLY")
    screenshot("conversation-a")
    check("compiled guest TUI streams a reply and executes a real shell tool inside A")
    send(b"/new", "Nuova sessione protetta")
    send(b"\r", "La chat chiede di creare")
    assert status()["session_open"] and status()["sessions"] == [a]
    screenshot("trusted-confirmation")
    # A pasted reserved key cannot confirm an untrusted guest request.
    os.write(master, b"\x1b[200~\x1d\x1b[201~")
    send(b"\x1b", "OBLIVION_TUI_A_REPLY")
    assert status()["session_open"] and status()["sessions"] == [a]
    check("new-session hint and pasted Ctrl+] cannot close a vault; Escape cancels")
    send(b"/new", "Nuova sessione protetta")
    send(b"\r", "La chat chiede di creare")
    send(b"\x1d", "Nuova sessione - password")
    assert not status()["session_open"]
    send(b"synthetic-session-password-b\r", "Ripeti la password")
    send(b"synthetic-session-password-b\r", "Conversazioni e documenti")
    send(b"OBLIVION_TUI_B_REQUEST", "OBLIVION_TUI_B_REQUEST")
    send(b"\r", "OBLIVION_TUI_B_REPLY")
    check("confirmed new-session action closes A before password entry and opens isolated B")
    send(b"/sessions", "Cambia sessione protetta")
    send(b"\r", "La chat chiede di cambiare")
    send(b"\x1d", "Sessioni protette")
    assert not status()["session_open"]
    sessions = status()["sessions"]
    if sessions.index(a) == 1:
        send(b"j", "Sessioni protette")
    send(b"\r", "Password della sessione")
    send(PASSWORD + b"\r", "OBLIVION_TUI_A_REPLY")
    send(b"OBLIVION_TUI_RESUME", "OBLIVION_TUI_RESUME")
    send(b"\r", "OBLIVION_TUI_A_RESUMED")
    screenshot("resumed-a")
    check("reopening A restores its primary conversation and documents but not RAM temporaries")
    send(b"exit", "exit")
    send(b"\r", "La chat chiede di chiudere")
    send(b"\x1b", "OBLIVION_TUI_A_RESUMED")
    assert status()["session_open"]
    send(b"/exit", "Chiudi e blocca la sessione")
    send(b"\r", "La chat chiede di chiudere")
    send(b"\x1d", "Sessioni protette")
    assert not status()["session_open"]
    check("guest exit action returns only after VM shutdown and session LUKS closure")
    # Exit may draw only the busy screen, then clear; wait on the real child.
    os.write(master, b"q")
    while manager.poll() is None:
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            try:
                screen.extend(os.read(master, 65536))
            except OSError:
                break
    assert manager.wait(timeout=10) == 0
    assert not status()["general_open"] and not status()["session_open"]
    assert all(secret not in screen for secret in [GENERAL, PASSWORD, b"synthetic-session-password-b", b"incorrect-synthetic-password"])
    check("passwords never appear in terminal output and exit closes both encryption layers")
    daemon.terminate()
    daemon.wait(timeout=10)
    subprocess.run(["umount", "/data"], check=True)
    print("OBLIVION_VM_LAB_PASS", flush=True)
except BaseException:
    print("OBLIVION_VM_LAB_FAIL", flush=True)
    raise
finally:
    if manager.poll() is None:
        manager.kill()
        manager.wait(timeout=10)
    os.close(master)
