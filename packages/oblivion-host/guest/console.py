#!/usr/bin/env python3
"""Session-only PTY: wait for the trusted viewer and propagate its dimensions.

The host sends CSI 8;rows;cols t on attachment and resize. This changes only
the guest PTY size; it never invokes commands or changes host state. Ordinary
input, including other escape sequences, goes to the existing OpenCode TUI.
"""
import errno
import fcntl
import os
import pty
import re
import selectors
import signal
import struct
import sys
import termios
import time
import tty

READY = b"\x1b]777;oblivion;ready\x07"
FAILED = b"\x1b]777;oblivion;client-failed\x07"
PREFIX = b"\x1b[8;"


class Input:
    def __init__(self):
        self.pending = bytearray()
        self.since = 0.0

    def decode(self, data, now):
        output = bytearray()
        sizes = []
        if not data and self.pending and now - self.since >= 0.1:
            output.extend(self.pending)
            self.pending.clear()
        for byte in data:
            self.pending.append(byte)
            self.since = now
            while self.pending and not PREFIX.startswith(self.pending) and not self.pending.startswith(PREFIX):
                output.append(self.pending.pop(0))
            if self.pending.startswith(PREFIX):
                suffix = self.pending[len(PREFIX):]
                if byte == ord("t"):
                    match = re.fullmatch(rb"([0-9]{1,3});([0-9]{1,3})t", suffix)
                    if match and 5 <= int(match[1]) <= 297 and 24 <= int(match[2]) <= 512:
                        sizes.append((int(match[1]), int(match[2])))
                    else:
                        output.extend(self.pending)
                    self.pending.clear()
                elif len(suffix) > 7 or any(value not in b"0123456789;" for value in suffix):
                    output.extend(self.pending)
                    self.pending.clear()
        return bytes(output), sizes


def main(command):
    # Headless OpenCode commands such as `run --format json` deliberately use
    # pipes or /dev/null. They need no viewer resize protocol or guest PTY.
    if not os.isatty(0):
        os.execvp(command[0], command)
    original = termios.tcgetattr(0)
    tty.setraw(0)
    decoder = Input()
    child = None
    master = None
    ready_at = 0.0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(0, selectors.EVENT_READ)
            while True:
                if child is None and time.monotonic() >= ready_at:
                    os.write(1, READY)
                    ready_at = time.monotonic() + 0.5
                events = selector.select(timeout=0.05)
                if not events:
                    data, _ = decoder.decode(b"", time.monotonic())
                    if master is not None and data:
                        os.write(master, data)
                for key, _ in events:
                    try:
                        data = os.read(key.fd, 65536)
                    except OSError as error:
                        if key.fd == master and error.errno == errno.EIO:
                            os.write(1, FAILED)
                            return
                        raise
                    if not data:
                        if key.fd == master:
                            os.write(1, FAILED)
                        return
                    if key.fd == master:
                        os.write(1, data)
                        continue
                    data, sizes = decoder.decode(data, time.monotonic())
                    if child is None and sizes:
                        master, slave = pty.openpty()
                        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", *sizes[-1], 0, 0))
                        child = os.fork()
                        if child == 0:
                            os.close(master)
                            os.setsid()
                            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                            for descriptor in (0, 1, 2):
                                os.dup2(slave, descriptor)
                            if slave > 2:
                                os.close(slave)
                            os.execvp(command[0], command)
                        os.close(slave)
                        selector.register(master, selectors.EVENT_READ)
                    if master is not None:
                        for size in sizes:
                            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", *size, 0, 0))
                        if data:
                            os.write(master, data)
    finally:
        termios.tcsetattr(0, termios.TCSANOW, original)
        if master is not None:
            os.close(master)
        if child:
            # The enclosing systemd cgroup also owns every session subprocess.
            try:
                os.kill(child, signal.SIGHUP)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)


if __name__ == "__main__":
    main(sys.argv[1:])
