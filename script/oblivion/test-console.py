#!/usr/bin/env python3
"""Real PTY regression for delayed viewer attachment and guest resize."""
import importlib.util
import os
import pty
import select
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
source = Path(__file__).resolve().parents[2] / "packages/oblivion-host/guest/console.py"
spec = importlib.util.spec_from_file_location("console", source)
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)


class ConsoleTest(unittest.TestCase):
    def test_non_terminal_executes_command_without_pty(self):
        result = subprocess.run(
            [sys.executable, str(source), sys.executable, "-c", "print('HEADLESS')"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "HEADLESS\n")
        self.assertEqual(result.stderr, "")

    def test_input_preserves_text_and_split_escape_sequences(self):
        decoder = console.Input()
        output = bytearray()
        sizes = []
        for byte in b"hello\x1b[A\x1b[8;47;160tworld":
            text, resize = decoder.decode(bytes([byte]), 0)
            output.extend(text)
            sizes.extend(resize)
        self.assertEqual(output, b"hello\x1b[Aworld")
        self.assertEqual(sizes, [(47, 160)])
        self.assertEqual(decoder.decode(b"\x1b[8;999;999t", 0), (b"\x1b[8;999;999t", []))
        self.assertEqual(decoder.decode(b"\x1b", 0), (b"", []))
        self.assertEqual(decoder.decode(b"", 1), (b"\x1b", []))

    def test_application_starts_only_after_viewer_size_and_receives_resize(self):
        master, slave = pty.openpty()
        fixture = """import os, signal, sys
def report(*args):
    size = os.get_terminal_size()
    print(f'VISIBLE:{size.lines}:{size.columns}', flush=True)
signal.signal(signal.SIGWINCH, report)
report()
for line in sys.stdin:
    if line.strip() == 'quit': break
"""
        child = subprocess.Popen([sys.executable, str(source), sys.executable, "-u", "-c", fixture], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
        os.close(slave)
        captured = bytearray()

        def until(marker):
            deadline = time.monotonic() + 5
            while marker not in captured and time.monotonic() < deadline:
                if select.select([master], [], [], max(0, deadline - time.monotonic()))[0]:
                    captured.extend(os.read(master, 65536))
            self.assertIn(marker, captured)

        try:
            until(console.READY)
            self.assertNotIn(b"VISIBLE", captured)
            # Discard the first ready frame, as happens before a viewer attaches.
            captured.clear()
            until(console.READY)
            self.assertNotIn(b"VISIBLE", captured)
            os.write(master, b"\x1b[8;47;160t")
            until(b"VISIBLE:47:160")
            os.write(master, b"\x1b[8;21;80t")
            until(b"VISIBLE:21:80")
            os.write(master, b"quit\n")
            self.assertEqual(child.wait(timeout=5), 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            os.close(master)


if __name__ == "__main__":
    unittest.main()
