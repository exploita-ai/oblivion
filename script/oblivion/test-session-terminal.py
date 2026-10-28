#!/usr/bin/env python3
"""Real PTY/tmux integration for protected terminal windows and reattachment."""
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "packages/oblivion-host/guest/console.py"
CONFIG = ROOT / "packages/oblivion-host/guest/tmux.conf"


class SessionTerminalTest(unittest.TestCase):
    def test_real_shell_multiple_windows_resize_and_reattachment(self):
        tmux = shutil.which("tmux")
        self.assertIsNotNone(tmux, "Install tmux to run the real session-terminal test")
        with tempfile.TemporaryDirectory(prefix="oblivion-terminal-") as directory:
            socket = str(Path(directory) / "tmux.sock")
            command = [tmux, "-f", str(CONFIG), "-S", socket, "new-session", "-A", "-s", "workspace", "-c", directory]
            refresh = [tmux, "-S", socket, "refresh-client"]
            launcher = "import importlib.util,sys; sys.dont_write_bytecode=True; s=importlib.util.spec_from_file_location('guest',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.main(__import__('json').loads(sys.argv[2]),persistent=True,refresh=__import__('json').loads(sys.argv[3]))"

            def attach():
                import json
                master, slave = pty.openpty()
                child = subprocess.Popen([sys.executable, "-c", launcher, str(SOURCE), json.dumps(command), json.dumps(refresh)], stdin=slave, stdout=slave, stderr=slave,
                                         env={"PATH": "/opt/homebrew/bin:/usr/bin:/bin", "TERM": "xterm-256color", "HISTFILE": "/dev/null", "HOME": directory, "TMPDIR": directory}, close_fds=True)
                os.close(slave)
                captured = bytearray()
                deadline = time.monotonic() + 5
                while b"oblivion;ready" not in captured and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        captured.extend(os.read(master, 65536))
                self.assertIn(b"oblivion;ready", captured)
                os.write(master, b"\x1b[8;24;80t")
                return child, master

            def wait_file(name, contents):
                deadline = time.monotonic() + 5
                file = Path(directory) / name
                while time.monotonic() < deadline:
                    if file.exists() and file.read_text() == contents:
                        return
                    if select.select([master], [], [], 0.01)[0]:
                        os.read(master, 65536)
                self.fail(f"Real shell did not write {name}")

            def wait_output(marker):
                captured = bytearray()
                deadline = time.monotonic() + 5
                while marker not in captured and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.01)[0]:
                        captured.extend(os.read(master, 65536))
                self.assertIn(marker, captured)

            child, master = attach()
            try:
                os.write(master, b"printf alpha > first.txt\n")
                wait_file("first.txt", "alpha")
                os.write(master, b"\x02c")
                os.write(master, b"printf beta > second.txt\n")
                wait_file("second.txt", "beta")
                windows = subprocess.check_output([tmux, "-S", socket, "list-windows", "-F", "#{window_index}"], text=True)
                self.assertEqual(windows.splitlines(), ["0", "1"])
                os.write(master, b"\x1b[8;30;120t")
                os.write(master, b"stty size > size.txt\n")
                wait_file("size.txt", "29 120\n")
                marker = b"VIEW_REATTACH_CANARY"
                os.write(master, ("printf '" + "".join(f"\\{byte:03o}" for byte in marker + b"\n") + "'\n").encode())
                wait_output(marker)
                os.write(master, b"\x1b[8;30;120t")
                wait_output(marker)
                child.terminate(); child.wait(timeout=5); os.close(master)
                child, master = attach()
                os.write(master, b"printf resumed > resumed.txt\n")
                wait_file("resumed.txt", "resumed")
                windows = subprocess.check_output([tmux, "-S", socket, "list-windows", "-F", "#{window_index}"], text=True)
                self.assertEqual(windows.splitlines(), ["0", "1"])
                clipboard = subprocess.check_output([tmux, "-S", socket, "show-option", "-gv", "set-clipboard"], text=True)
                self.assertEqual(clipboard.strip(), "off")
            finally:
                child.terminate(); child.wait(timeout=5); os.close(master)
                subprocess.run([tmux, "-S", socket, "kill-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    unittest.main()
