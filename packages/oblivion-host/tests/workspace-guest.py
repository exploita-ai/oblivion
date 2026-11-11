"""Linux guest fixture: real tmux and native wrappers; no model calls.

Run in an isolated container with the guest files staged at their production
paths, UID1000, tmpfs /vault and synthetic native executables. A real VM remains
necessary to qualify systemd/cgroup shutdown and the attachment lifetime.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest


@unittest.skipUnless(sys.platform == "linux" and os.getuid() == 1000 and os.path.ismount("/vault"), "isolated UID1000 guest fixture required")
class Workspace(unittest.TestCase):
    def setUp(self):
        self.server = None

    def tearDown(self):
        if self.server:
            self.server.terminate()
            self.server.wait(timeout=5)

    def wait_socket(self, path, process):
        deadline = time.monotonic() + 5
        while not Path(path).is_socket():
            self.assertIsNone(process.poll())
            if time.monotonic() >= deadline:
                self.fail("fixture service was not ready")
            time.sleep(0.02)

    def test_native_wrapper_preserves_argv_cwd_and_status(self):
        arguments = ["--resume", "space ; $HOME", "", "à", "--"]
        result = subprocess.run(["/usr/bin/codex", *arguments], cwd="/vault/workspace/project", env={"PATH":"/usr/bin:/bin"}, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 23, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["argv"], arguments)
        self.assertEqual(report["cwd"], "/vault/workspace/project")
        self.assertEqual(report["home"], "/vault/home")
        self.assertEqual(report["config"], "/vault/config")
        self.assertEqual(report["telemetry"], "true")
        self.assertEqual(report["state"], "/vault/state")
        self.assertEqual(report["cache"], "/tmp/oblivion-cache")
        self.assertFalse(Path("/vault/home/.oblivion-history").exists())
        self.assertFalse(Path("/run/oblivion-history").exists())

    def test_foreground_tmux_server_and_independent_shell_panes(self):
        self.server = subprocess.Popen(["/usr/lib/oblivion/guest/workspace-server.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        endpoint = "/run/oblivion-workspace/tmux.sock"
        self.wait_socket(endpoint, self.server)
        command = ["/usr/bin/tmux", "-N", "-S", endpoint]
        subprocess.run([*command, "new-session", "-d", "-s", "workspace", "-c", "/vault/workspace", "/bin/bash", "-l"], check=True)
        subprocess.run([*command, "split-window", "-h", "-t", "workspace"], check=True)
        panes = subprocess.check_output([*command, "list-panes", "-t", "workspace", "-F", "#{pane_id}:#{pane_current_command}"], text=True).splitlines()
        self.assertEqual(len(panes), 2)
        self.assertTrue(all(pane.endswith(":bash") for pane in panes), panes)
        self.assertEqual(subprocess.check_output([*command, "show-option", "-gv", "default-command"], text=True).strip(), "/bin/bash -l")
        self.assertEqual(subprocess.check_output([*command, "show-option", "-gv", "history-limit"], text=True).strip(), "2000")
        self.assertEqual(subprocess.check_output([*command, "show-option", "-gv", "set-clipboard"], text=True).strip(), "off")
        self.server.terminate()
        self.server.wait(timeout=5)
        self.assertNotEqual(subprocess.run([*command, "list-sessions"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode, 0)
        self.server = None


if __name__ == "__main__":
    unittest.main()
