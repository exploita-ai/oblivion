"""Explicit pinned-Claude fixture. Docker runner has no external network.

Native histories start with two synthetic messages. Fixture hooks deny every
prompt, so there is no model call, credential use or generated reply.
"""

import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from oblivion_history.catalog import Catalog
from oblivion_history.claude import read_claude, write_claude
from oblivion_history.layout import Layout
from oblivion_history.model import Item, VERSIONS

HISTORY = Path(__file__).resolve().parents[1] / "history.py"
SOCKET = "/run/oblivion-author/author.sock"
BINARY = "/agents/claude/claude"


def block_fixture():
    json.load(sys.stdin)
    barrier = os.environ.get("OBLIVION_TEST_BARRIER")
    if barrier:
        Path(barrier + ".ready").touch()
        deadline = time.monotonic() + 15
        while not Path(barrier + ".release").exists():
            if time.monotonic() > deadline:
                raise RuntimeError("fixture barrier timed out")
            select.select([], [], [], 0.01)
    print(json.dumps({"decision": "block", "reason": "Synthetic fixture: no model call", "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}))


class PinnedClaudeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.state = self.home / ".oblivion-history"
        self.layout = Layout.resolve(self.home)
        now = time.time_ns() // 1_000_000 - 10000
        self.native = str(uuid.uuid4())
        chat = {"id": str(uuid.uuid4()), "title": "Synthetic admission fixture", "cwd": str(self.workspace), "created": now, "updated": now + 1}
        items = [Item("original-user", "text", "user", {"text": "Original synthetic question"}, now, str(uuid.uuid4())),
                 Item("original-answer", "text", "assistant", {"text": "Original synthetic answer"}, now + 1, str(uuid.uuid4()))]
        path, _, _ = write_claude(self.layout, chat, items, self.native, lambda *_: None, {})
        self.transcript = Path(path)
        catalog = Catalog(self.state)
        canonical, _ = catalog.ingest(read_claude(self.transcript))
        for agent in ("codex", "claude", "opencode2"):
            # Other clients are not part of this fixture; current projection
            # markers keep hold's real sync from invoking their importers.
            native = catalog.native_id(canonical, agent)
            catalog.mark_projection(agent, native, canonical)
        catalog.close()
        self.environment = {**os.environ, **self.layout.environment(), "ANTHROPIC_API_KEY": "sk-ant-oblivion-synthetic-no-network",
                            "ANTHROPIC_BASE_URL": "http://127.0.0.1:1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                            "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1"}
        self.environment.pop("OBLIVION_AUTHOR_OWNER", None)
        self.service = subprocess.Popen([sys.executable, "-B", str(HISTORY), "author", "--home", str(self.home), "--workspace", str(self.workspace), "--state", str(self.state), "--author-socket", SOCKET], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while not Path(SOCKET).exists():
            if self.service.poll() is not None:
                self.fail(self.service.stderr.read().decode())
            if time.monotonic() > deadline:
                self.fail("author service did not start")
            select.select([], [], [], 0.01)

    def tearDown(self):
        self.service.kill()
        self.service.wait(timeout=10)
        self.service.stderr.close()
        Path(SOCKET).unlink(missing_ok=True)
        self.temporary.cleanup()

    def command(self, settings, *, wrapped=True):
        native = [BINARY, "--print", "--output-format", "stream-json", "--verbose", "--resume", self.native, "--settings", json.dumps(settings), "--max-turns", "1", "DENIED_PROMPT_CANARY"]
        if not wrapped:
            return native
        return [sys.executable, "-B", str(HISTORY), "hold", "--home", str(self.home), "--workspace", str(self.workspace), "--state", str(self.state), "--author-socket", SOCKET, "--agent", "claude", "--", *native]

    def blocked(self, output, *, failure=None):
        rows = [json.loads(row) for row in output.splitlines()]
        outcomes = [row["prompt_submit_outcome"] for row in rows if "prompt_submit_outcome" in row]
        self.assertTrue(outcomes, output[-1000:])
        if failure:
            self.assertTrue(all(row == {"kind": "no_verdict", "prompt_kept": False, "no_verdict_kind": failure} for row in outcomes), repr(outcomes))
        else:
            self.assertTrue(all(row["kind"] == "blocked_by_hook" for row in outcomes), repr(outcomes))
        results = [row for row in rows if "duration_api_ms" in row]
        self.assertTrue(results)
        for row in results:
            self.assertEqual(row["duration_api_ms"], 0)
            self.assertEqual(row["num_turns"], 0)
        snapshot = read_claude(self.transcript)
        self.assertEqual([item.body["text"] for item in snapshot.items], ["Original synthetic question", "Original synthetic answer"])

    def test_real_resume_is_denied_while_another_native_child_owns_the_chat(self):
        barrier = str(self.root / "barrier")
        settings = {"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": "python3 -B " + __file__ + " --block-fixture", "timeout": 20, "onFailure": "block"}]}]}}
        first = subprocess.Popen(self.command(settings), env={**self.environment, "OBLIVION_TEST_BARRIER": barrier}, cwd=self.workspace, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 20
            while not Path(barrier + ".ready").exists() or not list((self.state / "authors").glob("*.active")):
                if first.poll() is not None:
                    self.fail(first.communicate()[1].decode())
                if time.monotonic() > deadline:
                    self.fail("real Claude never acquired admission")
                select.select([], [], [], 0.01)
            second = subprocess.run(self.command({}), env=self.environment, cwd=self.workspace, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
            self.assertEqual(second.returncode, 0, second.stderr.decode())
            self.blocked(second.stdout.decode())
            Path(barrier + ".release").touch()
            output, error = first.communicate(timeout=20)
            self.assertEqual(first.returncode, 0, error.decode())
            self.blocked(output.decode())
        finally:
            if first.poll() is None:
                first.kill()
            first.communicate(timeout=20)

    def test_managed_hook_cannot_be_disabled_by_cli_settings(self):
        for mode in ("settings", "bare", "simple"):
            with self.subTest(mode=mode):
                command = self.command({"disableAllHooks": True}, wrapped=False)
                environment = dict(self.environment)
                if mode == "bare":
                    command.insert(1, "--bare")
                if mode == "simple":
                    environment["CLAUDE_CODE_SIMPLE"] = "1"
                result = subprocess.run(command, env=environment, cwd=self.workspace, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.blocked(result.stdout.decode())

    def test_native_hook_failures_block_without_a_canonical_user_message(self):
        for command, timeout, reason in (("/oblivion-fixture-command-does-not-exist", 2, "hook_failed"), ("exit 1", 2, "hook_failed"), ("printf '{\"decision\":42}'", 2, "hook_failed"), ("sleep 3", 1, "hook_timed_out")):
            with self.subTest(command=command):
                settings = {"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": command, "timeout": timeout, "onFailure": "block"}]}]}}
                result = subprocess.run(self.command(settings), env=self.environment, cwd=self.workspace, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.blocked(result.stdout.decode(), failure=reason)


if __name__ == "__main__":
    if sys.argv[1:] == ["--block-fixture"]:
        block_fixture()
    else:
        version = subprocess.run([BINARY, "--version"], stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        if version.returncode != 0 or version.stdout.decode().strip() != VERSIONS["claude"] + " (Claude Code)":
            sys.exit("The fixture requires the exact pinned Claude Code " + VERSIONS["claude"] + " binary.")
        unittest.main()
