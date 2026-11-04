"""Real Linux sockets/process pins; no model, provider or synthetic PID oracle."""

import fcntl
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from oblivion_history.author import call
from oblivion_history.admin import catalog_state
from oblivion_history.catalog import Catalog
from oblivion_history.model import Item, Snapshot

ROOT = Path(__file__).resolve().parents[1]


def emit(value):
    print(json.dumps(value), flush=True)


def worker():
    path, agent = sys.argv[2:4]
    owner = call(path, {"version": 1, "operation": "register", "agent": agent})["owner"]
    with subprocess.Popen([sys.executable, "-B", __file__, "--child", path, owner], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as child:
        call(path, {"version": 1, "operation": "bind-child", "owner": owner, "pid": child.pid})
        emit({"pid": child.pid, "owner": owner})
        for line in sys.stdin:
            value = json.loads(line)
            if value == "native-exit":
                child.kill()
                child.wait()
                emit({"exited": True})
                continue
            if value == "exit":
                child.kill()
                child.wait()
                return
            child.stdin.write(line)
            child.stdin.flush()
            print(child.stdout.readline(), end="", flush=True)


def native_child():
    path, owner = sys.argv[2:4]
    for line in sys.stdin:
        native, cwd = json.loads(line)
        try:
            emit(call(path, {"version": 1, "operation": "claim", "owner": owner, "native_id": native, "cwd": cwd}))
        except ValueError as error:
            emit({"error": str(error)})
    # Survive orphaning: a dead wrapper alone must not unlock a live writer.
    while True:
        signal.pause()


def line(process):
    if not select.select([process.stdout], [], [], 10)[0]:
        raise AssertionError("fixture process did not respond")
    value = process.stdout.readline()
    if not value:
        raise AssertionError("fixture process exited: " + str(process.poll()))
    return json.loads(value)


class IdentityTests(unittest.TestCase):
    def test_admin_snapshot_hides_reservations_until_real_message_ingestion(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "history"
            self.assertEqual(catalog_state(state, None)["consistency"], "catalog-empty")
            self.assertFalse(state.exists())
            state.mkdir(mode=0o700)
            self.assertEqual(catalog_state(state, None)["entries"], [])
            self.assertEqual(list(state.iterdir()), [])
            catalog = Catalog(state)
            (state / "history.sqlite").chmod(0o600)
            chat = catalog.author_identity("claude", "native-one", "/vault/workspace", set())
            self.assertEqual(catalog_state(state, None)["entries"], [])
            self.assertEqual(catalog.chats(), [])
            observed, _ = catalog.ingest(Snapshot("claude", "native-one", "/vault/workspace", "Real saved message", 1, 2,
                [Item("user-one", "text", "user", {"text": "Synthetic saved message"}, 2)], fingerprint="saved"))
            self.assertEqual(observed, chat)
            entries = catalog_state(state, None)["entries"]
            self.assertEqual([(row["chat_id"], row["title"], row["agents"]) for row in entries], [(chat, "Real saved message", ["claude"])])
            self.assertEqual([row[0]["id"] for row in catalog.chats()], [chat])
            catalog.close()

    def test_admission_resolves_alias_and_rejects_a_stale_foreign_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog = Catalog(tmp)
            with catalog.exclusive():
                chat = catalog.author_identity("claude", "native-one", "/vault/workspace", set())
                self.assertEqual(catalog.author_identity("claude", "native-one", "/vault/workspace", set()), chat)
                self.assertEqual(catalog.chats(), [])  # An admission is not a visible message.
                codex = catalog.native_id(chat, "codex")
                catalog.mark_projection("codex", codex, chat)
                self.assertEqual(catalog.author_identity("codex", codex, "/vault/workspace", set()), chat)
                with catalog.db:
                    catalog.db.execute("UPDATE chat SET updated=updated+1 WHERE id=?", (chat,))
                with self.assertRaisesRegex(ValueError, "author_history_stale_reopen"):
                    catalog.author_identity("codex", codex, "/vault/workspace", set())
                self.assertEqual(catalog.author_identity("codex", codex, "/vault/workspace", {chat}), chat)
            catalog.close()

    def test_admission_never_resurrects_a_deleted_conversation(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog = Catalog(tmp)
            chat = catalog.author_identity("claude", "native-one", "/vault/workspace", set())
            catalog.confirm_delete(chat, chat)
            with self.assertRaisesRegex(ValueError, "author_chat_deleted"):
                catalog.author_identity("claude", "native-one", "/vault/workspace", set())
            catalog.close()


@unittest.skipUnless(sys.platform.startswith("linux"), "Production author admission requires Linux SO_PEERPIDFD/pidfd.")
class AuthorProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.socket = self.root / "author.sock"
        self.workers = []
        self.start_service()

    def start_service(self):
        self.service = subprocess.Popen([sys.executable, "-B", str(ROOT / "history.py"), "author", "--home", str(self.root), "--workspace", str(self.workspace), "--state", str(self.state), "--author-socket", str(self.socket)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while not self.socket.exists():
            if self.service.poll() is not None:
                self.fail(self.service.stderr.read().decode())
            if time.monotonic() > deadline:
                self.fail("author service did not start")
            select.select([], [], [], 0.01)

    def stop_service(self):
        self.service.kill()
        self.service.wait(timeout=10)
        self.service.stderr.close()
        self.socket.unlink(missing_ok=True)

    def tearDown(self):
        for process, child in self.workers:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            for stream in (process.stdin, process.stdout):
                stream.close()
            # A failed assertion must not leave a fixture orphan behind.
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.stop_service()
        self.temporary.cleanup()

    def new_owner(self, agent="claude"):
        process = subprocess.Popen([sys.executable, "-B", __file__, "--worker", str(self.socket), agent], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        info = line(process)
        self.workers.append((process, info["pid"]))
        return process, info

    def command(self, process, value):
        process.stdin.write(json.dumps(value) + "\n")
        process.stdin.flush()
        return line(process)

    def claim(self, process, native):
        return self.command(process, [native, str(self.workspace)])

    def markers_gone(self):
        deadline = time.monotonic() + 10
        while list((self.state / "authors").glob("*.active")):
            if time.monotonic() > deadline:
                self.fail("dead native owner retained an admission")
            select.select([], [], [], 0.01)

    def test_distinct_conversations_can_write_but_same_canonical_alias_cannot(self):
        first, _ = self.new_owner()
        second, _ = self.new_owner("codex")
        self.assertEqual(self.claim(first, "native-one"), {"allowed": True})
        catalog = Catalog(self.state)
        with catalog.exclusive():
            chat = catalog.db.execute("SELECT chat_id FROM native WHERE native_id='native-one'").fetchone()[0]
            alias = catalog.native_id(chat, "codex")
            catalog.mark_projection("codex", alias, chat)
        catalog.close()
        self.assertEqual(self.claim(second, alias), {"error": "author_conversation_busy"})
        self.assertEqual(self.claim(second, "different-native"), {"allowed": True})
        self.assertEqual(self.claim(first, "native-one"), {"allowed": True})

    def test_child_exit_does_not_release_before_wrapper_post_sync_finishes(self):
        first, _ = self.new_owner()
        second, _ = self.new_owner()
        self.assertEqual(self.claim(first, "native-one"), {"allowed": True})
        self.assertEqual(self.command(first, "native-exit"), {"exited": True})
        self.assertEqual(self.claim(second, "native-one"), {"error": "author_conversation_busy"})
        first.stdin.write('"exit"\n')
        first.stdin.flush()
        first.wait(timeout=10)
        self.markers_gone()
        self.assertEqual(self.claim(second, "native-one"), {"allowed": True})

    def test_killed_wrapper_cannot_leave_a_live_unlocked_native_child(self):
        first, info = self.new_owner()
        self.assertEqual(self.claim(first, "native-one"), {"allowed": True})
        descriptor = os.pidfd_open(info["pid"])
        try:
            first.kill()
            first.wait(timeout=10)
            self.assertTrue(select.select([descriptor], [], [], 10)[0], "orphaned native process was not terminated")
            self.markers_gone()
        finally:
            os.close(descriptor)
        second, _ = self.new_owner()
        self.assertEqual(self.claim(second, "native-one"), {"allowed": True})

    def test_service_restart_with_live_marker_fences_admissions(self):
        first, _ = self.new_owner()
        self.assertEqual(self.claim(first, "native-one"), {"allowed": True})
        self.stop_service()
        self.start_service()
        self.assertEqual(self.claim(first, "native-one"), {"error": "author_recovery_required_reopen_safe"})
        with self.assertRaisesRegex(ValueError, "author_recovery_required_reopen_safe"):
            call(self.socket, {"version": 1, "operation": "register", "agent": "claude"})

    def test_unrelated_same_uid_process_cannot_use_owner_token_or_bind_child(self):
        first, info = self.new_owner()
        with self.assertRaisesRegex(ValueError, "author_invalid_owner"):
            call(self.socket, {"version": 1, "operation": "claim", "owner": info["owner"], "native_id": "native-one", "cwd": str(self.workspace)})
        with self.assertRaisesRegex(ValueError, "author_invalid_child"):
            call(self.socket, {"version": 1, "operation": "bind-child", "owner": info["owner"], "pid": os.getpid()})
        self.assertEqual(self.claim(first, "native-one"), {"allowed": True})

    def test_busy_catalog_returns_denial_instead_of_rewriting_active_profile(self):
        first, _ = self.new_owner()
        catalog = Catalog(self.state)
        with catalog.exclusive():
            self.assertEqual(self.claim(first, "native-one"), {"error": "author_unavailable"})
        catalog.close()
        self.assertEqual(self.claim(first, "native-one"), {"allowed": True})


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker()
    elif len(sys.argv) > 1 and sys.argv[1] == "--child":
        native_child()
    else:
        unittest.main()
