"""Confirmed catalog deletion. Never infer intent from a missing native file."""

from contextlib import ExitStack
import fcntl
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess

from .catalog import Catalog
from .claude import read_claude
from .codex import codex_request, read_codex
from .model import VERSIONS
from .opencode import database, read_opencode


def delete_chat(layout, workspace, state, chat_id, confirmation):
    catalog = Catalog(state)
    try:
        with catalog.exclusive(), ExitStack() as locks:
            # Admission is explicit and all-or-nothing. A native picker or
            # idle TUI still holds its profile lease and makes this busy.
            for agent in VERSIONS:
                lease = locks.enter_context(
                    open(Path(state) / (agent + ".active"), "a+b")
                )
                try:
                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ValueError("history_delete_busy") from None
            chat = catalog.db.execute(
                "SELECT cwd FROM chat WHERE id=?", (chat_id,)
            ).fetchone()
            if chat is None or chat[0] != str(Path(workspace).resolve()):
                raise ValueError("history_chat_not_found")
            catalog.confirm_delete(chat_id, confirmation)
            errors = reconcile_deletions(catalog, layout, locked=True)
            return {"chat_id": chat_id, "deleted": not errors, "errors": errors}
    finally:
        catalog.close()


def reconcile_deletions(catalog, layout, *, locked=False):
    errors = []
    for target in catalog.deletions():
        with open(catalog.directory / (target["agent"] + ".active"), "a+b") as lease:
            try:
                if not locked:
                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                delete_native(layout, target)
                catalog.complete_delete(target["chat_id"], target["agent"])
            except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
                errors.append(
                    {"agent": target["agent"], "error": "history_delete_pending"}
                )
    return errors


def delete_native(layout, target):
    agent = target["agent"]
    identifier = target["native_id"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", identifier):
        raise ValueError("history_delete_identity_mismatch")
    if agent == "codex":
        paths = [
            path
            for root in (layout.codex / "sessions", layout.codex / "archived_sessions")
            for path in root.glob("**/rollout-*" + identifier + ".jsonl")
        ]
        for path in paths:
            if path.is_symlink():
                raise ValueError("history_delete_identity_mismatch")
            snapshot = read_codex(path)
            if snapshot.native_id != identifier or snapshot.cwd != target["cwd"]:
                raise ValueError("history_delete_identity_mismatch")
        if paths:
            codex_request(
                layout, target["cwd"], "thread/delete", {"threadId": identifier}
            )
        if any(path.exists() for path in paths):
            raise ValueError("history_native_delete_incomplete")
        return
    if agent == "opencode2":
        path = database(layout)
        if not path.exists():
            return
        with sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True) as db:
            row = db.execute(
                "SELECT directory FROM session_v2 WHERE id=?", (identifier,)
            ).fetchone()
            running = db.execute(
                "WITH RECURSIVE children(id) AS (SELECT id FROM session_v2 WHERE id=? UNION ALL SELECT s.id FROM session_v2 s JOIN children c ON s.parent_id=c.id) SELECT 1 FROM session_v2 WHERE id IN (SELECT id FROM children) AND time_suspended IS NOT NULL LIMIT 1",
                (identifier,),
            ).fetchone()
        if running:
            raise ValueError("history_native_delete_busy")
        if row is None:
            return
        if row[0] != target["cwd"]:
            raise ValueError("history_delete_identity_mismatch")
        result = subprocess.run(
            ["opencode2", "session", "delete", "--standalone", identifier],
            env=layout.environment(),
            cwd=target["cwd"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
        if result.returncode or any(
            x.native_id == identifier for x in read_opencode(layout)
        ):
            raise ValueError("history_native_delete_incomplete")
        return
    if agent != "claude":
        raise ValueError("unsupported_agent")
    root = layout.claude / "projects"
    paths = list(root.glob("*/" + identifier + ".jsonl"))
    for path in paths:
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("history_delete_identity_mismatch")
        snapshot = read_claude(path)
        if (
            snapshot is None
            or snapshot.native_id != identifier
            or snapshot.cwd != target["cwd"]
        ):
            raise ValueError("history_delete_identity_mismatch")
    # Claude has no supported delete RPC in the pinned version. Only this
    # explicit, confirmed catalog operation removes its verified transcript.
    for path in paths:
        sidecars = path.with_suffix("")
        if sidecars.is_symlink():
            raise ValueError("history_delete_identity_mismatch")
        if sidecars.exists():
            shutil.rmtree(sidecars)
        path.unlink()
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
