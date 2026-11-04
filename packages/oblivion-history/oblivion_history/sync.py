from contextlib import contextmanager
import fcntl
import re
import sqlite3
import subprocess
from pathlib import Path

from .catalog import Catalog
from .claude import read_claude, write_claude
from .codex import read_codex, write_codex
from .model import VERSIONS
from .layout import Layout
from .opencode import read_opencode, write_opencode
from .projection import project
from .deletion import reconcile_deletions


def allowed_cwd(value, workspace):
    """Lexical Safe roots only; this never discovers or follows a filesystem."""
    if not isinstance(value, str) or len(value.encode()) > 4096 or "\\" in value or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value):
        return False
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        return False
    workspace = Path(workspace)
    return any(path == root or path.is_relative_to(root) for root in (workspace, workspace.parent / "imports"))


@contextmanager
def active_agent(state, agent):
    """Hold around a native process. Writers skip profiles with active clients.

    This lease is deliberately process-held rather than a persistent PID marker.
    Native /resume happens inside a running client, so the profile remains fenced
    until that process exits. A future chat-specific admission hook can narrow it.
    """
    if agent not in VERSIONS:
        raise ValueError("unsupported_agent")
    root = Path(state)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(root / (agent + ".active"), "a+b") as lease:
        fcntl.flock(lease, fcntl.LOCK_SH)
        yield


def sync(home, workspace, state, *, layout=None):
    layout = layout or Layout.resolve(home)
    workspace = str(Path(workspace).resolve())
    catalog = Catalog(state)
    report = {"ingested": 0, "projected": 0, "busy": [], "errors": [], "retained": []}
    try:
        with catalog.exclusive():
            report["errors"].extend(reconcile_deletions(catalog, layout))
            sources = []
            pending = catalog.pending()
            for agent, root, pattern, reader in (
                ("codex", layout.codex / "sessions", "**/rollout-*.jsonl", read_codex),
                ("claude", layout.claude / "projects", "**/*.jsonl", read_claude),
            ):
                if agent in pending:
                    continue
                if not root.exists():
                    continue
                for path in root.glob(pattern):
                    if path.is_symlink() or "subagents" in path.parts:
                        continue
                    try:
                        snapshot = reader(path)
                        if snapshot and allowed_cwd(snapshot.cwd, workspace):
                            sources.append(snapshot)
                    except (
                        ValueError,
                        KeyError,
                        OSError,
                        sqlite3.Error,
                        subprocess.SubprocessError,
                    ) as error:
                        report["errors"].append(
                            {
                                "agent": agent,
                                "error": error_code(error, "native_read_failed"),
                            }
                        )
            try:
                if "opencode2" not in pending:
                    sources.extend(
                        x for x in read_opencode(layout) if allowed_cwd(x.cwd, workspace)
                    )
            except (
                ValueError,
                KeyError,
                OSError,
                sqlite3.Error,
                subprocess.SubprocessError,
            ) as error:
                report["errors"].append(
                    {
                        "agent": "opencode2",
                        "error": error_code(error, "native_read_failed"),
                    }
                )
            for snapshot in sorted(sources, key=lambda x: x.updated):
                chat_id, changed = catalog.ingest(snapshot)
                report["ingested"] += int(changed)
                if chat_id is None:
                    continue
                if catalog.source_current(snapshot, chat_id):
                    catalog.mark_projection(snapshot.agent, snapshot.native_id, chat_id)
            invalid = {error["agent"] for error in report["errors"]}
            for agent, writer in (
                ("codex", write_codex),
                ("claude", write_claude),
                ("opencode2", write_opencode),
            ):
                if agent in invalid:
                    continue
                with open(Path(state) / (agent + ".active"), "a+b") as lease:
                    try:
                        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        report["busy"].append(agent)
                        continue
                    for chat, items in catalog.chats():
                        identifier = catalog.native_id(chat["id"], agent)
                        if agent not in pending and catalog.projection_current(
                            agent, identifier, chat["id"]
                        ):
                            continue
                        try:
                            portable, _ = project(items, agent)
                            path, digest, mapping = writer(
                                layout,
                                chat,
                                portable,
                                identifier,
                                lambda mapping, source: catalog.prepare_projection(
                                    agent, identifier, chat["id"], mapping, source
                                ),
                                catalog.bindings(agent, identifier),
                            )
                            catalog.exported(
                                chat["id"], agent, identifier, path, digest, mapping
                            )
                            report["projected"] += 1
                        except (
                            ValueError,
                            KeyError,
                            OSError,
                            sqlite3.Error,
                            subprocess.SubprocessError,
                        ) as error:
                            report["errors"].append(
                                {
                                    "agent": agent,
                                    "error": error_code(error, "native_write_failed"),
                                }
                            )
            for chat, items in catalog.chats():
                for agent in VERSIONS:
                    report["retained"].extend(catalog.retention(chat["id"], agent))
                    _, omitted = project(items, agent)
                    report["retained"].extend(
                        {
                            "chat_id": chat["id"],
                            "target": agent,
                            "kind": kind,
                            "count": count,
                            "storage": "encrypted_archive",
                            "projection": "omitted_from_portable_projection",
                        }
                        for kind, count in omitted.items()
                    )
        return report
    finally:
        catalog.close()


def error_code(error, fallback):
    if isinstance(error, ValueError) and re.fullmatch("[a-z_]{1,80}", str(error)):
        return str(error)
    return fallback
