"""Positive native Claude transcript dependencies, without profile configuration."""

import json
import os
from pathlib import Path
import re
import stat

MAX_ARTIFACTS = 4096
MAX_LINE = 16 * 1024 * 1024
MAX_RECORDS = 100000
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,254}")
SIDECAR = re.compile(r"agent-[A-Za-z0-9_-]{1,128}\.(?:jsonl|meta\.json)")


def collect(vault, transcript_path, rows):
    vault = Path(vault)
    transcript_path = Path(transcript_path)
    project = transcript_path.parent
    if project.parent != vault / "home/.claude/projects":
        raise ValueError("unsupported_claude_transcript_path")
    session = transcript_path.stem
    if not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", session):
        raise ValueError("invalid_claude_session_identity")
    first = next((row for row in rows if row.get("type") in ("user", "assistant") and not row.get("isSidechain")), None)
    if first is None or not isinstance(first.get("cwd"), str):
        raise ValueError("unsupported_claude_workspace")
    cwd = Path(first["cwd"])
    required = set()
    artifacts = set()

    def scope(path):
        candidate = Path(os.path.abspath(path if path.is_absolute() else cwd / path))
        for base in (Path("/vault"), vault):
            for root in ("workspace", "imports"):
                try:
                    relative = candidate.relative_to(base / root)
                except ValueError:
                    continue
                if not relative.parts:
                    break
                return root + "/" + relative.as_posix(), vault / root / relative
        raise ValueError("unsupported_claude_external_file")

    def regular(path):
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError("claude_dependency_symlink")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("unsupported_claude_dependency")
        return path

    def artifact(path):
        regular(path)
        artifacts.add(path)
        if len(artifacts) > MAX_ARTIFACTS:
            raise ValueError("claude_dependency_limit")

    def attachment(source):
        kind = source.get("type")
        if kind in ("base64", "text"):
            return
        if kind == "file" and isinstance(source.get("path"), str):
            selected, path = scope(Path(source["path"]))
            regular(path)
            required.add(selected)
            return
        raise ValueError("unsupported_claude_external_attachment")

    def content(value):
        if isinstance(value, list):
            for item in value:
                content(item)
            return
        if not isinstance(value, dict):
            return
        if value.get("type") in ("image", "document"):
            source = value.get("source")
            if not isinstance(source, dict):
                raise ValueError("unsupported_claude_external_attachment")
            attachment(source)
        if value.get("type") == "tool_result":
            content(value.get("content"))

    def dependencies(row):
        message = row.get("message")
        if isinstance(message, dict):
            content(message.get("content"))
        if row.get("type") != "file-history-snapshot":
            return
        snapshot = row.get("snapshot")
        backups = snapshot.get("trackedFileBackups") if isinstance(snapshot, dict) else None
        if not isinstance(backups, dict):
            raise ValueError("unsupported_claude_file_history")
        for original, record in backups.items():
            if not isinstance(original, str) or not isinstance(record, dict):
                raise ValueError("unsupported_claude_file_history")
            # Backups of provider/profile configuration are never portable.
            scope(Path(original))
            name = record.get("backupFileName")
            if name is None:
                continue
            if not isinstance(name, str) or not NAME.fullmatch(name) or name in (".", ".."):
                raise ValueError("unsupported_claude_file_history")
            artifact(vault / "home/.claude/file-history" / session / name)

    for row in rows:
        dependencies(row)

    native = project / session
    if native.is_symlink():
        raise ValueError("claude_dependency_symlink")
    for name in ("subagents", "tool-results"):
        directory = native / name
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("unsupported_claude_dependency")
        for path in directory.iterdir():
            if name == "subagents" and not SIDECAR.fullmatch(path.name):
                raise ValueError("unsupported_claude_subagent_artifact")
            if name == "tool-results" and (not NAME.fullmatch(path.name) or path.name in (".", "..")):
                raise ValueError("unsupported_claude_tool_result")
            artifact(path)
            if name == "subagents" and path.suffix == ".jsonl":
                with path.open("rb") as source:
                    count = 0
                    while True:
                        line = source.readline(MAX_LINE + 1)
                        if not line:
                            break
                        count += 1
                        if len(line) > MAX_LINE or count > MAX_RECORDS or not line.endswith(b"\n"):
                            raise ValueError("claude_dependency_limit")
                        value = json.loads(line)
                        if not isinstance(value, dict):
                            raise ValueError("unsupported_claude_subagent_artifact")
                        dependencies(value)

    return {"artifacts": sorted(artifacts), "required_paths": sorted(required)}
