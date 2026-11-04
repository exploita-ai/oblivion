"""Exact native Claude transcripts and their positive-scope file dependencies."""

import os
from pathlib import Path
import re

from .artifacts import file_records
from .claude_dependencies import collect


def parse(data):
    from .portable import CLAUDE_TYPES, MAX_LINE, MAX_RECORDS, VERSIONS, identifier, scope
    import json

    if not data or not data.endswith(b"\n"):
        raise ValueError("native_history_incomplete_or_limit")
    lines = data.splitlines(keepends=True)
    if len(lines) > MAX_RECORDS or any(len(line) > MAX_LINE for line in lines):
        raise ValueError("native_history_limit")
    rows = [json.loads(line) for line in lines]
    if any(not isinstance(row, dict) or row.get("type") not in CLAUDE_TYPES for row in rows):
        raise ValueError("unsupported_claude_format")
    first = next((row for row in rows if row.get("type") in ("user", "assistant") and not row.get("isSidechain")), None)
    if first is None or first.get("version") != VERSIONS["claude"]:
        raise ValueError("unsupported_claude_format")
    identifier(first.get("sessionId"))
    scope(first.get("cwd"), "/vault")
    return rows, first


def validate(artifacts, identity):
    main = []
    for path, artifact in artifacts.items():
        match = re.fullmatch(r"projects/([^/]+)/([a-f0-9-]{36})\.jsonl", path)
        if match and match[2] == identity:
            rows, first = parse(artifact["data"])
            if first["sessionId"] != identity or match[1] != re.sub(r"[^a-zA-Z0-9]", "-", first["cwd"]):
                raise ValueError("invalid_claude_identity")
            main.append((path, rows, first))
            continue
        if re.fullmatch(r"file-history/" + re.escape(identity) + r"/[A-Za-z0-9][A-Za-z0-9._@-]{0,254}", path):
            continue
        if re.fullmatch(r"projects/[^/]+/" + re.escape(identity) + r"/(?:subagents/agent-[A-Za-z0-9_-]{1,128}\.(?:jsonl|meta\.json)|tool-results/[A-Za-z0-9][A-Za-z0-9._@-]{0,254})", path):
            continue
        raise ValueError("invalid_claude_artifact_path")
    if len(main) != 1:
        raise ValueError("invalid_claude_identity")
    return main[0]


def snapshot(vault, path):
    from .portable import MAX_BYTES, chat, open_file

    with open_file(path) as source:
        data = source.read(MAX_BYTES + 1)
        mtime = os.fstat(source.fileno()).st_mtime_ns
    rows, first = parse(data)
    identity = first["sessionId"]
    if path.stem != identity:
        raise ValueError("invalid_claude_identity")
    dependencies = collect(vault, path, rows)
    payload = list(file_records(path.relative_to(Path(vault) / "home/.claude").as_posix(), data, mtime))
    total = len(data)
    for artifact in dependencies["artifacts"]:
        with open_file(artifact) as source:
            raw = source.read(MAX_BYTES + 1)
            mtime = os.fstat(source.fileno()).st_mtime_ns
        total += len(raw)
        if total > MAX_BYTES:
            raise ValueError("native_history_limit")
        payload.extend(file_records(artifact.relative_to(Path(vault) / "home/.claude").as_posix(), raw, mtime))
    title = next((row.get("customTitle", "") for row in reversed(rows) if row.get("type") == "custom-title"), "")
    entry = chat("claude", identity, first["cwd"], title, payload, "/vault")
    entry["required_paths"] = dependencies["required_paths"]
    return entry
