"""Pinned Codex logical threads and immutable physical rollout prefixes."""

import json
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from .artifacts import file_records, files


def parsed(data):
    from .portable import CODEX_TYPES, MAX_LINE, MAX_RECORDS, VERSIONS, identifier, scope

    if not data or not data.endswith(b"\n"):
        raise ValueError("native_history_incomplete_or_limit")
    positions = []
    meta = None
    offset = 0
    stream = io.BytesIO(data)
    for index, line in enumerate(stream):
        if index >= MAX_RECORDS or len(line) > MAX_LINE:
            raise ValueError("native_history_limit")
        row = json.loads(line)
        if not isinstance(row, dict) or row.get("type") not in CODEX_TYPES:
            raise ValueError("unsupported_codex_record")
        if index == 0:
            meta = row.get("payload")
            if row.get("type") != "session_meta" or not isinstance(meta, dict):
                raise ValueError("invalid_codex_rollout")
        offset += len(line)
        positions.append((row.get("ordinal"), offset))
    if meta.get("cli_version") != VERSIONS["codex"] or meta.get("history_mode", "legacy") not in ("legacy", "paginated"):
        raise ValueError("unsupported_codex_format")
    identifier(meta.get("id"))
    # Safe profiles always use the same /vault roots, so raw byte offsets need no rewrite.
    scope(meta.get("cwd"), "/vault")
    base = meta.get("history_base")
    if base is not None:
        if not isinstance(base, dict) or set(base) != {"thread_id", "end_ordinal_exclusive", "end_byte_offset"} or any(type(base[key]) is not int or not 0 <= base[key] <= 2**64 - 1 for key in ("end_ordinal_exclusive", "end_byte_offset")):
            raise ValueError("invalid_codex_history_base")
        identifier(base["thread_id"])
    return positions, meta


def physical_id(path):
    from .portable import identifier

    if not re.fullmatch(r"(?:sessions|archived_sessions)/(?:[^/]+/){0,6}rollout-[^/]+\.jsonl", path):
        raise ValueError("invalid_codex_artifact_path")
    return identifier(Path(path).stem[-36:])


def validate(artifacts, logical_id):
    available = {}
    for path, artifact in artifacts.items():
        physical = physical_id(path)
        rows, meta = parsed(artifact["data"])
        if physical in available:
            raise ValueError("duplicate_codex_rollout")
        available[physical] = (artifact, rows, meta)
    if not any(meta["id"] == logical_id for _, _, meta in available.values()):
        raise ValueError("invalid_codex_rollout")
    for artifact, rows, meta in available.values():
        base = meta.get("history_base")
        if base is None:
            continue
        if base["thread_id"] not in available:
            raise ValueError("codex_history_dependency_missing")
        inherited, inherited_rows, _ = available[base["thread_id"]]
        offset = base["end_byte_offset"]
        if offset > len(inherited["data"]) or offset and inherited["data"][offset - 1:offset] != b"\n":
            raise ValueError("invalid_codex_history_position")
        ordinals = [ordinal for ordinal, end in inherited_rows if end <= offset and type(ordinal) is int]
        if any(ordinal >= base["end_ordinal_exclusive"] for ordinal in ordinals):
            raise ValueError("invalid_codex_history_position")
        if not ordinals or max(ordinals) + 1 != base["end_ordinal_exclusive"]:
            raise ValueError("invalid_codex_history_position")
    remaining = {key: (value[2].get("history_base") or {}).get("thread_id") for key, value in available.items()}
    while remaining:
        ready = [key for key, parent in remaining.items() if parent not in remaining]
        if not ready:
            raise ValueError("codex_history_dependency_cycle")
        for key in ready:
            remaining.pop(key)
    return available


def source_bytes(path):
    from .portable import MAX_BYTES, open_file

    with open_file(path) as source:
        mtime = os.fstat(source.fileno()).st_mtime_ns
        if not str(path).endswith(".zst"):
            return source.read(MAX_BYTES + 1), mtime
        binary = "/usr/bin/zstd" if sys.platform == "linux" else shutil.which("zstd")
        if binary is None:
            raise ValueError("native_decompressor_missing")
        process = subprocess.Popen([binary, "--decompress", "--stdout", "--quiet"], stdin=source,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            data = process.stdout.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                process.kill()
                raise ValueError("native_history_limit")
            if process.wait(timeout=60) != 0:
                raise ValueError("invalid_codex_compression")
            return data, mtime
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
            process.wait()


def collect(vault, titles):
    from . import portable
    from . import codex_index

    vault = Path(vault)
    physical = {}
    groups = {}
    total = 0
    for name in ("sessions", "archived_sessions"):
        for path in portable.files(vault / "home/.codex" / name, r"rollout-[^/]+\.jsonl(?:\.zst)?"):
            relative = path.relative_to(vault / "home/.codex").as_posix().removesuffix(".zst")
            identity = physical_id(relative)
            if identity in physical:
                # The native reader prefers a materialized plain file to its cold copy.
                if str(path).endswith(".zst") and physical[identity]["path"] == relative:
                    continue
                raise ValueError("duplicate_codex_rollout")
            data, mtime = source_bytes(path)
            total += len(data)
            if total > portable.MAX_BYTES:
                raise ValueError("native_history_limit")
            rows, meta = parsed(data)
            physical[identity] = {"path": relative, "data": data, "mtime_ns": mtime, "meta": meta}
            groups.setdefault(meta["id"], []).append(identity)
    index = codex_index.read(vault)
    if set(index) - set(groups):
        raise ValueError("codex_selected_rollout_missing")
    for identity, generations in groups.items():
        if identity in index:
            active = next((key for key in generations if physical[key]["path"] == index[identity]["rollout_path"]), None)
            if active is None:
                raise ValueError("codex_selected_rollout_missing")
            roots = [active]
        else:
            if len(generations) != 1:
                raise ValueError("codex_selected_rollout_index_missing")
            roots = generations
        wanted = {key: len(physical[key]["data"]) for key in roots}
        queue = list(roots)
        visited = set()
        while queue:
            current = queue.pop()
            if current in visited:
                continue
            visited.add(current)
            base = physical[current]["meta"].get("history_base")
            if base is None:
                continue
            dependency = base["thread_id"]
            if dependency not in physical:
                raise ValueError("codex_history_dependency_missing")
            wanted[dependency] = max(wanted.get(dependency, 0), base["end_byte_offset"])
            queue.append(dependency)
        payload = []
        for key, size in sorted(wanted.items()):
            entry = physical[key]
            if size > len(entry["data"]):
                raise ValueError("invalid_codex_history_position")
            payload.extend(file_records(entry["path"], entry["data"][:size], entry["mtime_ns"]))
        validate(files(payload), identity)
        payload = [*codex_index.collect(vault, [identity]), *payload]
        current = physical[roots[0]]
        meta = current["meta"]
        title = index.get(identity, {}).get("title") or titles.get(identity, "")
        entry = portable.chat("codex", identity, meta["cwd"], title, payload, "/vault")
        dependencies = set(wanted) - set(roots)
        if dependencies:
            entry["required_prefixes"] = len(dependencies)
            # history_base points to physical files; exclusion uses their
            # logical conversation IDs, which survive native reverts.
            entry["required_chat_ids"] = sorted({
                portable.reference("codex", physical[key]["meta"]["id"])
                for key in dependencies if physical[key]["meta"]["id"] != identity
            })
        yield entry
