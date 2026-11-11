"""Bounded exact native file bytes inside the reviewed Share stream."""

import base64
import hashlib
import re

CHUNK = 1024 * 1024
LIMIT = 256 * 1024 * 1024


def file_records(path, data, mtime_ns):
    yield {"type": "native-file", "path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mtime_ns": mtime_ns}
    for offset in range(0, len(data), CHUNK):
        yield {"type": "native-chunk", "path": path, "offset": offset, "data": base64.b64encode(data[offset:offset + CHUNK]).decode("ascii")}


def chunk(record):
    if set(record) != {"type", "path", "offset", "data"} or record["type"] != "native-chunk" or type(record["offset"]) is not int or record["offset"] < 0 or not isinstance(record["data"], str) or len(record["data"]) > (CHUNK + 2) // 3 * 4:
        raise ValueError("invalid_native_artifact")
    data = base64.b64decode(record["data"], validate=True)
    if not data or len(data) > CHUNK:
        raise ValueError("invalid_native_artifact")
    return data


def file_path(value):
    if not isinstance(value, str) or not value or len(value.encode()) > 4096 or "\\" in value:
        raise ValueError("invalid_native_artifact_path")
    parts = value.split("/")
    if len(parts) > 32 or any(not part or part in (".", "..") or len(part.encode()) > 255 or any(ord(char) < 32 for char in part) for part in parts):
        raise ValueError("invalid_native_artifact_path")
    return value


def files(records):
    result = {}
    current = None
    total = 0
    for row in records:
        if row.get("type") == "native-file":
            if set(row) != {"type", "path", "bytes", "sha256", "mtime_ns"} or type(row["bytes"]) is not int or not 0 <= row["bytes"] <= LIMIT or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) or type(row["mtime_ns"]) is not int or not 0 <= row["mtime_ns"] <= 2**63 - 1:
                raise ValueError("invalid_native_artifact")
            name = file_path(row["path"])
            if name in result:
                raise ValueError("duplicate_native_artifact")
            current = {**row, "data": bytearray()}
            result[name] = current
            continue
        if current is None or row.get("path") != current["path"] or row.get("offset") != len(current["data"]):
            raise ValueError("invalid_native_artifact")
        data = chunk(row)
        current["data"].extend(data)
        total += len(data)
        if len(current["data"]) > current["bytes"] or total > LIMIT:
            raise ValueError("native_artifact_limit")
    for value in result.values():
        if len(value["data"]) != value["bytes"] or hashlib.sha256(value["data"]).hexdigest() != value["sha256"]:
            raise ValueError("invalid_native_artifact_hash")
        value["data"] = bytes(value["data"])
    return result
