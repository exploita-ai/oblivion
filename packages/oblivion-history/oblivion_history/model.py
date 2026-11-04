from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import uuid

VERSIONS = {"codex": "0.159.2", "claude": "2.1.302", "opencode2": "2.0.1"}


def millis(value):
    if isinstance(value, (int, float)):
        return int(value if value > 100000000000 else value * 1000)
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


def iso(value):
    return (
        datetime.fromtimestamp(value / 1000, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def stable(chat, key):
    return str(uuid.uuid5(uuid.UUID(chat), key))


@dataclass
class Item:
    native_id: str
    kind: str
    role: str
    body: dict
    created: int
    id: str = ""


@dataclass
class Fact:
    native_id: str
    kind: str
    body: dict
    created: int


@dataclass
class Snapshot:
    agent: str
    native_id: str
    cwd: str
    title: str
    created: int
    updated: int
    items: list[Item]
    raw: list[dict] = field(default_factory=list)
    fingerprint: str = ""
    path: str = ""
    facts: list[Fact] = field(default_factory=list)
    raw_bytes: bytes = b""
    interrupted: bool = False
