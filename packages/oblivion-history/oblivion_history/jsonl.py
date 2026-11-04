import json
from pathlib import Path

from .catalog import fingerprint


def records(path):
    raw = Path(path).read_bytes()
    data = raw
    if data and not data.endswith(b"\n"):
        # Writers append. An incomplete final record is retried on the next scan.
        data = data[: data.rfind(b"\n") + 1]
    return (
        [json.loads(line) for line in data.splitlines() if line.strip()],
        fingerprint(raw),
        raw,
    )
