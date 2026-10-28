#!/usr/bin/env python3
"""Synthetic native chat fixtures, installed only in the backup laboratory."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

os.umask(0o077)
assert os.getuid() == 1000 and not Path("/run/oblivion-api/token").exists()
spec = importlib.util.spec_from_file_location("chat", "/usr/lib/oblivion/guest/chat-database.py")
chat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chat)
vault = Path("/vault")
data = vault / "state/opencode"
data.mkdir(mode=0o700, parents=True, exist_ok=True)
fixture = vault / "state/backup-probe"
fixture.mkdir(mode=0o700, exist_ok=True)

if sys.argv[1] in ("future", "corrupt-db"):
    metadata = vault / "state/oblivion"
    metadata.mkdir(mode=0o700, exist_ok=True)
    (metadata / "session.json").write_text(json.dumps({"format": "oblivion-session",
        "version": 2 if sys.argv[1] == "future" else 1,
        "original_id": "f" * 32, "title": "Fault source"}))
    if sys.argv[1] == "corrupt-db":
        (data / "oblivion.db").write_bytes(b"SQLite format 3\x00" + bytes(496))
    sys.exit(0)

assert sys.argv[1] in ("seed", "verify")
workspace = vault / "workspace/shared.txt"
with tempfile.TemporaryDirectory(prefix=".backup-probe-", dir=data) as directory:
    with chat.server("/usr/bin/oblivion", data / "oblivion.db", Path(directory)) as call:
        if sys.argv[1] == "seed":
            workspace.write_text("OBLIVION_BACKUP_SHARED_DOCUMENT_79bd")
            template = call("/api/session", {"title": "Backup template", "location": {"directory": str(vault / "workspace")}})
            for index in range(2):
                identifier = "ses_backup_fixture_" + str(index)
                user = {"id": "msg_backup_user_" + str(index), "type": "user",
                    "text": "OBLIVION_BACKUP_MESSAGE_a081 · città è à € " + str(index),
                    "time": {"created": 1700000000000}, "files": [], "agents": [], "skills": []}
                assistant = {"id": "msg_backup_assistant_" + str(index), "type": "assistant", "agent": "default",
                    "model": {"id": "fixture", "providerID": "fixture"},
                    "time": {"created": 1700000000001, "completed": 1700000000002},
                    "content": [{"type": "text", "text": "Settled saved response " + str(index)}]}
                call("/api/experimental/session/import", {"info": {**template, "id": identifier, "title": "Saved chat " + str(index)},
                    "messages": [user, assistant], "location": template["location"]})
                call("/api/session/" + identifier + "/prompt", {"text": "OBLIVION_BACKUP_PENDING_3da2 " + str(index), "resume": False})
            ids = sorted(entry["id"] for entry in call("/api/session?parentID=null&limit=100"))
            expected = {"ids": ids,
                "transcripts": {identifier: call("/api/experimental/session/" + identifier + "/export") for identifier in ids},
                "inbox": {identifier: call("/api/session/" + identifier + "/inbox") for identifier in ids}}
            (fixture / "expected.json").write_text(json.dumps(expected, ensure_ascii=False))
        else:
            expected = json.loads((fixture / "expected.json").read_text())
            assert sorted(entry["id"] for entry in call("/api/session?parentID=null&limit=100")) == expected["ids"]
            assert {identifier: call("/api/experimental/session/" + identifier + "/export") for identifier in expected["ids"]} == expected["transcripts"]
            assert {identifier: call("/api/session/" + identifier + "/inbox") for identifier in expected["ids"]} == expected["inbox"]
            assert workspace.read_text() == "OBLIVION_BACKUP_SHARED_DOCUMENT_79bd"
