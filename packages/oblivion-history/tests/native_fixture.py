import json
from pathlib import Path
import sqlite3
import uuid

from oblivion_history.portable import VERSIONS, encode, reference


def vault(root):
    root = Path(root).resolve()
    for name in ("home", "state", "workspace", "imports"):
        (root / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def codex(root, *, text="Synthetic native conversation", identity=None):
    identity = identity or str(uuid.uuid4())
    directory = root / "home/.codex/sessions/2026/11/04"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    rows = [
        {"type": "session_meta", "timestamp": "2026-11-04T12:00:00Z", "payload": {"id": identity, "cwd": "/vault/workspace/project", "timestamp": "2026-11-04T12:00:00Z", "history_mode": "paginated", "cli_version": VERSIONS["codex"], "base_instructions": {"text": "Original native instructions"}}},
        {"type": "event_msg", "timestamp": "2026-11-04T12:01:00Z", "payload": {"type": "user_message", "message": text}},
        {"type": "response_item", "timestamp": "2026-11-04T12:01:01Z", "payload": {"type": "reasoning", "encrypted_content": "native-provider-signature"}},
        {"type": "response_item", "timestamp": "2026-11-04T12:01:02Z", "payload": {"type": "function_call", "name": "exec_command", "arguments": "{\"cmd\":\"printf hi\"}", "call_id": "original-tool-id"}},
        {"type": "response_item", "timestamp": "2026-11-04T12:01:03Z", "payload": {"type": "function_call_output", "output": "hi", "call_id": "original-tool-id"}},
    ]
    rows = [{"ordinal": index, **row} for index, row in enumerate(rows)]
    path = directory / ("rollout-2026-11-04T12-00-00-" + identity + ".jsonl")
    path.write_text("".join(encode(row) + "\n" for row in rows))
    return reference("codex", identity), path, rows


def claude(root, *, identity=None):
    identity = identity or str(uuid.uuid4())
    directory = root / "home/.claude/projects/-vault-workspace-project"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    rows = [
        {"type": "user", "uuid": str(uuid.uuid4()), "parentUuid": None, "sessionId": identity, "version": VERSIONS["claude"], "cwd": "/vault/workspace/project", "timestamp": "2026-11-04T12:00:00Z", "message": {"role": "user", "content": "Native Claude question"}},
        {"type": "assistant", "uuid": str(uuid.uuid4()), "parentUuid": "original-parent", "sessionId": identity, "version": VERSIONS["claude"], "cwd": "/vault/workspace/project", "message": {"role": "assistant", "content": [{"type": "thinking", "thinking": "native thinking", "signature": "original-signature"}, {"type": "tool_use", "id": "claude-tool", "name": "Bash", "input": {"command": "printf hi"}}], "stop_reason": "tool_use"}},
        {"type": "custom-title", "sessionId": identity, "customTitle": "Claude research"},
    ]
    path = directory / (identity + ".jsonl")
    path.write_text("".join(encode(row) + "\n" for row in rows))
    return reference("claude", identity), path, rows


def opencode(root):
    directory = root / "state/opencode"
    directory.mkdir(mode=0o700, parents=True)
    database = directory / "opencode.db"
    identity = "ses_nativeExample123"
    connection = sqlite3.connect(database)
    connection.executescript('''
CREATE TABLE session_v2(id TEXT PRIMARY KEY,version TEXT,directory TEXT,title TEXT,cost REAL,tokens_input INTEGER,tokens_output INTEGER,tokens_reasoning INTEGER,tokens_cache_read INTEGER,tokens_cache_write INTEGER,time_created INTEGER,time_updated INTEGER,parent_id TEXT,agent TEXT,idle_outcome TEXT,model TEXT,fork_session_id TEXT,fork_boundary TEXT);
CREATE TABLE session_message(id TEXT PRIMARY KEY,session_id TEXT,type TEXT,seq INTEGER,data TEXT);
CREATE TABLE auth(token TEXT);
''')
    connection.execute("INSERT INTO auth VALUES(?)", ("PROFILE-CREDENTIAL-CANARY",))
    connection.execute("INSERT INTO session_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (identity, VERSIONS["opencode2"], str(root / "workspace/project"), "Native OpenCode chat", 0, 1, 2, 3, 0, 0, 1, 2, None, "build", "succeeded", json.dumps({"id": "model", "providerID": "provider"}), None, None))
    message = {"time": {"created": 1}, "text": "Native OpenCode question"}
    connection.execute("INSERT INTO session_message VALUES(?,?,?,?,?)", ("msg_nativeExample123", identity, "user", 1, encode(message)))
    connection.commit(); connection.close()
    return reference("opencode2", identity), database


def codex_index(root, logical, physical):
    """A current native metadata row; no source runtime configuration is portable."""
    from oblivion_history.codex_index import restore

    relative = physical.relative_to(root / "home/.codex").as_posix()
    thread = {
        "id": logical, "rollout_path": relative, "created_at": 1793793600, "updated_at": 1793793660,
        "created_at_ms": 1793793600000, "updated_at_ms": 1793793660000,
        "recency_at": 1793793660, "recency_at_ms": 1793793660000,
        "source": "cli", "model_provider": "openai", "cwd": "/vault/workspace/project",
        "title": "Authoritative native title", "cli_version": VERSIONS["codex"],
        "history_mode": "paginated", "name": None, "preview": "Native question", "first_user_message": "Native question",
        "tokens_used": 0, "archived": 0, "archived_at": None, "originator": None,
        "thread_source": None, "agent_nickname": None, "agent_role": None, "agent_path": None,
    }
    restore(root, [{"type": "codex-index", "version": 1, "thread": thread, "attachments": []}])
