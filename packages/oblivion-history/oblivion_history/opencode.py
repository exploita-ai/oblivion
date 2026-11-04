import json
import os
import sqlite3
import subprocess
import tempfile

from .catalog import fingerprint
from .model import Fact, Item, Snapshot, VERSIONS, encode


def database(layout):
    return layout.data / "opencode/opencode.db"


def read_opencode(layout):
    path = database(layout)
    if not path.exists():
        return []
    db = sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    snapshots = []
    try:
        for chat in db.execute(
            "SELECT * FROM session_v2 WHERE parent_id IS NULL AND time_archived IS NULL"
        ):
            if chat["version"] != VERSIONS["opencode2"]:
                raise ValueError("unsupported_opencode_format")
            rows = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM session_message WHERE session_id=? ORDER BY seq",
                    (chat["id"],),
                )
            ]
            items = []
            facts = []
            raw = []
            for row in rows:
                data = json.loads(row["data"])
                record = {"id": row["id"], "type": row["type"], **data}
                raw.append(record)
                kind = row["type"]
                created = row["time_created"]
                if kind == "user":
                    if data["text"] or not data.get("files"):
                        items.append(
                            Item(
                                row["id"] + ":text",
                                "text",
                                "user",
                                {"text": data["text"]},
                                created,
                            )
                        )
                    for index, attachment in enumerate(data.get("files", [])):
                        if attachment["mime"].startswith("image/"):
                            items.append(
                                Item(
                                    row["id"] + ":image:" + str(index),
                                    "image",
                                    "user",
                                    {
                                        "url": "data:"
                                        + attachment["mime"]
                                        + ";base64,"
                                        + attachment["data"]
                                    },
                                    created,
                                )
                            )
                        else:
                            items.append(
                                Item(
                                    row["id"] + ":file:" + str(index),
                                    "file",
                                    "user",
                                    {
                                        "mime": attachment["mime"],
                                        "data": attachment["data"],
                                        "name": attachment.get("name"),
                                    },
                                    created,
                                )
                            )
                elif kind == "assistant":
                    if "completed" not in data["time"]:
                        facts.append(
                            Fact(
                                row["id"],
                                "partial_assistant",
                                {"record": record},
                                created,
                            )
                        )
                        continue
                    for index, content in enumerate(data["content"]):
                        key = row["id"] + ":" + str(index)
                        if content["type"] == "text":
                            items.append(
                                Item(
                                    key,
                                    "text",
                                    "assistant",
                                    {"text": content["text"]},
                                    created,
                                )
                            )
                        elif content["type"] == "reasoning":
                            facts.append(
                                Fact(
                                    key,
                                    "provider_reasoning",
                                    {"record": record, "block": content},
                                    created,
                                )
                            )
                        elif content["type"] == "tool":
                            state = content["state"]
                            if state["status"] not in ("completed", "error"):
                                facts.append(
                                    Fact(
                                        key,
                                        "unsettled_tool",
                                        {"record": record, "block": content},
                                        created,
                                    )
                                )
                                continue
                            items.append(
                                Item(
                                    key + ":call",
                                    "tool_call",
                                    "assistant",
                                    {
                                        "id": content["id"],
                                        "name": content["name"],
                                        "input": state["input"],
                                    },
                                    created,
                                )
                            )
                            output = state.get("content") or [
                                {"type": "text", "text": encode(state.get("error", {}))}
                            ]
                            items.append(
                                Item(
                                    key + ":result",
                                    "tool_result",
                                    "user",
                                    {
                                        "id": content["id"],
                                        "content": output,
                                        "is_error": state["status"] == "error",
                                    },
                                    created,
                                )
                            )
                        else:
                            facts.append(
                                Fact(
                                    key,
                                    "native_content",
                                    {"record": record, "block": content},
                                    created,
                                )
                            )
                else:
                    facts.append(
                        Fact(
                            row["id"],
                            "compaction" if kind == "compaction" else "native_message",
                            {"record": record},
                            created,
                        )
                    )
            from .projection import settle

            items = settle(items, facts)
            data = (
                encode({"session": dict(chat)})
                + "\n"
                + "\n".join(encode(row) for row in rows)
                + "\n"
            ).encode()
            snapshots.append(
                Snapshot(
                    "opencode2",
                    chat["id"],
                    chat["directory"],
                    chat["title"] or "Untitled chat",
                    chat["time_created"],
                    chat["time_updated"],
                    items,
                    raw,
                    fingerprint(data),
                    str(path),
                    facts=facts,
                    raw_bytes=data,
                )
            )
    finally:
        db.close()
    return snapshots


def render(chat, items):
    messages = []
    mapping = {}
    results = {x.body["id"]: x for x in items if x.kind == "tool_result"}
    calls = {x.body["id"] for x in items if x.kind == "tool_call"}
    for item in items:
        identifier = "msg_" + item.id.replace("-", "")
        message = {
            "id": identifier,
            "type": item.role,
            "time": {"created": item.created},
        }
        if item.kind == "text" and item.role == "user":
            message["text"] = item.body["text"]
            mapping[identifier + ":text"] = item.id
        elif item.kind == "file":
            message.update(
                type="user",
                text="",
                files=[
                    {
                        "data": item.body["data"],
                        "mime": item.body["mime"],
                        "source": {"type": "inline"},
                        **(
                            {"name": item.body["name"]} if item.body.get("name") else {}
                        ),
                    }
                ],
            )
            mapping[identifier + ":file:0"] = item.id
        elif item.kind == "image":
            url = item.body["url"]
            if not url.startswith("data:"):
                raise ValueError("external_image_not_supported")
            mime, data = url[5:].split(";base64,", 1)
            message.update(
                type="user",
                text="",
                files=[{"data": data, "mime": mime, "source": {"type": "inline"}}],
            )
            mapping[identifier + ":image:0"] = item.id
        elif item.kind in ("text", "reasoning"):
            message.update(
                type="assistant",
                agent="build",
                model={"providerID": "oblivion-history", "id": "imported"},
                content=[{"type": item.kind, "text": item.body["text"]}],
            )
            message["time"]["completed"] = item.created
            mapping[identifier + ":0"] = item.id
        elif item.kind == "tool_call":
            result = results.get(item.body["id"])
            if result is None:
                raise ValueError("unsettled_tool_call")
            content = result.body["content"]
            if isinstance(content, str):
                content = [{"type": "text", "text": content}]
            if not content:
                content = [{"type": "text", "text": ""}]
            if any(x.get("type") != "text" for x in content):
                raise ValueError("non_text_tool_result_not_supported")
            state = {
                "status": "completed",
                "input": item.body["input"],
                "content": content,
            }
            if result.body["is_error"]:
                state.update(
                    status="error",
                    error={
                        "type": "ImportedToolError",
                        "message": "Historical tool invocation failed",
                    },
                )
            message.update(
                type="assistant",
                agent="build",
                model={"providerID": "oblivion-history", "id": "imported"},
                content=[
                    {
                        "type": "tool",
                        "id": item.body["id"],
                        "name": item.body["name"],
                        "state": state,
                        "time": {"created": item.created, "completed": result.created},
                    }
                ],
            )
            message["time"]["completed"] = result.created
            mapping[identifier + ":0:call"] = item.id
            mapping[identifier + ":0:result"] = result.id
        elif item.kind == "tool_result":
            if item.body["id"] not in calls:
                raise ValueError("unmatched_tool_result")
            continue
        else:
            raise ValueError("unsupported_history_item")
        messages.append(message)
    return messages, mapping


def write_opencode(layout, chat, items, native_id, prepare, bindings):
    from .projection import prefix

    path = database(layout)
    previous = next(
        (x for x in read_opencode(layout) if x.native_id == native_id), None
    )
    count, prefix_mapping, keep = prefix(previous, items, bindings)
    exists = previous is not None
    if exists:
        with sqlite3.connect(path, timeout=10) as db:
            active = db.execute(
                "SELECT time_suspended FROM session_v2 WHERE id=?", (native_id,)
            ).fetchone()
            if active is None or active[0] is not None:
                raise ValueError("opencode_session_active")
    messages, mapping = render(chat, items[count:] if keep else items)
    mapping = {**prefix_mapping, **mapping}
    prepare(mapping, previous)
    if not exists:
        # Let the pinned official client resolve the project and initialize its
        # current schema. Never synthesize a parallel database schema here.
        data = {
            "info": {
                "id": native_id,
                "projectID": "global",
                "cost": 0,
                "tokens": {
                    "input": 0,
                    "output": 0,
                    "reasoning": 0,
                    "cache": {"read": 0, "write": 0},
                },
                "time": {"created": chat["created"], "updated": chat["updated"]},
                "title": chat["title"],
                "location": {"directory": chat["cwd"]},
            },
            "messages": messages,
        }
        environment = layout.environment()
        # This temporary export contains the conversation and must remain on the
        # caller's Safe volume. The guest installs the package there as well.
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".oblivion-import-", suffix=".json"
        ) as transfer:
            transfer.write(encode(data).encode())
            transfer.flush()
            os.fsync(transfer.fileno())
            process = subprocess.run(
                ["opencode2", "session", "import", "--standalone", transfer.name],
                cwd=chat["cwd"],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
            if process.returncode != 0:
                raise ValueError("opencode_native_import_failed")
    else:
        with sqlite3.connect(path, timeout=10) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            active = db.execute(
                "SELECT time_suspended FROM session_v2 WHERE id=?", (native_id,)
            ).fetchone()
            if active is None or active[0] is not None:
                raise ValueError("opencode_session_active")
            # Mirror the official import's message projection and sequence
            # reservation, retaining the existing native session and project.
            if not keep:
                db.execute(
                    "DELETE FROM session_message WHERE session_id=?", (native_id,)
                )
            sequence = db.execute(
                "SELECT coalesce(seq,0) FROM event_sequence WHERE aggregate_id=?",
                (native_id,),
            ).fetchone()
            sequence = sequence[0] if sequence else 0
            for index, message in enumerate(messages):
                value = {k: v for k, v in message.items() if k not in ("id", "type")}
                db.execute(
                    "INSERT INTO session_message(id,session_id,type,seq,time_created,time_updated,data) VALUES(?,?,?,?,?,?,?)",
                    (
                        message["id"],
                        native_id,
                        message["type"],
                        sequence + index + 1,
                        message["time"]["created"],
                        chat["updated"],
                        encode(value),
                    ),
                )
            db.execute(
                "UPDATE event_sequence SET seq=? WHERE aggregate_id=?",
                (sequence + len(messages), native_id),
            )
            db.execute(
                "UPDATE session_v2 SET title=?,time_updated=? WHERE id=?",
                (chat["title"], chat["updated"], native_id),
            )
    snapshot = next(x for x in read_opencode(layout) if x.native_id == native_id)
    return path, snapshot, mapping
