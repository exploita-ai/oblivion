import re

from .catalog import atomic_write
from .jsonl import records
from .model import Fact, Item, Snapshot, VERSIONS, encode, iso, millis


def read_claude(path):
    rows, digest, raw_bytes = records(path)
    messages = [
        x
        for x in rows
        if x.get("type") in ("user", "assistant")
        and "message" in x
        and not x.get("isSidechain")
    ]
    if not messages:
        return None
    first = messages[0]
    if first.get("version") != VERSIONS["claude"]:
        raise ValueError("unsupported_claude_format")
    items = []
    facts = []
    title = next(
        (x["customTitle"] for x in reversed(rows) if x.get("type") == "custom-title"),
        "",
    )
    for row in rows:
        if row.get("subtype") == "compact_boundary" or row.get("isCompactSummary"):
            facts.append(
                Fact(
                    row.get("uuid", str(len(facts))),
                    "compaction",
                    {"record": row},
                    millis(row.get("timestamp", first["timestamp"])),
                )
            )
    for row in messages:
        if row.get("isCompactSummary"):
            continue
        if row.get("type") == "assistant" and row["message"].get("stop_reason") is None:
            facts.append(
                Fact(
                    row["uuid"],
                    "partial_assistant",
                    {"record": row},
                    millis(row["timestamp"]),
                )
            )
            continue
        content = row["message"].get("content", [])
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        for index, block in enumerate(content):
            key = row["uuid"] + ":" + str(index)
            time = millis(row["timestamp"])
            kind = block["type"]
            if kind == "text":
                items.append(
                    Item(
                        key,
                        "text",
                        row["message"]["role"],
                        {"text": block["text"]},
                        time,
                    )
                )
            elif kind == "tool_use":
                items.append(
                    Item(
                        key,
                        "tool_call",
                        "assistant",
                        {
                            "id": block["id"],
                            "name": block["name"],
                            "input": block["input"],
                        },
                        time,
                    )
                )
            elif kind == "tool_result":
                items.append(
                    Item(
                        key,
                        "tool_result",
                        "user",
                        {
                            "id": block["tool_use_id"],
                            "content": block.get("content", ""),
                            "is_error": block.get("is_error", False),
                        },
                        time,
                    )
                )
            elif kind in ("thinking", "redacted_thinking"):
                facts.append(
                    Fact(
                        key, "provider_reasoning", {"record": row, "block": block}, time
                    )
                )
            elif kind == "document":
                source = block["source"]
                if source.get("type") == "base64":
                    items.append(
                        Item(
                            key,
                            "file",
                            "user",
                            {
                                "mime": source["media_type"],
                                "data": source["data"],
                                "name": block.get("title"),
                            },
                            time,
                        )
                    )
                else:
                    facts.append(
                        Fact(key, "attachment", {"record": row, "block": block}, time)
                    )
            elif kind == "image":
                source = block["source"]
                url = (
                    source["url"]
                    if source["type"] == "url"
                    else "data:" + source["media_type"] + ";base64," + source["data"]
                )
                items.append(Item(key, "image", "user", {"url": url}, time))
            else:
                facts.append(
                    Fact(key, "native_content", {"record": row, "block": block}, time)
                )
    from .projection import settle

    items = settle(items, facts)
    if not title:
        title = next(
            (
                x.body["text"][:120]
                for x in items
                if x.kind == "text" and x.role == "user"
            ),
            "Untitled chat",
        )
    return Snapshot(
        "claude",
        first["sessionId"],
        first["cwd"],
        title,
        millis(first["timestamp"]),
        max(
            [millis(first["timestamp"])]
            + [x.created for x in items]
            + [x.created for x in facts]
        ),
        items,
        rows,
        digest,
        str(path),
        facts=facts,
        raw_bytes=raw_bytes,
        interrupted=bool(raw_bytes and not raw_bytes.endswith(b"\n")),
    )


def claude_project(cwd):
    return re.sub(r"[^a-zA-Z0-9]", "-", cwd)


def write_claude(layout, chat, items, native_id, prepare, bindings):
    from .projection import prefix

    path = (
        layout.claude
        / "projects"
        / claude_project(chat["cwd"])
        / (native_id + ".jsonl")
    )
    previous = read_claude(path) if path.exists() else None
    count, mapping, keep = prefix(previous, items, bindings)
    rows = []
    parent = None
    original = b""
    if keep:
        original = previous.raw_bytes
        if previous.interrupted:
            original = original[: original.rfind(b"\n") + 1]
        parent = next(
            (
                row["uuid"]
                for row in reversed(previous.raw)
                if row.get("uuid")
                and row.get("type") in ("user", "assistant", "system")
            ),
            None,
        )
        items = items[count:]
    for item in items:
        body = item.body
        kind = item.kind
        if kind == "text":
            block = {"type": "text", "text": body["text"]}
        elif kind == "file":
            block = {
                "type": "document",
                "source": {
                    "type": "base64",
                    "media_type": body["mime"],
                    "data": body["data"],
                },
            }
            if body.get("name"):
                block["title"] = body["name"]
        elif kind == "tool_call":
            block = {
                "type": "tool_use",
                "id": body["id"],
                "name": body["name"],
                "input": body["input"],
            }
        elif kind == "tool_result":
            block = {
                "type": "tool_result",
                "tool_use_id": body["id"],
                "content": body["content"],
                "is_error": body["is_error"],
            }
        elif kind == "image":
            url = body["url"]
            if url.startswith("data:"):
                mime, data = url[5:].split(";base64,", 1)
                block = {
                    "type": "image",
                    "source": {"type": "base64", "media_type": mime, "data": data},
                }
            else:
                block = {"type": "image", "source": {"type": "url", "url": url}}
        else:
            raise ValueError("unsupported_history_item")
        identifier = item.id
        message = {"role": item.role, "content": [block]}
        if item.role == "assistant":
            message.update(
                id="msg_" + identifier.replace("-", ""),
                type="message",
                model="oblivion-history",
                stop_reason="tool_use" if kind == "tool_call" else "end_turn",
                stop_sequence=None,
                usage={"input_tokens": 0, "output_tokens": 0},
            )
        rows.append(
            {
                "type": item.role,
                "uuid": identifier,
                "parentUuid": parent,
                "sessionId": native_id,
                "cwd": chat["cwd"],
                "version": VERSIONS["claude"],
                "isSidechain": False,
                "userType": "external",
                "timestamp": iso(item.created),
                "message": message,
            }
        )
        mapping[identifier + ":0"] = item.id
        parent = identifier
    rows.append(
        {"type": "custom-title", "sessionId": native_id, "customTitle": chat["title"]}
    )
    data = original + ("\n".join(encode(x) for x in rows) + "\n").encode()
    prepare(mapping, previous)
    atomic_write(path, data)
    return path, read_claude(path), mapping
