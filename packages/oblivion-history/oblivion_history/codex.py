import json
from pathlib import Path

from .catalog import atomic_write, fingerprint
from .jsonl import records
from .model import Fact, Item, Snapshot, VERSIONS, encode, iso, millis


def read_codex(path):
    rows, digest, raw_bytes = records(path)
    if not rows or rows[0].get("type") != "session_meta":
        raise ValueError("invalid_codex_rollout")
    meta = rows[0]["payload"]
    if (
        meta.get("history_mode") != "paginated"
        or meta.get("cli_version") != VERSIONS["codex"]
    ):
        raise ValueError("unsupported_codex_format")
    created = millis(meta.get("timestamp", rows[0]["timestamp"]))
    title = ""
    index = Path(path).parents[4] / "session_index.jsonl"
    if index.exists():
        names = [x for x in records(index)[0] if x.get("id") == meta["id"]]
        if names:
            title = names[-1]["thread_name"]
            digest = fingerprint((digest + encode(names[-1])).encode())
    items = []
    facts = []
    for row in rows[1:]:
        payload = row["payload"]
        if row.get("type") == "response_item" and payload.get("type") == "reasoning":
            facts.append(
                Fact(
                    "response:" + str(row.get("ordinal", len(facts))),
                    "provider_reasoning",
                    {"record": row},
                    millis(row["timestamp"]),
                )
            )
        if row.get("type") in ("compacted", "compaction"):
            facts.append(
                Fact(
                    "record:" + str(row.get("ordinal", len(facts))),
                    "compaction",
                    {"record": row},
                    millis(row["timestamp"]),
                )
            )
        if row.get("type") != "event_msg":
            continue
        if payload.get("type") in ("turn_aborted", "task_aborted", "task_failed"):
            facts.append(
                Fact(
                    "interrupted:" + str(row.get("ordinal", len(facts))),
                    "interrupted_execution",
                    {"record": row},
                    millis(row["timestamp"]),
                )
            )
        if payload.get("type") != "item_completed":
            continue
        item = payload["item"]
        key = item["id"]
        time = int(payload.get("completed_at_ms", millis(row["timestamp"])))
        kind = item["type"]
        if kind in ("UserMessage", "AgentMessage"):
            role = "user" if kind == "UserMessage" else "assistant"
            for index, block in enumerate(item["content"]):
                if block["type"] in ("text", "Text"):
                    items.append(
                        Item(
                            key + ":" + str(index),
                            "text",
                            role,
                            {"text": block["text"]},
                            time,
                        )
                    )
                elif block["type"] == "image":
                    items.append(
                        Item(
                            key + ":" + str(index),
                            "image",
                            "user",
                            {"url": block["image_url"]},
                            time,
                        )
                    )
                else:
                    facts.append(
                        Fact(
                            key + ":" + str(index),
                            "attachment",
                            {"record": row, "block": block},
                            time,
                        )
                    )
        elif kind == "CommandExecution":
            if (
                item.get("status") not in ("completed", "failed")
                or item.get("exit_code") is None
            ):
                facts.append(Fact(key, "interrupted_tool", {"record": row}, time))
                continue
            command = item.get("parsed_cmd", [])
            text = command[0].get("cmd") if len(command) == 1 else None
            if text is None:
                import shlex

                text = shlex.join(item["command"])
            items.append(
                Item(
                    key + ":call",
                    "tool_call",
                    "assistant",
                    {"id": key, "name": "exec_command", "input": {"cmd": text}},
                    time,
                )
            )
            items.append(
                Item(
                    key + ":result",
                    "tool_result",
                    "user",
                    {
                        "id": key,
                        "content": item.get("aggregated_output", ""),
                        "is_error": item.get("exit_code", 0) != 0,
                    },
                    time,
                )
            )
        elif kind in ("DynamicToolCall", "McpToolCall"):
            name = (
                item["tool"]
                if kind == "DynamicToolCall"
                else "mcp__" + item["server"] + "__" + item["tool"]
            )
            if kind == "DynamicToolCall":
                content = [
                    {"type": "text", "text": x["text"]}
                    for x in (item.get("content_items") or [])
                    if x["type"] == "inputText"
                ]
                if any(
                    x["type"] != "inputText" for x in (item.get("content_items") or [])
                ):
                    facts.append(
                        Fact(key + ":binary", "tool_content", {"record": row}, time)
                    )
            else:
                content = (item.get("result") or {}).get("content", [])
            items.append(
                Item(
                    key + ":call",
                    "tool_call",
                    "assistant",
                    {"id": key, "name": name, "input": item["arguments"]},
                    time,
                )
            )
            items.append(
                Item(
                    key + ":result",
                    "tool_result",
                    "user",
                    {
                        "id": key,
                        "content": content,
                        "is_error": item["status"] == "failed",
                    },
                    time,
                )
            )
        elif kind == "Reasoning":
            facts.append(Fact(key, "reasoning_summary", {"record": row}, time))
        elif kind == "ContextCompaction":
            facts.append(Fact(key, "compaction", {"record": row}, time))
        else:
            facts.append(Fact(key, "native_item", {"record": row}, time))
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
        "codex",
        meta["id"],
        meta["cwd"],
        title,
        created,
        max([created] + [x.created for x in items]),
        items,
        rows,
        digest,
        str(path),
        facts=facts,
        raw_bytes=raw_bytes,
        interrupted=bool(raw_bytes and not raw_bytes.endswith(b"\n")),
    )


def write_codex(layout, chat, items, native_id, prepare, bindings):
    from .model import stable
    import tomllib

    previous = list(
        (layout.codex / "sessions").glob("**/rollout-*-" + native_id + ".jsonl")
    )
    if len(previous) > 1:
        raise ValueError("duplicate_native_rollout")
    from .projection import prefix

    snapshot = read_codex(previous[0]) if previous else None
    count, mapping, keep = prefix(snapshot, items, bindings)
    original = snapshot.raw[0] if snapshot else None
    original_bytes = b""
    ordinal_start = 0
    if keep:
        original_bytes = snapshot.raw_bytes
        if snapshot.interrupted:
            original_bytes = original_bytes[: original_bytes.rfind(b"\n") + 1]
        ordinal_start = max(row.get("ordinal", 0) for row in snapshot.raw) + 1
        items = items[count:]
    configuration = layout.codex / "config.toml"
    provider = "openai"
    if configuration.exists():
        provider = tomllib.loads(configuration.read_text()).get(
            "model_provider", "openai"
        )
    rows = [
        {
            "timestamp": iso(chat["created"]),
            "type": "session_meta",
            "payload": {
                "session_id": native_id,
                "id": native_id,
                "timestamp": iso(chat["created"]),
                "cwd": chat["cwd"],
                "runtime_workspace_roots": [chat["cwd"]],
                "originator": "codex_cli_rs",
                "cli_version": VERSIONS["codex"],
                "source": "cli",
                "thread_source": "user",
                "model_provider": provider,
                "history_mode": "paginated",
                "context_window": {"window_id": stable(chat["id"], "context-window")},
                "title": chat["title"],
                "base_instructions": {"text": ""},
            },
        }
    ]
    if original:
        rows[0]["payload"] = {
            **original["payload"],
            "cwd": chat["cwd"],
            "title": chat["title"],
        }
    results = {x.body["id"]: x for x in items if x.kind == "tool_result"}
    turn_id = None
    turn_started = None
    last = ""

    def event(time, payload):
        rows.append({"timestamp": iso(time), "type": "event_msg", "payload": payload})

    def complete_turn(time):
        if turn_id:
            event(
                time,
                {
                    "type": "task_complete",
                    "turn_id": turn_id,
                    "last_agent_message": last,
                    "started_at": int(turn_started / 1000),
                    "completed_at": int(time / 1000),
                    "duration_ms": 0,
                },
            )

    for item in items:
        body = item.body
        identifier = item.id
        if turn_id is None or item.kind in ("text", "image") and item.role == "user":
            complete_turn(item.created)
            turn_id = stable(chat["id"], "turn:" + identifier)
            turn_started = item.created
            event(
                item.created,
                {
                    "type": "task_started",
                    "turn_id": turn_id,
                    "root_turn_id": turn_id,
                    "started_at": int(item.created / 1000),
                    "model_context_window": 0,
                    "collaboration_mode_kind": "default",
                },
            )
        visible = None
        if item.kind == "text":
            payload = {
                "id": identifier,
                "type": "message",
                "role": item.role,
                "content": [
                    {
                        "type": "input_text" if item.role == "user" else "output_text",
                        "text": body["text"],
                    }
                ],
            }
            visible = {
                "type": "UserMessage" if item.role == "user" else "AgentMessage",
                "id": identifier,
                "content": [
                    {
                        "type": "text" if item.role == "user" else "Text",
                        "text": body["text"],
                        **({"text_elements": []} if item.role == "user" else {}),
                    }
                ],
            }
            mapping[identifier + ":0"] = item.id
            if item.role == "assistant":
                last = body["text"]
        elif item.kind == "image":
            payload = {
                "id": identifier,
                "type": "message",
                "role": "user",
                "content": [{"type": "input_image", "image_url": body["url"]}],
            }
            visible = {
                "type": "UserMessage",
                "id": identifier,
                "content": [{"type": "image", "image_url": body["url"]}],
            }
            mapping[identifier + ":0"] = item.id
        elif item.kind == "tool_call":
            result = results.get(body["id"])
            if result is None:
                raise ValueError("unsettled_tool_call")
            content = result.body["content"]
            if isinstance(content, str):
                content = [{"type": "text", "text": content}]
            if any(x.get("type") != "text" for x in content):
                raise ValueError("non_text_tool_result_not_supported")
            payload = {
                "type": "function_call",
                "call_id": body["id"],
                "name": body["name"],
                "arguments": encode(body["input"]),
            }
            visible = {
                "type": "DynamicToolCall",
                "id": body["id"],
                "tool": body["name"],
                "arguments": body["input"],
                "status": "failed" if result.body["is_error"] else "completed",
                "content_items": [
                    {"type": "inputText", "text": x["text"]} for x in content
                ],
                "success": not result.body["is_error"],
            }
            mapping[body["id"] + ":call"] = item.id
            mapping[body["id"] + ":result"] = result.id
        elif item.kind == "tool_result":
            output = body["content"]
            payload = {
                "type": "function_call_output",
                "call_id": body["id"],
                "output": output if isinstance(output, str) else encode(output),
            }
        elif item.kind == "reasoning":
            raise ValueError("cross_provider_reasoning_not_supported")
        else:
            raise ValueError("unsupported_history_item")
        payload["internal_chat_message_metadata_passthrough"] = {"turn_id": turn_id}
        rows.append(
            {
                "timestamp": iso(item.created),
                "type": "response_item",
                "payload": payload,
            }
        )
        if visible:
            event(
                item.created,
                {
                    "type": "item_completed",
                    "thread_id": native_id,
                    "turn_id": turn_id,
                    "item": visible,
                    "started_at_ms": item.created,
                    "completed_at_ms": item.created,
                },
            )
    complete_turn(chat["updated"])

    if keep:
        rows = rows[1:]
    for ordinal, row in enumerate(rows, start=ordinal_start):
        row["ordinal"] = ordinal
    date = iso(chat["created"])
    path = (
        layout.codex
        / "sessions"
        / date[:4]
        / date[5:7]
        / date[8:10]
        / ("rollout-" + date[:19].replace(":", "-") + "-" + native_id + ".jsonl")
    )
    if previous:
        path = previous[0]
    data = (
        original_bytes
        + ("\n".join(encode(x) for x in rows) + ("\n" if rows else "")).encode()
    )
    prepare(mapping, snapshot)
    atomic_write(path, data)
    index = layout.codex / "session_index.jsonl"
    existing = []
    if index.exists():
        existing = [x for x in records(index)[0] if x.get("id") != native_id]
    existing.append(
        {
            "id": native_id,
            "thread_name": chat["title"],
            "updated_at": iso(chat["updated"]),
        }
    )
    atomic_write(index, ("\n".join(encode(x) for x in existing) + "\n").encode())
    update_codex_name(layout, chat, native_id)
    return path, read_codex(path), mapping


def update_codex_name(layout, chat, native_id):
    codex_request(
        layout,
        chat["cwd"],
        "thread/name/set",
        {"threadId": native_id, "name": chat["title"]},
    )


def codex_request(layout, workspace, method, params):
    import select
    import subprocess

    environment = layout.environment()
    process = subprocess.Popen(
        ["codex", "app-server", "--stdio"],
        env=environment,
        cwd=workspace,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )

    def request(identifier, method, params):
        process.stdin.write(
            (
                encode({"id": identifier, "method": method, "params": params}) + "\n"
            ).encode()
        )
        process.stdin.flush()
        import time

        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if not select.select(
                [process.stdout], [], [], max(0, deadline - time.monotonic())
            )[0]:
                raise ValueError("codex_index_timeout")
            line = process.stdout.readline()
            if not line:
                raise ValueError("codex_index_failed")
            data = json.loads(line)
            if data.get("id") == identifier:
                if "error" in data:
                    raise ValueError("codex_index_failed")
                return data
        raise ValueError("codex_index_timeout")

    try:
        request(
            1,
            "initialize",
            {
                "clientInfo": {"name": "oblivion-history", "version": "1"},
                "capabilities": {"experimentalApi": True},
            },
        )
        request(
            2,
            "thread/list",
            {
                "cwd": workspace,
                "limit": 100,
                "modelProviders": [],
                "sourceKinds": ["cli", "exec", "vscode"],
            },
        )
        return request(3, method, params)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
