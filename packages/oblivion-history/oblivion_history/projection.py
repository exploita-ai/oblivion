"""Native projection reports provider facts and attachments retained in the archive."""

from dataclasses import replace

from .catalog import item_digest
from .model import Fact


def project(items, agent):
    result = []
    retained = {}
    excluded = set()
    for item in items:
        content = item.body.get("content") if item.kind == "tool_result" else None
        if (
            isinstance(content, list)
            and content
            and not any(x.get("type") == "text" for x in content)
        ):
            excluded.add(item.body["id"])
    for item in items:
        reason = None
        if item.kind == "file" and (
            agent == "codex"
            or agent == "claude"
            and item.body.get("mime") != "application/pdf"
        ):
            reason = "attachment_format"
        if (
            item.kind == "image"
            and agent == "opencode2"
            and not item.body["url"].startswith("data:")
        ):
            reason = "attachment_format"
        if item.kind == "reasoning":
            reason = "provider_reasoning"
        if item.kind in ("tool_call", "tool_result") and item.body["id"] in excluded:
            reason = "tool_content"
        if reason:
            retained[reason] = retained.get(reason, 0) + 1
            continue
        if item.kind == "tool_result" and isinstance(item.body["content"], list):
            content = [x for x in item.body["content"] if x.get("type") == "text"]
            omitted = len(item.body["content"]) - len(content)
            if omitted:
                retained["tool_content"] = retained.get("tool_content", 0) + omitted
                item = replace(item, body={**item.body, "content": content})
        result.append(item)
    return result, retained


def prefix(snapshot, items, bindings):
    """An unchanged visible prefix retains original provider-owned records."""
    if snapshot is None:
        return 0, {}, False
    visible, _ = project(snapshot.items, snapshot.agent)
    if len(visible) > len(items):
        return 0, {}, False
    for native, canonical in zip(visible, items):
        if bindings.get(native.native_id) != canonical.id or item_digest(
            native
        ) != item_digest(canonical):
            return 0, {}, False
    mapping = {
        item.native_id: bindings[item.native_id]
        for item in snapshot.items
        if item.native_id in bindings
    }
    return len(visible), mapping, True


def settle(items, facts):
    results = {item.body["id"] for item in items if item.kind == "tool_result"}
    calls = {item.body["id"] for item in items if item.kind == "tool_call"}
    visible = []
    for item in items:
        if (
            item.kind == "tool_call"
            and item.body["id"] not in results
            or item.kind == "tool_result"
            and item.body["id"] not in calls
        ):
            facts.append(
                Fact(
                    item.native_id,
                    "unsettled_tool",
                    {"kind": item.kind, "body": item.body},
                    item.created,
                )
            )
            continue
        visible.append(item)
    return visible
