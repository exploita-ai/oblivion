"""Positive-scope Share selection. No native agent, network or user code runs."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from oblivion_history.artifacts import chunk
from oblivion_history.portable import export_histories, native_histories, identifier, MAX_CHATS

MAX_ENTRIES = 16384
MAX_BYTES = 16 * 1024 * 1024 * 1024
MAX_WARNINGS = 512
SCAN_FILE = 64 * 1024
SCAN_TOTAL = 16 * 1024 * 1024
DENIED = {".ssh", ".gnupg", ".aws", ".azure", ".codex", ".claude", ".oblivion-system", ".oblivion-jobs"}
DENIED_FILES = {"auth.json", "credentials.json", "provider.keys.json", "api-keys.json", "proxy-profiles.json", "oauth.json", "tokens.json", "keyring.json", ".bash_history", ".zsh_history", ".python_history"}
SECRET = re.compile(rb"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:sk-[A-Za-z0-9_-]{16,})|(?:gh[pousr]_[A-Za-z0-9]{20,})|(?:github_pat_[A-Za-z0-9_]{20,})|(?:AKIA[A-Z0-9]{16})|(?:Bearer[ \t]+[A-Za-z0-9._~+/-]{16,})|(?i:(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)[\"' ]{0,4}[:=][\"' ]{0,4}[A-Za-z0-9._~+/-]{16,}))")


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def path(value):
    if not isinstance(value, str) or not value or len(value.encode()) > 4096 or "\\" in value or any(ord(char) < 32 or 127 <= ord(char) < 160 or char in "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" for char in value):
        raise ValueError("invalid_share_path")
    parts = value.split("/")
    if parts[0] not in ("workspace", "imports") or len(parts) > 32 or any(not part or part in (".", "..") or len(part.encode()) > 255 for part in parts):
        raise ValueError("share_root_not_allowed")
    return value


def private(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("share_stage_unavailable")
    return directory


class Plan:
    def __init__(self, vault, request):
        fields = {"version", "operation", "request_id", "paths", "chat_ids", "exclude_paths", "exclude_chats", "include_sensitive_paths", "include_sensitive_chats"}
        if not isinstance(request, dict) or set(request) != fields or type(request["version"]) is not int or request["version"] != 1 or request["operation"] != "plan" or not isinstance(request["request_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", request["request_id"]):
            raise ValueError("invalid_share_request")
        for key in ("paths", "exclude_paths", "include_sensitive_paths"):
            if not isinstance(request[key], list) or len(request[key]) > MAX_ENTRIES:
                raise ValueError("invalid_share_selection")
            for value in request[key]:
                path(value)
        for key in ("exclude_chats", "include_sensitive_chats", "chat_ids"):
            if request[key] is None and key == "chat_ids":
                continue
            if not isinstance(request[key], list) or len(request[key]) > MAX_CHATS:
                raise ValueError("invalid_share_chat_selection")
            for value in request[key]:
                identifier(value)
        self.vault = Path(vault)
        self.request = request
        self.stage = None
        self.entries = {}
        self.aliases = {}
        self.warnings = []
        self.warning_count = 0
        self.scanned = 0
        self.history_scanned = 0
        self.bytes = 0
        self.chats = []
        self.omitted = {}
        root = os.open(vault, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for selected in sorted(set(request["paths"])):
                if any(selected.startswith(other + "/") for other in request["paths"]):
                    continue
                components = selected.split("/")
                if self.excluded(selected):
                    continue
                if any(part.casefold() in DENIED for part in components) or components[-1].casefold() in DENIED_FILES:
                    self.warn("credential_store_excluded", path=selected, included=False)
                    continue
                parent = os.dup(root)
                try:
                    prefix = []
                    for name in components[:-1]:
                        prefix.append(name)
                        self.directory("/".join(prefix))
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                        os.close(parent)
                        parent = child
                    self.collect(parent, components[-1], selected)
                finally:
                    os.close(parent)
            self.history()
            if not self.entries:
                self.directory("workspace")
            self.manifest = sorted(self.entries.values(), key=lambda entry: entry["path"])
            encoded = json.dumps(self.manifest, ensure_ascii=False, separators=(",", ":")).encode()
            if len(encoded) > 8 * 1024 * 1024:
                raise ValueError("share_manifest_limit")
            self.manifest_sha256 = hashlib.sha256(encoded).hexdigest()
            self.public = {"version": 1, "request_id": request["request_id"], "manifest": self.manifest,
                           "manifest_sha256": self.manifest_sha256, "bytes": self.bytes, "chats": self.chats,
                           "omitted": self.omitted, "warnings": self.warnings, "warning_count": self.warning_count,
                           "scan": {"files_bytes": self.scanned, "history_bytes": self.history_scanned,
                                    "limit_per_kind": SCAN_TOTAL, "best_effort": True}}
            self.plan_sha256 = hashlib.sha256(encode(self.public)).hexdigest()
            self.public["plan_sha256"] = self.plan_sha256
        except BaseException:
            self.close()
            raise
        finally:
            os.close(root)

    def warn(self, reason, **subject):
        self.warning_count += 1
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append({"reason": reason, **subject})

    def excluded(self, selected):
        return any(selected == value or selected.startswith(value + "/") for value in self.request["exclude_paths"])

    def directory(self, selected):
        if selected not in self.entries:
            if len(self.entries) >= MAX_ENTRIES:
                raise ValueError("share_entry_limit")
            self.entries[selected] = {"kind": "directory", "path": selected}

    def collect(self, parent, name, selected):
        if self.excluded(selected):
            return
        path(selected)
        parts = selected.split("/")
        if any(part.casefold() in DENIED for part in parts) or name.casefold() in DENIED_FILES:
            self.warn("credential_store_excluded", path=selected, included=False)
            return
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            self.directory(selected)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                for entry in sorted(os.scandir(child), key=lambda entry: entry.name):
                    try:
                        path(selected + "/" + entry.name)
                    except (ValueError, UnicodeError):
                        self.warn("invalid_name_excluded", path=selected, included=False)
                        continue
                    self.collect(child, entry.name, selected + "/" + entry.name)
            finally:
                os.close(child)
            return
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            self.warn("unsupported_entry_excluded", path=selected, included=False)
            return
        if info.st_size > MAX_BYTES - self.bytes or len(self.entries) >= MAX_ENTRIES:
            raise ValueError("share_content_limit")
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(source, "rb") as file:
            opened = os.fstat(file.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
                raise ValueError("share_source_changed")
            digest = hashlib.sha256()
            prefix = bytearray()
            remaining = info.st_size + 1
            while remaining:
                block = file.read(min(1024 * 1024, remaining))
                if not block:
                    break
                remaining -= len(block)
                digest.update(block)
                limit = min(SCAN_FILE, max(0, SCAN_TOTAL - self.scanned))
                sampled = block[:max(0, limit - len(prefix))]
                prefix.extend(sampled)
            self.scanned += len(prefix)
            if remaining != 1 or os.fstat(file.fileno()).st_size != info.st_size:
                raise ValueError("share_source_changed")
        candidate = name.startswith(".env") or name in (".npmrc", ".pypirc") or selected.endswith("/.git/config") or name.endswith((".pem", ".key", ".p12")) or "mcp" in name.casefold() and name.endswith(".json") or bool(SECRET.search(prefix))
        included = not candidate or selected in self.request["include_sensitive_paths"]
        if candidate:
            self.warn("potential_secret", path=selected, included=included, default_excluded=True)
        if len(prefix) < info.st_size:
            self.warn("partial_content_scan", path=selected, included=included)
        if not included:
            return
        self.bytes += info.st_size
        if self.bytes > MAX_BYTES or len(self.entries) >= MAX_ENTRIES:
            raise ValueError("share_content_limit")
        self.entries[selected] = {"kind": "file", "path": selected, "size": info.st_size, "sha256": digest.hexdigest()}
        self.aliases[selected] = selected

    def history(self):
        requested = self.request["chat_ids"]
        if requested == []:
            return
        histories = {entry["id"]: entry for entry in native_histories(self.vault)}
        available = set(histories)
        selected = sorted(available if requested is None else set(requested))
        selected = [value for value in selected if value not in self.request["exclude_chats"]]
        if not set(selected) <= available or len(selected) > MAX_CHATS:
            raise ValueError("invalid_share_chat_selection")
        if not selected:
            return
        for selected_id in selected:
            for required in histories[selected_id]["required_paths"]:
                if self.entries.get(required, {}).get("kind") != "file":
                    raise ValueError("share_native_dependency_not_selected")
        stage = private(self.vault / "state/.oblivion-share")
        selected_stage = stage / self.request["request_id"]
        selected_stage.mkdir(mode=0o700)
        self.stage = selected_stage
        archive = self.stage / "chats.jsonl"
        report = export_histories(self.vault, selected, archive)
        excluded = set()
        partial = set()
        carries = {}
        with open(archive, "rb") as source:
            for line in source:
                value = json.loads(line)
                chat = value.get("chat_id") or value.get("id")
                record = value.get("data")
                decoded = chunk(record) if isinstance(record, dict) and record.get("type") == "native-chunk" else line
                key = (chat, record["path"]) if isinstance(record, dict) and record.get("type") == "native-chunk" else (chat, "")
                limit = min(SCAN_FILE, max(0, SCAN_TOTAL - self.history_scanned))
                sample = decoded[:limit]
                self.history_scanned += len(sample)
                if chat and len(sample) < len(decoded):
                    partial.add(chat)
                tested = carries.get(key, b"") + sample
                carries[key] = sample[-256:] if len(sample) == len(decoded) else b""
                if chat and SECRET.search(tested):
                    included = chat in self.request["include_sensitive_chats"]
                    self.warn("potential_secret", chat_id=chat, included=included, default_excluded=True)
                    if not included:
                        excluded.add(chat)
        for chat in sorted(partial):
            self.warn("partial_content_scan", chat_id=chat, included=chat not in excluded)
        if excluded:
            selected = [chat for chat in selected if chat not in excluded]
            archive.unlink()
            if not selected:
                self.stage.rmdir(); self.stage = None
                return
            report = export_histories(self.vault, selected, archive)
        for selected_id in selected:
            if histories[selected_id].get("required_prefixes", 0):
                self.warn("native_history_dependency_included", chat_id=selected_id, included=True)
        self.chats = selected
        self.omitted = report["omitted"]
        digest = hashlib.sha256()
        with open(archive, "rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        self.directory("history")
        self.bytes += report["bytes"]
        if self.bytes > MAX_BYTES or len(self.entries) >= MAX_ENTRIES:
            raise ValueError("share_content_limit")
        self.entries["history/chats.jsonl"] = {"kind": "file", "path": "history/chats.jsonl", "size": report["bytes"], "sha256": digest.hexdigest()}
        self.aliases["history/chats.jsonl"] = "state/.oblivion-share/" + self.request["request_id"] + "/chats.jsonl"

    def approve(self, request_id, plan_sha256):
        if request_id != self.request["request_id"] or plan_sha256 != self.plan_sha256:
            raise ValueError("share_plan_not_approved")
        return {"version": 1, "request_id": request_id, "manifest_sha256": self.manifest_sha256,
                "entries": self.manifest, "aliases": [self.aliases[entry["path"]] for entry in self.manifest if entry["kind"] == "file"]}

    def close(self):
        if self.stage is not None:
            (self.stage / "chats.jsonl").unlink(missing_ok=True)
            self.stage.rmdir()
            self.stage = None
