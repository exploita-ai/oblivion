"""Private metadata/checks inside a networkless session VM, not disk encryption."""
import contextlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat


class Rejected(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def metadata(value):
    if not isinstance(value, dict) or set(value) != {"format", "version", "original_id", "title"}:
        raise Rejected("invalid-metadata")
    if value["format"] != "oblivion-session" or type(value["version"]) is not int:
        raise Rejected("invalid-metadata")
    if value["version"] != 1:
        raise Rejected("unsupported-version")
    if not isinstance(value["original_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", value["original_id"]):
        raise Rejected("invalid-metadata")
    title = value["title"]
    if title is not None and (not isinstance(title, str) or not title.strip() or title != title.strip()
                              or len(title) > 80 or len(title.encode()) > 256
                              or any(ord(char) < 32 or 0x7f <= ord(char) <= 0x9f or 0x202a <= ord(char) <= 0x202e or 0x2066 <= ord(char) <= 0x2069 for char in title)):
        raise Rejected("invalid-metadata")
    return value


@contextlib.contextmanager
def directory(vault, create=False):
    state = os.open(vault / "state", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if create:
            try:
                os.mkdir("oblivion", mode=0o700, dir_fd=state)
            except FileExistsError:
                pass
        target = os.open("oblivion", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state)
        try:
            owner = os.fstat(target)
            if owner.st_uid != os.geteuid() or owner.st_mode & 0o077:
                raise Rejected("invalid-metadata")
            yield target
            os.fsync(target)
            os.fsync(state)
        finally:
            os.close(target)
    finally:
        os.close(state)


def read(target):
    descriptor = os.open("session.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=target)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077 or not 0 < info.st_size <= 4096:
            raise Rejected("invalid-metadata")
        return metadata(json.loads(source.read(4097)))


def check_database(vault):
    data = vault / "state/opencode"
    canonical = data / "oblivion.db"
    paths = [canonical] if canonical.exists() or canonical.is_symlink() else [path for path in (
        data / "opencode-oblivion-beta.db", data / "opencode-oblivion-dev.db", data / "opencode.db",
    ) if path.exists() or path.is_symlink()]
    if data.is_symlink():
        raise Rejected("invalid-database")
    for path in paths:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size < 512 or source.read(16) != b"SQLite format 3\x00":
                raise Rejected("invalid-database")
            # mode=ro includes committed WAL frames and never runs engine
            # migrations or recovery. Any SQLite SHM remains inside this vault.
            with contextlib.closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
                if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    raise Rejected("invalid-database")


def execute(value, vault, owner):
    try:
        with directory(vault, value["action"] == "checkpoint") as target:
            if value["action"] == "inspect":
                current = read(target)
                check_database(vault)
                return {"result": "metadata", "metadata": current}
            # A future format must never be silently replaced by a v1 record.
            try:
                read(target)
            except FileNotFoundError:
                pass
            check_database(vault)
            name = ".pending-" + owner + "-" + secrets.token_hex(16)
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
            try:
                with os.fdopen(descriptor, "wb") as destination:
                    destination.write((json.dumps(value["metadata"], ensure_ascii=False) + "\n").encode())
                    destination.flush()
                    os.fsync(destination.fileno())
                os.replace(name, "session.json", src_dir_fd=target, dst_dir_fd=target)
                os.fsync(target)
            finally:
                try:
                    os.unlink(name, dir_fd=target)
                except FileNotFoundError:
                    pass
            return {"result": "metadata", "metadata": value["metadata"]}
    except Rejected as error:
        return {"result": "rejected", "error": error.code}
    except sqlite3.Error:
        return {"result": "rejected", "error": "invalid-database"}
    except (OSError, ValueError):
        return {"result": "rejected", "error": "invalid-metadata"}


def cleanup(vault, owner):
    try:
        with directory(vault) as target:
            prefix = ".pending-" + (owner + "-" if owner else "")
            for name in os.listdir(target):
                if name.startswith(prefix):
                    os.unlink(name, dir_fd=target)
    except FileNotFoundError:
        pass
