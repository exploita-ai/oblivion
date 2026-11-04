"""Complete a Share's same-agent OpenCode imports on explicit client launch.

The offline maintenance VM never runs an agent. Its authenticated native
transfer files are consumed here by the immutable official OpenCode importer.
"""

import argparse
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oblivion_history.portable import MAX_BYTES, MAX_CHATS, MAX_LINE, open_file, validate_opencode, workspace, scope


def imported(database, value):
    if not database.exists():
        return False
    with open_file(database):
        pass
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_LINE)
        connection.execute("BEGIN")
        row = connection.execute("SELECT directory,title FROM session_v2 WHERE id=?", (value["info"]["id"],)).fetchone()
        if row is None:
            return False
        actual = [{"id": row[0], "type": row[1], **json.loads(row[2])} for row in connection.execute("SELECT id,type,data FROM session_message WHERE session_id=? ORDER BY seq", (value["info"]["id"],))]
        if row != (value["info"]["location"]["directory"], value["info"]["title"]) or actual != value["messages"]:
            raise ValueError("native_import_identity_conflict")
        return True
    finally:
        connection.close()


def prepare(vault, binary):
    vault = Path(vault).resolve()
    directory = vault / "state/oblivion/native-imports/opencode2"
    if not directory.exists():
        return
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("native_import_unavailable")
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    lock = os.open(directory / ".lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        files = sorted(directory.iterdir())
        if len(files) > MAX_CHATS + 1:
            raise ValueError("native_chat_limit")
        pending = {}
        for path in files:
            if path.name == ".lock":
                continue
            with open_file(path) as source:
                data = source.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise ValueError("native_history_limit")
                value = validate_opencode(json.loads(data), path.stem)
            pending[path.stem] = (path, value)
        ordered = []
        while pending:
            ready = [key for key, (_, value) in pending.items() if value["info"].get("parentID") not in pending]
            if not ready:
                raise ValueError("native_import_parent_cycle")
            ordered.extend(pending.pop(key) for key in ready)
        for path, value in ordered:
            cwd = workspace(scope(value["info"]["location"]["directory"], vault), vault)
            database = vault / "state/opencode/opencode.db"
            if not imported(database, value):
                result = subprocess.run([binary, "session", "import", "--standalone", str(path)],
                                        cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=120, check=False)
                if result.returncode != 0 or not imported(database, value):
                    raise ValueError("native_import_failed")
            path.unlink()
            os.fsync(parent)
    finally:
        os.close(lock)
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vault", required=True)
    parser.add_argument("--agent", choices=["codex", "opencode2"], required=True)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    if args.agent == "codex":
        from oblivion_history import codex_index

        codex_index.prepare(args.vault, args.binary)
        return
    prepare(args.vault, args.binary)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
        print("Native conversation import needs recovery; the source transfer was retained.", file=sys.stderr)
        sys.exit(1)
