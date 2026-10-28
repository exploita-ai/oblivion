"""Keep chat storage independent of the client build channel, inside the vault."""

import base64
import contextlib
import json
import os
from pathlib import Path
import secrets
import selectors
import sqlite3
import subprocess
import tempfile
import urllib.request


@contextlib.contextmanager
def database(path):
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        yield connection
    finally:
        connection.close()


def backup(source, target):
    with database(source) as original, contextlib.closing(sqlite3.connect(target)) as copied:
        original.backup(copied)


@contextlib.contextmanager
def server(binary, path, runtime):
    password = secrets.token_urlsafe(32)
    env = {
        "PATH": os.defpath,
        "HOME": str(runtime / "home"),
        "XDG_CONFIG_HOME": str(runtime / "config"),
        "XDG_DATA_HOME": str(runtime / "data"),
        "XDG_STATE_HOME": str(runtime / "state"),
        "XDG_CACHE_HOME": str(runtime / "cache"),
        "OPENCODE_DB": str(path),
        "OPENCODE_PASSWORD": password,
        "OPENCODE_CONFIG_DIR": str(runtime / "config"),
        "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
        "OPENCODE_DISABLE_CLAUDE_CODE": "1",
        "OPENCODE_DISABLE_MODELS_FETCH": "1",
        "OPENCODE_DISABLE_FILEWATCHER": "1",
        "OPENCODE_DISABLE_FFF": "1",
    }
    # Unregistered stdio servers do not run restart recovery. No provider token,
    # user configuration, proxy credentials or inherited environment is supplied.
    process = subprocess.Popen(
        [binary, "serve", "--stdio", "--hostname", "127.0.0.1", "--port", "0"],
        env=env, cwd=runtime, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True,
    )
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(30):
                raise RuntimeError("Chat storage migration server did not start")
            line = process.stdout.readline()
            if not line:
                raise RuntimeError("Chat storage migration server failed")
        url = json.loads(line)["url"]
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def request(route, payload=None, *, envelope=False):
            headers = {
                "Authorization": "Basic " + base64.b64encode(("opencode:" + password).encode()).decode(),
                "Content-Type": "application/json",
            }
            query = urllib.request.Request(
                url + route, headers=headers,
                data=None if payload is None else json.dumps(payload).encode(),
            )
            with opener.open(query, timeout=30) as response:
                if response.status == 204:
                    return None
                value = json.load(response)
                return value if envelope else value["data"]

        yield request
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()
    if process.returncode != 0:
        raise RuntimeError("Chat storage migration server did not shut down cleanly")


def prepare(data, binary="/usr/bin/oblivion"):
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = data / "oblivion.db"
    if target.exists():
        return target
    sources = [path for path in (
        data / "opencode-oblivion-beta.db",
        data / "opencode-oblivion-dev.db",
        data / "opencode.db",
    ) if path.exists()]
    if not sources:
        return target

    # SQLite backup includes committed WAL frames. Keep originals untouched and
    # stage on the same encrypted filesystem; publish only after every check.
    with tempfile.TemporaryDirectory(prefix=".chat-migration-", dir=data) as directory:
        stage = Path(directory)
        merged = stage / "oblivion.db"
        backup(sources[0], merged)
        if len(sources) > 1:
            runtime = stage / "runtime"
            runtime.mkdir()
            with server(binary, merged, runtime) as destination:
                for index, source in enumerate(sources[1:]):
                    snapshot = stage / (str(index) + ".db")
                    backup(source, snapshot)
                    with database(snapshot) as db:
                        # Import preserves settled transcripts. Refuse to silently
                        # discard queued work or incomplete assistant/tool output.
                        if db.execute("select count(*) from session_inbox").fetchone()[0]:
                            raise RuntimeError("Finish pending chats before migrating chat storage")
                        rows = db.execute("select id, parent_id from session_v2").fetchall()
                        counts = dict(db.execute("select session_id, count(*) from session_message group by session_id"))
                    source_runtime = stage / ("runtime-" + str(index))
                    source_runtime.mkdir()
                    with server(binary, snapshot, source_runtime) as origin:
                        pending = dict(rows)
                        while pending:
                            ready = [key for key, parent in pending.items() if parent not in pending]
                            if not ready:
                                raise RuntimeError("Chat hierarchy needs recovery before migration")
                            for key in ready:
                                transcript = origin("/api/experimental/session/" + key + "/export")
                                if len(transcript["messages"]) != counts.get(key, 0):
                                    raise RuntimeError("Finish incomplete chats before migrating chat storage")
                                with database(merged) as db:
                                    exists = db.execute("select 1 from session_v2 where id = ?", (key,)).fetchone()
                                if exists:
                                    if destination("/api/experimental/session/" + key + "/export") != transcript:
                                        raise RuntimeError("Conflicting chat histories need recovery before migration")
                                else:
                                    destination("/api/experimental/session/import", {
                                        **transcript, "location": transcript["info"]["location"],
                                    })
                                    restored = destination("/api/experimental/session/" + key + "/export")
                                    if restored["messages"] != transcript["messages"]:
                                        raise RuntimeError("Chat migration verification failed")
                                del pending[key]
        with contextlib.closing(sqlite3.connect(merged)) as db:
            db.execute("pragma wal_checkpoint(truncate)")
            if db.execute("pragma integrity_check").fetchone() != ("ok",):
                raise RuntimeError("Chat database integrity check failed")
        with merged.open("rb") as file:
            os.fsync(file.fileno())
        os.rename(merged, target)
        descriptor = os.open(data, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return target


if __name__ == "__main__":
    os.umask(0o077)
    print(prepare(Path(os.environ["XDG_DATA_HOME"]) / "opencode"))
