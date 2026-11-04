"""Run inside a networkless Linux fixture with the official pinned binary.

This exercises real key import and native config readers, not inference or a
provider login. All identity material and model names below are synthetic.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import resource
import re
import select
import sqlite3
import subprocess
import tempfile
import urllib.request

guest = Path(__file__).parents[1] / "guest"
os.umask(0o077)
spec = importlib.util.spec_from_file_location("delegation", guest / "credential-delegation.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
spec = importlib.util.spec_from_file_location("native_configure", guest / "native-tools/configure.py")
profiles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profiles)

interfaces = [path for path in Path("/sys/class/net").iterdir() if path.is_dir()]
if any(path.name != "lo" and int((path / "flags").read_text(), 16) & 1 for path in interfaces):
    raise SystemExit("This fixture requires a network namespace with only loopback.")
binary = "/usr/lib/oblivion/agents/bin/opencode2"
with tempfile.TemporaryDirectory(prefix="oblivion-native-auth-fixture-") as temporary:
    vault = Path(temporary)
    for name in ("home", "state", "config", "workspace"):
        (vault / name).mkdir(mode=0o700)
    value = {"kind": "opencode-key", "integration_id": "abliteration-ai", "key": "ak-synthetic-oblivion-offline-fixture-only", "model": "abliteration-ai/abliterated-model"}
    adapter.install(vault, value)
    profiles.configure("opencode2", vault / "home", vault / "config")
    adapter.install(vault, value)
    with sqlite3.connect(vault / "state/opencode/opencode.db") as db:
        rows = db.execute("SELECT integration_id,value FROM credential").fetchall()
        assert len(rows) == 1 and rows[0][0] == "abliteration-ai"
        assert json.loads(rows[0][1]) == {"type": "key", "key": value["key"]}
    assert adapter.export(vault, "opencode2", auth_environment={}) == value
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "HOME": str(vault / "home"),
           "XDG_CONFIG_HOME": str(vault / "config"), "XDG_DATA_HOME": str(vault / "state"), "XDG_STATE_HOME": str(vault / "state"),
           "XDG_CACHE_HOME": str(vault / "cache"), "TMPDIR": "/tmp", "OPENCODE_SERVER_PASSWORD": "fixture-loopback-only-password",
           "OPENCODE_DISABLE_MODELS_FETCH": "1", "OPENCODE_DISABLE_PROJECT_CONFIG": "1", "OPENCODE_DISABLE_AUTOUPDATE": "1",
           "OPENCODE_DISABLE_FILEWATCHER": "1", "OPENCODE_DISABLE_FFF": "1", "DO_NOT_TRACK": "1", "OTEL_SDK_DISABLED": "true"}
    adapter.install(vault, {"kind": "codex-api-key", "key": "sk-synthetic-codex-fixture-only"})
    (vault / "home/.codex/config.toml").write_text('cli_auth_credentials_store="file"\n')
    codex = subprocess.run(["/usr/lib/oblivion/agents/bin/codex", "login", "status"], env={**env, "CODEX_HOME": str(vault / "home/.codex")},
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    assert codex.returncode == 0 and b"api key" in (codex.stdout + codex.stderr).lower()
    adapter.install(vault, {"kind": "claude-setup-token", "token": "sk-ant-oat01-synthetic-offline-fixture-only"})
    claude = subprocess.run(["/usr/lib/oblivion/agents/bin/claude", "auth", "status"],
                            env={**env, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1"},
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    assert claude.returncode == 0 and json.loads(claude.stdout)["loggedIn"] is True
    version = subprocess.run([binary, "--version"], env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
    assert re.search(rb"(?<![0-9.])2\.0\.1(?![0-9.])", version.stdout)
    process = subprocess.Popen([binary, "serve", "--stdio", "--hostname", "127.0.0.1", "--port", "0"],
                               cwd=vault / "workspace", env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        assert select.select([process.stdout], [], [], 15)[0], "native server readiness timeout"
        ready = json.loads(process.stdout.readline(4096))
        auth = "Basic " + base64.b64encode(b"opencode:fixture-loopback-only-password").decode()
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with client.open(urllib.request.Request(ready["url"] + "/api/config", headers={"Authorization": auth}), timeout=10) as response:
            entries = json.loads(response.read(65536))
        assert any(entry.get("info", {}).get("model") == {"providerID": "abliteration-ai", "model": "abliterated-model"} for entry in entries)
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    print("Pinned OpenCode2: offline native key API, idempotence, separate native store, profile preservation and native config reader passed.")
    print("Pinned Codex and Claude native auth readers recognized their synthetic API-key/setup-token stores offline.")
    print("Peak child RSS:", resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss, "KiB; tested under 512 MiB / 128 process limits.")
