"""Credential-only native adapters, called exclusively by private SafeAdmin.

No native login flow is run during installation: Codex's current file format
and Claude's documented env settings work offline. OpenCode2's current native
credential API is served briefly on private loopback, with model fetch,
project config, plugins, MCP and watchers disabled. No provider request is made.
"""
import base64
import contextlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import sqlite3
import stat
import subprocess
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

LIMIT = 16384
KINDS = {"codex-api-key": "codex", "codex-access-token": "codex", "claude-api-key": "claude", "claude-setup-token": "claude", "opencode-key": "opencode2"}
PROVIDERS = {"openai", "anthropic", "openrouter", "opencode", "xai", "cerebras", "abliteration-ai"}
# Identity registrations from the official v2.0.1 models-dev snapshot. No
# inference models are fabricated. This transient catalog exists only so a
# fresh, offline native API can accept its own integration's credential.
IDENTITIES = {
    "openai": {"name": "OpenAI", "env": ["OPENAI_API_KEY"], "npm": "@ai-sdk/openai"},
    "anthropic": {"name": "Anthropic", "env": ["ANTHROPIC_API_KEY"], "npm": "@ai-sdk/anthropic"},
    "openrouter": {"name": "OpenRouter", "env": ["OPENROUTER_API_KEY"], "npm": "@openrouter/ai-sdk-provider", "api": "https://openrouter.ai/api/v1"},
    "opencode": {"name": "OpenCode Zen", "env": ["OPENCODE_API_KEY"], "npm": "@ai-sdk/openai-compatible", "api": "https://opencode.ai/zen/v1"},
    "xai": {"name": "xAI", "env": ["XAI_API_KEY"], "npm": "@ai-sdk/xai"},
    "cerebras": {"name": "Cerebras", "env": ["CEREBRAS_API_KEY"], "npm": "@ai-sdk/cerebras"},
    "abliteration-ai": {"name": "abliteration.ai", "env": ["ABLIT_KEY"], "npm": "@ai-sdk/openai-compatible", "api": "https://api.abliteration.ai/v1"},
}
OPENCODE_ROUTE_ENV = ("OPENCODE_CONFIG", "OPENCODE_CONFIG_CONTENT", "OPENCODE_CONFIG_DIR", "OPENCODE_MODELS_PATH", "OPENCODE_MODELS_URL",
                      "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "OPENROUTER_BASE_URL", "OPENCODE_BASE_URL", "XAI_BASE_URL", "CEREBRAS_BASE_URL", "ABLIT_BASE_URL", "ABLITERATION_BASE_URL")
AUTH_ENV = {"codex": ("CODEX_ACCESS_TOKEN", "CODEX_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "CODEX_HOME"),
            "claude": ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_BASE_URL", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "ANTHROPIC_PROFILE"),
            "opencode2": tuple(name for identity in IDENTITIES.values() for name in identity["env"]) + OPENCODE_ROUTE_ENV}


class Rejected(ValueError):
    def __init__(self, code="needs-auth"):
        self.code = code
        super().__init__(code)


def credential(value):
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str) or value["kind"] not in KINDS:
        raise Rejected("invalid-credential")
    kind = value["kind"]
    field = "token" if kind.endswith("token") else "key"
    fields = {"kind", field} | ({"integration_id", "model"} if kind == "opencode-key" else set())
    secret = value.get(field)
    if set(value) != fields or not isinstance(secret, str) or not 0 < len(secret.encode()) <= 8192 or secret != secret.strip() or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in secret):
        raise Rejected("invalid-credential")
    if kind == "codex-access-token" and not secret.startswith("at-"):
        raise Rejected("unsupported-oauth")
    if kind == "opencode-key":
        integration = value["integration_id"]
        model = value["model"]
        if not isinstance(integration, str) or integration not in PROVIDERS or not isinstance(model, str) or len(model.encode()) > 256 or not model.startswith(integration + "/") or len(model) <= len(integration) + 1 or any(not char.isprintable() for char in model):
            raise Rejected("invalid-credential")
    if len(json.dumps(value, ensure_ascii=False).encode()) > LIMIT:
        raise Rejected("invalid-credential")
    return value


@contextlib.contextmanager
def directory(vault, relative, create=False):
    descriptor = os.open(vault, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in relative.split("/"):
            if create:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def read_json(vault, relative, *, private=True):
    parent, name = relative.rsplit("/", 1)
    try:
        with directory(vault, parent) as target:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=target)
            with os.fdopen(descriptor, "rb") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or private and info.st_mode & 0o077 or info.st_size > 65536:
                    raise Rejected()
                raw = source.read(65537)
                value = tomllib.loads(raw.decode()) if relative.endswith(".toml") else json.loads(raw)
                if not isinstance(value, dict):
                    raise Rejected()
                return value
    except FileNotFoundError:
        return {}


def write_json(vault, relative, value):
    parent, name = relative.rsplit("/", 1)
    with directory(vault, parent, create=True) as target:
        pending = ".pending-credential-" + secrets.token_hex(16)
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(value, output, separators=(",", ":"), ensure_ascii=False)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(pending, name, src_dir_fd=target, dst_dir_fd=target)
            os.fsync(target)
        finally:
            try:
                os.unlink(pending, dir_fd=target)
            except FileNotFoundError:
                pass


def environment(agent, vault):
    """Only fixed identity variables of official processes in THIS Safe.

    Multiple processes with different credentials are ambiguous; never choose
    an arbitrary account. No other process variables are returned or stored.
    """
    selected = {key: os.environ[key] for key in AUTH_ENV[agent] if key in os.environ and (os.environ[key] or agent == "opencode2" and key in OPENCODE_ROUTE_ENV)}
    executable = Path("/usr/lib/oblivion/agents/bin") / agent
    if not executable.exists():
        return selected
    expected = executable.resolve()
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            if process.stat().st_uid != os.geteuid() or (process / "exe").resolve() != expected:
                continue
            with (process / "cmdline").open("rb") as source:
                argv = source.read(65537)
            if len(argv) > 65536 or route_overrides(agent, [value.decode("utf-8", "ignore") for value in argv.split(b"\0")[1:] if value]):
                raise Rejected("unsupported-routing")
            if project_overrides(vault, agent, (process / "cwd").resolve()):
                raise Rejected("unsupported-routing")
            with (process / "environ").open("rb") as source:
                data = source.read(65537)
            if len(data) > 65536:
                raise Rejected()
            for item in data.split(b"\0"):
                key, separator, value = item.partition(b"=")
                if separator and key.decode("ascii", "ignore") in AUTH_ENV[agent] and (value or agent == "opencode2" and key.decode("ascii") in OPENCODE_ROUTE_ENV):
                    name = key.decode("ascii")
                    token = value.decode("utf-8")
                    if name in selected and selected[name] != token:
                        raise Rejected("ambiguous-auth")
                    selected[name] = token
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return selected


def route_overrides(agent, argv):
    """Effective CLI config cannot be qualified by inspecting defaults alone."""
    blocked = {"codex": ("--config", "--profile", "--oss", "--local-provider"),
               "claude": ("--settings", "--setting-sources"),
               "opencode2": ("--server", "--model")}[agent]
    for value in argv:
        if value == "--":
            return False
        if any(value == flag or value.startswith(flag + "=") for flag in blocked):
            return True
        if agent == "codex" and (value.startswith("-c") and not value.startswith("--") or value.startswith("-p") and not value.startswith("--")):
            return True
        if agent == "opencode2" and value.startswith("-m") and not value.startswith("--"):
            return True
    return False


def project_overrides(vault, agent, cwd):
    """Presence-only qualification; never parse or run a project's config."""
    roots = [vault / name for name in ("workspace", "imports", "home")]
    if not any(cwd == root or root in cwd.parents for root in roots):
        return True
    names = {"codex": (".codex/config.toml",),
             "claude": (".claude/settings.json", ".claude/settings.local.json"),
             "opencode2": ("opencode.json", "opencode.jsonc", ".opencode/opencode.json", ".opencode/opencode.jsonc", ".opencode/plugins")}[agent]
    current = cwd
    for _ in range(64):
        for name in names:
            # These two are the fixed global profiles qualified separately.
            if current == vault / "home" and name in (".codex/config.toml", ".claude/settings.json"):
                continue
            if os.path.lexists(current / name):
                return True
        if current in roots:
            return False
        current = current.parent
    return True


def export(vault, agent, *, auth_environment=None):
    if agent not in AUTH_ENV:
        raise Rejected("invalid-credential")
    env = environment(agent, vault) if auth_environment is None else auth_environment
    if agent == "codex":
        config = read_json(vault, "home/.codex/config.toml", private=False)
        if env.get("OPENAI_BASE_URL") or env.get("CODEX_HOME") not in (None, str(vault / "home/.codex")) or config.get("model_provider", "openai") != "openai" or config.get("model_providers", {}).get("openai"):
            raise Rejected("unsupported-routing")
        if env.get("CODEX_ACCESS_TOKEN"):
            return credential({"kind": "codex-access-token", "token": env["CODEX_ACCESS_TOKEN"]})
        source = read_json(vault, "home/.codex/auth.json")
        mode = source.get("auth_mode")
        if mode in ("chatgpt", "chatgptAuthTokens", "agentIdentity") or source.get("tokens"):
            raise Rejected("unsupported-oauth")
        if mode == "personalAccessToken" and source.get("personal_access_token"):
            return credential({"kind": "codex-access-token", "token": source["personal_access_token"]})
        # An explicit account login is never replaced by another billing mode.
        key = source.get("OPENAI_API_KEY") if mode in (None, "apikey") else None
        key = key or env.get("CODEX_API_KEY") or env.get("OPENAI_API_KEY")
        if key and mode in (None, "apikey"):
            return credential({"kind": "codex-api-key", "key": key})
        raise Rejected()
    if agent == "claude":
        settings = read_json(vault, "home/.claude/settings.json")
        configured = settings.get("env", {})
        if not isinstance(configured, dict):
            raise Rejected()
        env = {**{key: configured[key] for key in AUTH_ENV[agent] if configured.get(key)}, **env}
        if any(env.get(key) for key in ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "ANTHROPIC_PROFILE")) or env.get("CLAUDE_CONFIG_DIR") not in (None, str(vault / "home/.claude")):
            raise Rejected("unsupported-routing")
        oauth = read_json(vault, "home/.claude/.credentials.json").get("claudeAiOauth")
        if env.get("ANTHROPIC_API_KEY") and (env.get("CLAUDE_CODE_OAUTH_TOKEN") or oauth):
            raise Rejected("ambiguous-auth")
        if settings.get("apiKeyHelper") or settings.get("forceLoginMethod"):
            raise Rejected("unsupported-routing")
        if env.get("ANTHROPIC_API_KEY"):
            return credential({"kind": "claude-api-key", "key": env["ANTHROPIC_API_KEY"]})
        if env.get("CLAUDE_CODE_OAUTH_TOKEN"):
            return credential({"kind": "claude-setup-token", "token": env["CLAUDE_CODE_OAUTH_TOKEN"]})
        if oauth:
            raise Rejected("unsupported-oauth")
        raise Rejected()
    # Even an empty override is unqualified here: its loading semantics belong
    # to the native client, not to the fixed default-profile adapter.
    if any(name in env for name in OPENCODE_ROUTE_ENV):
        raise Rejected("unsupported-routing")
    settings = read_json(vault, "config/opencode/opencode.json", private=False)
    model = settings.get("model")
    if isinstance(model, dict) and set(model) <= {"providerID", "model", "variant"}:
        model = str(model.get("providerID", "")) + "/" + str(model.get("model", "")) + ("#" + str(model["variant"]) if model.get("variant") else "")
    if not isinstance(model, str) or "/" not in model:
        raise Rejected("model-required")
    integration = model.split("/", 1)[0]
    # Custom endpoints, provider forms and plugins require their own adapters.
    # Never send an inherited key to a guessed built-in endpoint.
    if settings.get("providers", {}).get(integration) or settings.get("plugins"):
        raise Rejected("unsupported-routing")
    value = selected_opencode_credential(vault, integration)
    if value is None:
        raise Rejected()
    if value.get("type") == "oauth":
        raise Rejected("unsupported-oauth")
    if set(value) != {"type", "key"} or value["type"] != "key":
        raise Rejected("unsupported-routing")
    result = credential({"kind": "opencode-key", "integration_id": integration, "key": value["key"], "model": model})
    if any(env.get(name) and env[name] != result["key"] for name in IDENTITIES[integration]["env"]):
        raise Rejected("ambiguous-auth")
    return result


def selected_opencode_credential(vault, integration):
    try:
        with directory(vault, "state/opencode") as target:
            descriptor = os.open("opencode.db", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=target)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                    raise Rejected()
                # Keep WAL-visible reads anchored to the opened native dir.
                with contextlib.closing(sqlite3.connect(f"file:/proc/self/fd/{target}/opencode.db?mode=ro", uri=True, timeout=2)) as db:
                    db.execute("PRAGMA query_only=ON")
                    row = db.execute("SELECT value FROM credential WHERE integration_id=? AND active=1 ORDER BY time_created DESC,id DESC LIMIT 1", (integration,)).fetchone()
                    if row is None:
                        return None
                    if len(row[0].encode()) > LIMIT:
                        raise Rejected()
                    value = json.loads(row[0])
                    if not isinstance(value, dict):
                        raise Rejected()
                    return value
            finally:
                os.close(descriptor)
    except FileNotFoundError:
        return None


def install(vault, value):
    credential(value)
    kind = value["kind"]
    if kind.startswith("codex-"):
        source = read_json(vault, "home/.codex/auth.json")
        native = ({"auth_mode": "apikey", "OPENAI_API_KEY": value["key"]} if kind == "codex-api-key"
                  else {"auth_mode": "personalAccessToken", "personal_access_token": value["token"], "OPENAI_API_KEY": None})
        if source and source != native:
            raise Rejected("auth-conflict")
        write_json(vault, "home/.codex/auth.json", native)
        return
    if kind.startswith("claude-"):
        settings = read_json(vault, "home/.claude/settings.json")
        env = settings.get("env", {})
        if not isinstance(env, dict):
            raise Rejected()
        name, secret = ("ANTHROPIC_API_KEY", value["key"]) if kind == "claude-api-key" else ("CLAUDE_CODE_OAUTH_TOKEN", value["token"])
        if any(key in env and (key != name or env[key] != secret) for key in AUTH_ENV["claude"]) or read_json(vault, "home/.claude/.credentials.json"):
            raise Rejected("auth-conflict")
        write_json(vault, "home/.claude/settings.json", {**settings, "env": {**env, name: secret}})
        return
    settings = read_json(vault, "config/opencode/opencode.json", private=False)
    if settings.get("model") not in (None, value["model"]) or settings.get("providers", {}).get(value["integration_id"]):
        raise Rejected("auth-conflict")
    current = selected_opencode_credential(vault, value["integration_id"])
    if current is not None and current != {"type": "key", "key": value["key"]}:
        raise Rejected("auth-conflict")
    if current is None:
        install_opencode(vault, value)
    write_json(vault, "config/opencode/opencode.json", {**settings, "model": value["model"]})


def install_opencode(vault, value):
    """The exact 2.0.1 public API. PrivateNetwork provides only loopback."""
    process = None
    with tempfile.TemporaryDirectory(prefix="oblivion-auth-config-") as config:
        # An isolated config directory plus disabled project config excludes
        # external plugins. Do not disable native built-in provider plugins.
        Path(config, "opencode.json").write_text('{"update":"disable","mcp":{"servers":{}}}', encoding="utf-8")
        Path(config, "identities.json").write_text(json.dumps({value["integration_id"]: {"id": value["integration_id"], **IDENTITIES[value["integration_id"]], "models": {}}}), encoding="utf-8")
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(vault / "home"),
               "XDG_CONFIG_HOME": str(vault / "config"), "XDG_DATA_HOME": str(vault / "state"),
               "XDG_STATE_HOME": str(vault / "state"), "XDG_CACHE_HOME": "/tmp/oblivion-cache", "TMPDIR": "/tmp",
               "OPENCODE_CONFIG_DIR": config, "OPENCODE_DISABLE_PROJECT_CONFIG": "1", "OPENCODE_DISABLE_MODELS_FETCH": "1",
               "OPENCODE_MODELS_PATH": str(Path(config, "identities.json")),
               "OPENCODE_DISABLE_FILEWATCHER": "1", "OPENCODE_DISABLE_FFF": "1", "OPENCODE_DISABLE_AUTOUPDATE": "1",
               "OTEL_SDK_DISABLED": "true", "DO_NOT_TRACK": "1", "OPENCODE_SERVER_PASSWORD": secrets.token_urlsafe(32)}
        try:
            process = subprocess.Popen(["/usr/lib/oblivion/agents/bin/opencode2", "serve", "--stdio", "--hostname", "127.0.0.1", "--port", "0"],
                cwd=config, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True, umask=0o077)
            deadline = time.monotonic() + 25
            data = bytearray()
            while b"\n" not in data:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    raise Rejected("install-timeout")
                part = os.read(process.stdout.fileno(), 1024)
                if not part or len(data) + len(part) > 4096:
                    raise Rejected("install-failed")
                data.extend(part)
            ready = json.loads(data.split(b"\n", 1)[0])
            address = urllib.parse.urlsplit(ready["url"])
            if address.scheme != "http" or address.hostname != "127.0.0.1" or not address.port or address.username or address.password or address.path not in ("", "/") or address.query or address.fragment:
                raise Rejected("install-failed")
            # Explicitly disable ambient proxies and redirects: the native key
            # is allowed only on this newly started loopback server instance.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, request, fp, code, message, headers, newurl):
                    raise Rejected("install-failed")
            client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            authorization = "Basic " + base64.b64encode(("opencode:" + env["OPENCODE_SERVER_PASSWORD"]).encode()).decode()
            endpoint = ready["url"].rstrip("/") + "/api/integration/" + urllib.parse.quote(value["integration_id"], safe="")
            # v2 activates a cold Location's built-in plugins asynchronously.
            # Listening is not sufficient readiness for a key-connect request.
            while True:
                if time.monotonic() >= deadline:
                    raise Rejected("install-timeout")
                with client.open(urllib.request.Request(endpoint, headers={"Authorization": authorization}), timeout=2) as response:
                    body = response.read(32769)
                    if len(body) > 32768:
                        raise Rejected("install-failed")
                    integration = json.loads(body).get("data")
                if integration is not None:
                    methods = integration.get("methods", [])
                    if integration.get("id") != value["integration_id"] or not any(method.get("type") == "key" and not method.get("form") for method in methods):
                        raise Rejected("install-failed")
                    break
                time.sleep(0.05)
            payload = json.dumps({"key": value["key"], "label": "Inherited identity"}, separators=(",", ":")).encode()
            request = urllib.request.Request(endpoint + "/connect/key",
                data=payload, headers={"Authorization": authorization, "Content-Type": "application/json"}, method="POST")
            with client.open(request, timeout=15) as response:
                if response.status != 204:
                    raise Rejected("install-failed")
        except (OSError, ValueError, KeyError, urllib.error.URLError, subprocess.SubprocessError):
            raise Rejected("install-failed") from None
        finally:
            if process is not None:
                process.stdin.close()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
