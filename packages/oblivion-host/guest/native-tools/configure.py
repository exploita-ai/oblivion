"""Add the local Safe tools to a native JSON profile without replacing entries."""
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile

NODE = "/usr/lib/oblivion/node/bin/node"
SERVER = "/usr/lib/oblivion/tools/server.mjs"


def configure(agent, home, config):
    if agent == "claude":
        destination = home / ".claude.json"
        sections = ("mcpServers",)
        entry = {"type": "stdio", "command": NODE, "args": [SERVER], "timeout": 170000}
    elif agent == "opencode2":
        destination = config / "opencode/opencode.json"
        sections = ("mcp", "servers")
        entry = {"type": "local", "command": [NODE, SERVER], "codemode": False,
                 "timeout": {"startup": 10000, "catalog": 10000, "execution": 170000}}
    else:
        raise ValueError("unsupported_agent")
    # One lock covers simultaneous startup of native clients in the same Safe.
    descriptor = os.open(home / ".oblivion-tools-config.lock",
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            descriptor = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            value = {}
        else:
            with os.fdopen(descriptor, encoding="utf-8") as source:
                value = json.load(source)
        if not isinstance(value, dict):
            raise ValueError("invalid_agent_profile")
        servers = value
        for section in sections:
            servers = servers.setdefault(section, {})
            if not isinstance(servers, dict):
                raise ValueError("invalid_agent_profile")
        if "oblivion" in servers:
            return
        servers["oblivion"] = entry
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        pending = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                             prefix=".oblivion-tools-", delete=False) as output:
                pending = Path(output.name)
                os.fchmod(output.fileno(), 0o600)
                json.dump(value, output, indent=2, ensure_ascii=False)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            pending.replace(destination)
            pending = None
            descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            if pending is not None:
                pending.unlink(missing_ok=True)


if __name__ == "__main__":
    os.umask(0o077)
    try:
        if len(sys.argv) != 2:
            raise ValueError("unsupported_agent")
        configure(sys.argv[1], Path(os.environ["HOME"]), Path(os.environ["XDG_CONFIG_HOME"]))
    except (OSError, ValueError, KeyError):
        print("Oblivion tools could not be added to this agent profile.", file=sys.stderr)
        sys.exit(1)
