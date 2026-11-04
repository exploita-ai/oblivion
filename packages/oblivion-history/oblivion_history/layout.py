"""Explicit Safe-local agent roots. A different test home never adopts host XDG."""

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class Layout:
    home: Path
    data: Path
    config: Path
    cache: Path
    state: Path
    codex: Path
    claude: Path

    @classmethod
    def resolve(
        cls,
        home,
        *,
        data=None,
        config=None,
        cache=None,
        state=None,
        codex=None,
        claude=None,
    ):
        home = Path(home).resolve()
        same_home = Path(os.environ.get("HOME", "/nonexistent")).resolve() == home

        def root(value, variable, fallback):
            return Path(
                value or (os.environ.get(variable) if same_home else None) or fallback
            ).resolve()

        return cls(
            home,
            root(data, "XDG_DATA_HOME", home / ".local/share"),
            root(config, "XDG_CONFIG_HOME", home / ".config"),
            root(cache, "XDG_CACHE_HOME", home / ".cache"),
            root(state, "XDG_STATE_HOME", home / ".local/state"),
            root(codex, "CODEX_HOME", home / ".codex"),
            root(claude, "CLAUDE_CONFIG_DIR", home / ".claude"),
        )

    def environment(self):
        environment = {
            key: os.environ[key]
            for key in ("PATH", "TMPDIR", "LANG", "LC_ALL")
            if key in os.environ
        }
        environment.update(
            HOME=str(self.home),
            XDG_DATA_HOME=str(self.data),
            XDG_CONFIG_HOME=str(self.config),
            XDG_CACHE_HOME=str(self.cache),
            XDG_STATE_HOME=str(self.state),
            CODEX_HOME=str(self.codex),
            CLAUDE_CONFIG_DIR=str(self.claude),
            OTEL_SDK_DISABLED="true",
            OPENCODE_DISABLE_FREE_MODELS="1",
        )
        return environment
