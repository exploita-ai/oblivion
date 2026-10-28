#!/bin/sh
# Shared by the agent and terminal; durable user state stays in this vault.
export EDITOR=nano VISUAL=nano PAGER=less
export HISTFILE=/dev/null LESSHISTFILE=/dev/null SQLITE_HISTORY=/dev/null
export NODE_REPL_HISTORY=/dev/null PYTHON_HISTORY=/dev/null
export PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
PIP_CACHE_DIR="$XDG_CACHE_HOME/pip"
npm_config_cache="$XDG_CACHE_HOME/npm"
npm_config_prefix="$HOME/.local"
export PIP_CACHE_DIR npm_config_cache npm_config_prefix
export npm_config_logs_max=0 npm_config_update_notifier=false
export npm_config_audit=false npm_config_fund=false
PATH="$HOME/.local/bin:$PATH"
export PATH
# Native Node support applies to built-in fetch and HTTP(S) clients. Programs
# with their own networking stacks still need proxy support and remain subject
# to the VM's route isolation and the gateway's destination policy.
export NODE_USE_ENV_PROXY=1
