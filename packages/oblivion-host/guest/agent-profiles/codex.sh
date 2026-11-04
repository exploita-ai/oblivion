. /usr/lib/oblivion/guest/agent-profiles/common.sh
initialize_agent_config /usr/lib/oblivion/guest/agent-profiles/codex.toml "${CODEX_HOME:-$HOME/.codex}/config.toml"
if [ -d /vault/state/oblivion/native-imports/codex ]; then
    /usr/bin/python3 -I -B /usr/lib/oblivion/history/prepare.py \
        --vault /vault --agent codex --binary /usr/lib/oblivion/agents/bin/codex
fi
