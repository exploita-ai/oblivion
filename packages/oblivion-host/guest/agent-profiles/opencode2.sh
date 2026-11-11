. /usr/lib/oblivion/guest/agent-profiles/common.sh
export OPENCODE_DISABLE_AUTOUPDATE=1
initialize_agent_config /usr/lib/oblivion/guest/agent-profiles/opencode2.json "$XDG_CONFIG_HOME/opencode/opencode.json"
/usr/bin/python3 -B /usr/lib/oblivion/guest/native-tools/configure.py opencode2
if [ -d /vault/state/oblivion/native-imports/opencode2 ]; then
    /usr/bin/python3 -I -B /usr/lib/oblivion/history/prepare.py \
        --vault /vault --agent opencode2 --binary /usr/lib/oblivion/agents/bin/opencode2
fi
