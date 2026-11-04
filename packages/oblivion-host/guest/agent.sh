#!/bin/sh
# Official agents execute inside this Safe with their own native histories.
set -eu
umask 077
. /usr/lib/oblivion/guest/safe-environment.sh
agent=${1:-}
case "$agent" in
    codex|claude|opencode2) shift ;;
    *) printf 'Choose codex, claude or opencode2.\n' >&2; exit 64 ;;
esac
if [ ! -x "/usr/lib/oblivion/agents/bin/$agent" ]; then
    printf 'The requested official agent is not installed in this Safe image.\n' >&2
    exit 127
fi
. "/usr/lib/oblivion/guest/agent-profiles/$agent.sh"
# The native process owns its own history. No wrapper rewrites or mirrors it.
exec "/usr/lib/oblivion/agents/bin/$agent" "$@"
