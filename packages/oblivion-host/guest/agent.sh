#!/bin/sh
# Official agents execute inside this Safe with their own native histories.
set -eu
umask 077
test "$(id -u)" = 1000
mountpoint -q /vault
export HOME=/vault/home
export XDG_CONFIG_HOME=/vault/config
export XDG_STATE_HOME=/vault/state
export XDG_DATA_HOME=/vault/state
export XDG_CACHE_HOME=/tmp/oblivion-cache
export TMPDIR=/tmp
. /usr/lib/oblivion/guest/session-environment.sh
if [ -r /run/oblivion-api/token ]; then
    . /usr/lib/oblivion/guest/tools-proxy.sh
fi
cd /vault/workspace
agent=${1:-}
case "$agent" in
    codex|claude|opencode2) shift ;;
    *) printf 'Choose codex, claude or opencode2.\n' >&2; exit 64 ;;
esac
if [ ! -x "/usr/bin/$agent" ]; then
    printf 'The requested official agent is not installed in this Safe image.\n' >&2
    exit 127
fi
. "/usr/lib/oblivion/guest/agent-profiles/$agent.sh"
# No shell evaluation, argument rewriting, shared server or automatic resume.
exec "/usr/bin/$agent" "$@"
