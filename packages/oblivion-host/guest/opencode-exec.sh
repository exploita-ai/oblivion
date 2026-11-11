#!/bin/sh
# The sole native OpenCode entrypoint. Interactive clients arrive after the
# scope/UID handoff; fixed standalone jobs retain their original service cgroup.
set -eu
umask 077
. /usr/lib/oblivion/guest/safe-environment.sh
. /usr/lib/oblivion/guest/agent-profiles/opencode2.sh
exec /usr/lib/oblivion/agents/bin/opencode2 "$@"
