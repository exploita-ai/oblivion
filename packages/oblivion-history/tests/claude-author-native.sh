#!/bin/sh
# IMAGE supplies Python 3.11+, glibc and a shell; AGENTS is an already installed
# pinned Linux agents tree. No downloads or provider credentials are required.
set -eu
test "$#" = 2 || { printf 'Usage: %s IMAGE AGENTS_DIRECTORY\n' "$0" >&2; exit 64; }
package=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
guest=$(CDPATH= cd -- "$package/../oblivion-host/guest" && pwd)
agents=$(CDPATH= cd -- "$2" && pwd)
docker run --rm --network none --read-only --user 1000:1000 \
    --tmpfs /tmp:rw,mode=1777 \
    --tmpfs /run/oblivion-author:rw,uid=1000,gid=1000,mode=0700 \
    --mount "type=bind,src=$package,dst=/usr/lib/oblivion/history,readonly" \
    --mount "type=bind,src=$guest/claude-managed-settings.json,dst=/etc/claude-code/managed-settings.json,readonly" \
    --mount "type=bind,src=$agents,dst=/agents,readonly" \
    --entrypoint python3 "$1" -B /usr/lib/oblivion/history/tests/claude-author-native.py -v
