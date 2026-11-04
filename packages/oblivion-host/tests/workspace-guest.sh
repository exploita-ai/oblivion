#!/bin/sh
# Reproducible isolated guest fixture. IMAGE needs Python3, tmux, bash,
# mountpoint and setpriv; no native agent/provider is contacted.
set -eu
test "$#" -eq 1 || { printf 'Usage: workspace-guest.sh IMAGE\n' >&2; exit 64; }
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
exec docker run --rm -i --network=none \
    --mount "type=bind,src=$root,dst=/src,readonly" \
    --tmpfs /vault:rw,exec,mode=0700 --tmpfs /tmp:rw,exec,mode=1777 \
    --entrypoint sh "$1" -s <<'SH'
set -eu
test ! -e /usr/bin/codex
mkdir -p /usr/lib/oblivion/guest /usr/lib/oblivion/agents/bin /usr/lib/oblivion/history \
    /etc/oblivion /etc/profile.d /run/oblivion-history /run/oblivion-workspace \
    /vault/home/.oblivion-history /vault/workspace/project /vault/config /vault/state /tmp/oblivion-cache
cp -R /src/packages/oblivion-host/guest/. /usr/lib/oblivion/guest/
cp -R /src/packages/oblivion-history/. /usr/lib/oblivion/history/
chmod 0755 /usr/lib/oblivion/guest/*.sh
cp /usr/lib/oblivion/guest/shell-profile.sh /etc/profile.d/oblivion-safe.sh
cp /usr/lib/oblivion/guest/tmux.conf /etc/oblivion/tmux.conf
ln -s /usr/lib/oblivion/guest/agent-wrapper.sh /usr/bin/codex
cat > /usr/lib/oblivion/agents/bin/codex <<'PY'
#!/usr/bin/python3
import json,os,sys
print(json.dumps({"argv":sys.argv[1:],"cwd":os.getcwd(),"home":os.environ.get("HOME"),"config":os.environ.get("XDG_CONFIG_HOME"),"telemetry":os.environ.get("OTEL_SDK_DISABLED")}))
sys.exit(23)
PY
chmod 0755 /usr/lib/oblivion/agents/bin/codex
chown -R 1000:1000 /vault /run/oblivion-history /run/oblivion-workspace /tmp/oblivion-cache
chmod 0700 /run/oblivion-history /run/oblivion-workspace
exec setpriv --reuid=1000 --regid=1000 --clear-groups \
    python3 -B /src/packages/oblivion-host/tests/workspace-guest.py
SH
