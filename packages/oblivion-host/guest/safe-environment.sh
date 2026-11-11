# Sourced by native agents and every login shell inside this Safe.
test "$(id -u)" = 1000
mountpoint -q /vault
export HOME=/vault/home
export XDG_CONFIG_HOME=/vault/config
export XDG_STATE_HOME=/vault/state
export XDG_DATA_HOME=/vault/state
export XDG_CACHE_HOME=/tmp/oblivion-cache
export TMPDIR=/tmp
. /usr/lib/oblivion/guest/session-environment.sh
if [ -r /run/oblivion-network/token ]; then
    . /usr/lib/oblivion/guest/tools-proxy.sh
fi
