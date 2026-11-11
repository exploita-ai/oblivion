#!/bin/sh
set -eu
umask 077
ulimit -c 0
# Created by the app's own tmpfiles rule for its explicitly authorized account.
test -d /run/oblivion-manager
test "$(stat -c '%u' /run/oblivion-manager)" = "$(id -u)"
test "$(stat -c '%a' /run/oblivion-manager)" = 700
test "$(stat -f -c '%T' /run/oblivion-manager)" = tmpfs
export OTUI_ASSET_ROOT=/usr/lib/oblivion/manager
export TMPDIR=/run/oblivion-manager BUN_TMPDIR=/run/oblivion-manager
exec /usr/lib/oblivion/manager/oblivion-manager "$@"
