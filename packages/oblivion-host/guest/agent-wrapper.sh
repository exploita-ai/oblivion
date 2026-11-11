#!/bin/sh
set -eu
# argv[0] selects one of three fixed agents; user arguments are never reparsed.
case "${0##*/}" in
    codex|claude|opencode2) exec /usr/lib/oblivion/guest/agent.sh "${0##*/}" "$@" ;;
    *) exit 64 ;;
esac
