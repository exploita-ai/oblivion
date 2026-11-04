#!/bin/sh
set -eu
[ "$#" -le 1 ] || { echo 'Usage: install.sh [BUNDLE_DIRECTORY]' >&2; exit 2; }
bundle=${1:-$(dirname "$0")}
bundle=$(CDPATH= cd -P "$bundle" && pwd)
exec "$bundle/bin/oblivion" runtime install-bundle "$bundle"
