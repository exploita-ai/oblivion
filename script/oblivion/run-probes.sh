#!/bin/sh
set -eu

# Run from any directory. Never load the user's OpenCode profile or API key.
oblivion_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
oblivion_output="$oblivion_root/artifacts/oblivion-phase0"
mkdir -p "$oblivion_output/temp-probe"

docker run --rm --network none --log-driver none --cap-add SYS_PTRACE --cap-add NET_RAW \
  --mount "type=bind,source=$oblivion_root,target=/work,readonly" \
  --mount "type=bind,source=$oblivion_output,target=/out" \
  --workdir /work oblivion-audit:v2.1.4 \
  python3 /work/script/oblivion/capture-network.py

docker run --rm --network none --log-driver none --cap-add SYS_PTRACE \
  --mount "type=bind,source=$oblivion_root,target=/work,readonly" \
  --mount "type=bind,source=$oblivion_output,target=/out" \
  --workdir /work -e TMPDIR=/out/temp-probe oblivion-audit:v2.1.4 \
  strace -f -yy -s 256 -e trace=%file,%network -o /out/temp-syscalls.log \
  bun --preload /work/packages/cli/node_modules/@opentui/solid/scripts/preload.js \
  --tsconfig-override /work/packages/cli/tsconfig.json /work/script/oblivion/temp-probe.mjs

python3 "$oblivion_root/script/oblivion/summarize.py"
