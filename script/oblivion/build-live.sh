#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
root=$(pwd)
bun=${OBLIVION_BUN:-bun}
test "$("$bun" --version)" = 1.4.4 || { printf '%s\n' 'Bun 1.4.4 is required.' >&2; exit 1; }
arch=${OBLIVION_ARCH:-amd64}
case "$arch" in
    amd64) out="$root/artifacts/oblivion-beta-iso"; target=opencode-linux-x64-baseline; client=cli-linux-x64-baseline; manager=bun-linux-x64;;
    arm64) out="$root/artifacts/oblivion-arm-iso"; target=opencode-linux-arm64; client=cli-linux-arm64; manager=bun-linux-arm64;;
    *) printf '%s\n' 'OBLIVION_ARCH must be amd64 or arm64.' >&2; exit 1;;
esac
mkdir -p "$out"
image=${OBLIVION_ISO_OUTPUT:-"$out/image"}
(
    cd packages/oblivion-manager
    "$bun" run script/build.ts "--target=$manager"
)
(
    cd packages/cli
    OPENCODE_CHANNEL=oblivion-beta TURBO_TELEMETRY_DISABLED=1 "$bun" run script/build.ts \
        "--target=$target" --skip-install --skip-web-ui --oblivion --outdir="$out/client"
)
OBLIVION_BUILD_DIR="$out" OBLIVION_CLIENT="$client" OBLIVION_BUILD_ARCH="$arch" python3 - <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import os

root = Path(os.environ['OBLIVION_BUILD_DIR'])
with (root / 'client' / os.environ['OBLIVION_CLIENT'] / 'bin/opencode').open('rb') as binary:
    digest = hashlib.file_digest(binary, 'sha256').hexdigest()
files = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard', 'packages', 'script', 'patches', 'bun.lock', 'package.json']).decode().split('\0')
manifest = ''.join(hashlib.sha256(Path(name).read_bytes()).hexdigest() + '  ' + name + '\n'
    for name in sorted(files) if name and Path(name).is_file())
(root / 'client-sources.sha256').write_text(manifest)
(root / 'client-evidence.json').write_text(json.dumps({
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip(),
    'source_manifest_sha256': hashlib.sha256(manifest.encode()).hexdigest(),
    'source_manifest': 'client-sources.sha256',
    'binary_sha256': digest, 'architecture': os.environ['OBLIVION_BUILD_ARCH'], 'profile': 'oblivion',
    'scope': 'Development ISO build; not a signed release.'
}, indent=2) + '\n')
PY
docker buildx build --platform "linux/$arch" --file script/oblivion/Dockerfile.vm-lab \
    --target "${OBLIVION_IMAGE_TARGET:-beta-iso}" \
    --build-arg "OPENCODE_BINARY=${out#"$root/"}/client/$client/bin/opencode" \
    --build-arg "OPENCODE_BUILD_EVIDENCE=${out#"$root/"}/client-evidence.json" \
    --build-arg "MANAGER_BINARY=artifacts/oblivion-manager/$manager/oblivion-manager" \
    --build-arg "MANAGER_ASSETS=artifacts/oblivion-manager/$manager/assets" \
    --output "type=local,dest=$image" .
cp "$out/client-sources.sha256" "$image/client-sources.sha256"
(cd "$image" && shasum -a 256 client-sources.sha256 >> SHA256SUMS)
printf 'Image directory: %s\n' "$image"
