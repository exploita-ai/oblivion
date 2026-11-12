#!/bin/bash
# Download a published bundle; its native installer owns installation and state.
set -euo pipefail
export LC_ALL=C
umask 077

fail() {
  printf 'Oblivion: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage: bash install.sh [--version v1.X.Y[-rc.N]]

Install Oblivion for macOS Apple Silicon from its published GitHub release.
Without --version, select the latest stable 1.x release. Older beta releases
and unpublished/draft releases are refused. An RC requires its explicit tag.

The native installer verifies the bundle and platform prerequisites. It owns
the per-user installation and preserves existing encrypted runtime data.
No sudo, Python, Bun or package manager is required by this bootstrap.
USAGE
}

release_version() {
  local pattern='^v(1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))(-rc\.([1-9][0-9]*))?$'
  [[ ${#1} -le 65 && $1 =~ $pattern ]] || fail "Unsupported release tag '$1'; expected v1.X.Y or v1.X.Y-rc.N."
  printf '%s' "${BASH_REMATCH[1]}"
  [[ -z ${BASH_REMATCH[5]:-} ]] || printf '~rc%s' "${BASH_REMATCH[5]}"
}

fetch() {
  # Ignore user curl configuration; only the fixed GitHub release endpoint and
  # its HTTPS asset redirects participate in this download.
  /usr/bin/curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --location --silent --show-error --retry 2 --connect-timeout 15 \
    --max-filesize "$3" --output "$2" --write-out '%{http_code}' "$1"
}

checksum_digest() {
  local line=$1 name=$2 digest=${1:0:64}
  [[ $digest =~ ^[0-9a-f]{64}$ && ${line:64:2} == '  ' && ${line:66} == "$name" ]] \
    || fail "Invalid checksum record for $name."
  printf '%s' "$digest"
}

verify_digest() {
  local actual
  actual=$(/usr/bin/shasum -a 256 "$1") || fail "Cannot hash $1."
  [[ ${actual:0:64} == "$2" ]] || fail "SHA-256 mismatch for ${1##*/}."
}

validate_archive() {
  local archive=$1 root=$2 directory=$3 member line
  /usr/bin/tar -tf "$archive" > "$directory/archive.paths" || fail 'Cannot read bundle archive.'
  /usr/bin/tar -tvf "$archive" > "$directory/archive.types" || fail 'Cannot inspect bundle archive.'
  [[ -s "$directory/archive.paths" ]] || fail 'Empty bundle archive.'
  while IFS= read -r member; do
    member=${member%/}
    [[ $member == "$root" || $member == "$root/"* ]] || fail 'Unexpected archive root.'
    case "/$member/" in
      *'/../'*|*'/./'*|*'//'*) fail 'Unsafe archive path.' ;;
    esac
    [[ $member != *\\* && ! $member =~ [[:cntrl:]] ]] || fail 'Unsupported archive path.'
  done < "$directory/archive.paths"
  while IFS= read -r line; do
    case "$line" in
      -*|d*) ;;
      *) fail 'Bundle archive must contain only regular files and directories.' ;;
    esac
  done < "$directory/archive.types"
}

cleanup() {
  [[ -z ${oblivion_install_work:-} ]] || /bin/rm -rf -- "$oblivion_install_work"
}

main() {
  local tag='' product latest base archive root code expected line part count=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help|-h) usage; return ;;
      --version)
        [[ $# -ge 2 && -z $tag ]] || fail 'Provide --version once, followed by a release tag.'
        tag=$2
        shift 2
        ;;
      *) fail "Unknown argument: $1" ;;
    esac
  done
  [[ $(/usr/bin/uname -s) == Darwin && $(/usr/bin/uname -m) == arm64 ]] \
    || fail 'This installer currently supports native macOS Apple Silicon only.'
  local macos
  macos=$(/usr/bin/sw_vers -productVersion)
  [[ ${macos%%.*} =~ ^[0-9]+$ && ${macos%%.*} -ge 15 ]] || fail 'macOS 15 or newer is required.'
  [[ $EUID -ne 0 ]] || fail 'Run as your normal user, without sudo.'
  if [[ -z $tag ]]; then
    printf 'Finding the latest published stable release…\n' >&2
    latest=$(/usr/bin/curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --location --fail --silent --show-error --retry 2 --connect-timeout 15 \
      --output /dev/null --write-out '%{url_effective}' https://github.com/exploita-ai/oblivion/releases/latest) \
      || fail 'Cannot resolve the latest published release.'
    [[ $latest != https://github.com/exploita-ai/oblivion/releases ]] \
      || fail 'No stable release is published yet. A public RC requires --version with its exact tag.'
    [[ $latest == https://github.com/exploita-ai/oblivion/releases/tag/* ]] || fail 'Unexpected latest release URL.'
    tag=${latest##*/}
    [[ $tag != *-rc.* ]] || fail 'The latest stable release must not be an RC.'
  fi
  product=$(release_version "$tag")
  archive="oblivion-${product/\~/-}-darwin-arm64.tar"
  root="oblivion-$product-darwin-arm64"
  base="https://github.com/exploita-ai/oblivion/releases/download/$tag"
  oblivion_install_work=$(/usr/bin/mktemp -d /tmp/oblivion-install.XXXXXXXX)
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' HUP TERM
  printf 'Downloading Oblivion %s for macOS Apple Silicon…\n' "$tag" >&2
  code=$(fetch "$base/$archive.sha256" "$oblivion_install_work/checksum" 1024) || fail 'Checksum download failed.'
  [[ $code == 200 ]] || fail "Release $tag has no public macOS checksum (HTTP $code). Draft releases are not downloadable here."
  [[ $(/usr/bin/wc -l < "$oblivion_install_work/checksum") -eq 1 ]] || fail 'Expected exactly one checksum record.'
  IFS= read -r line < "$oblivion_install_work/checksum"
  expected=$(checksum_digest "$line" "$archive")
  code=$(fetch "$base/$archive" "$oblivion_install_work/$archive" 1992294400) || fail 'Bundle download failed.'
  if [[ $code == 404 ]]; then
    /bin/rm "$oblivion_install_work/$archive"
    code=$(fetch "$base/$archive.parts.sha256" "$oblivion_install_work/parts" 16384) || fail 'Part inventory download failed.'
    [[ $code == 200 ]] || fail "No complete or split bundle is published for $tag (HTTP $code)."
    : > "$oblivion_install_work/$archive"
    while IFS= read -r line || [[ -n $line ]]; do
      count=$((count + 1))
      [[ $count -le 99 ]] || fail 'Too many bundle parts.'
      printf -v part '%s.part%02d' "$archive" "$count"
      local part_digest
      part_digest=$(checksum_digest "$line" "$part")
      code=$(fetch "$base/$part" "$oblivion_install_work/$part" 1992294400) || fail "Download failed: $part."
      [[ $code == 200 ]] || fail "Missing bundle part $part (HTTP $code)."
      verify_digest "$oblivion_install_work/$part" "$part_digest"
      /bin/cat "$oblivion_install_work/$part" >> "$oblivion_install_work/$archive"
      /bin/rm "$oblivion_install_work/$part"
    done < "$oblivion_install_work/parts"
    [[ $count -ge 2 ]] || fail 'A split bundle requires at least two ordered parts.'
  elif [[ $code != 200 ]]; then
    fail "Bundle download failed (HTTP $code)."
  fi
  verify_digest "$oblivion_install_work/$archive" "$expected"
  validate_archive "$oblivion_install_work/$archive" "$root" "$oblivion_install_work"
  /bin/mkdir "$oblivion_install_work/extracted"
  /usr/bin/tar --no-same-owner --no-same-permissions -xf "$oblivion_install_work/$archive" -C "$oblivion_install_work/extracted"
  local bundle="$oblivion_install_work/extracted/$root"
  [[ -f $bundle/install.sh && -x $bundle/bin/oblivion ]] || fail 'The bundle is missing its native installer.'
  printf 'Checksum verified. Running the native installer…\n' >&2
  /bin/sh "$bundle/install.sh"
  printf 'Oblivion installed. Run ~/.local/bin/oblivion to start.\n'
}

if [[ -z ${BASH_SOURCE[0]:-} || ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
