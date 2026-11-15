#!/usr/bin/env bash
# Builds release binaries into dist/ for Windows, Linux and macOS, with a
# SHA-256 list. The build is pure Go (no C compiler needed) and reproducible:
# the same source and Go version give byte-identical binaries, so a published
# hash can be checked by rebuilding.
#
#   bash scripts/build.sh           all platforms
#   bash scripts/build.sh linux     only targets whose name contains "linux"
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(sed -n 's/^const ToolVersion = "\(.*\)"/\1/p' internal/store/store.go)"
[ -n "$VERSION" ] || { echo "could not read ToolVersion"; exit 1; }
rm -rf dist && mkdir -p dist
for target in windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  case "$target" in *"${1:-}"*) ;; *) continue ;; esac
  os="${target%/*}"; arch="${target#*/}"
  out="dist/atropos-$VERSION-$os-$arch"
  [ "$os" = windows ] && out="$out.exe"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o "$out" .
  echo "built $out"
done
(cd dist && sha256sum atropos-* > SHA256SUMS && cat SHA256SUMS)
