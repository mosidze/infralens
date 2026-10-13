#!/usr/bin/env bash
# Builds static binaries for linux and macOS (amd64, arm64) into dist/, with
# checksums. Pure Go, no cgo: the result runs on a bare machine.
#   VERSION=1.0.0 scripts/release.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT=dist
rm -rf "$OUT" && mkdir -p "$OUT"

go vet ./...
go test ./...

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os="${target%/*}"; arch="${target#*/}"
  name="infralens-${VERSION}-${os}-${arch}"
  dir="$OUT/$name"
  mkdir -p "$dir"
  echo "building $name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "$dir/infralens" .
  cp README.md THIRD_PARTY.md "$dir/"
  tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
  rm -rf "$dir"
done

( cd "$OUT" && sha256sum ./*.tar.gz > SHA256SUMS )
echo "done:"; ls -1 "$OUT"
