#!/usr/bin/env bash
# Builds release assets into dist/ (run on Windows with Git Bash, Go and Wails):
#   txlite-linux-amd64, txlite-linux-arm64, txlite-windows-x64.zip, SHA256SUMS
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf dist && mkdir -p dist
go mod vendor && python scripts/patch-vendor.py
go test -tags=http2legacy -count=1 ./internal/share/ ./internal/lite/ ./internal/server/ >/dev/null
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -tags=http2legacy -trimpath -ldflags='-s -w' -o "dist/txlite-linux-$arch" ./cmd/txlite
done
(cd gui && go mod vendor && python ../scripts/patch-vendor.py && wails build -m -nosyncgomod -s -skipbindings -tags http2legacy -webview2 error -o txlite-client.exe)
stage=dist/txlite-windows-x64
mkdir -p "$stage"
cp gui/build/bin/txlite-client.exe "$stage/"
cp -r gui/runtime "$stage/runtime"
(cd dist && python -c "import shutil;shutil.make_archive('txlite-windows-x64','zip','txlite-windows-x64')")
rm -rf "$stage"
(cd dist && sha256sum txlite-linux-amd64 txlite-linux-arm64 txlite-windows-x64.zip | sed 's/ \*/  /' > SHA256SUMS)
cat dist/SHA256SUMS
