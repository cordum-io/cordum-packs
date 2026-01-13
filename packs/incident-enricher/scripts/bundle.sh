#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=$(awk '/version:/ {print $2; exit}' "$ROOT/pack/pack.yaml" | tr -d '"')
DIST="$ROOT/dist"
ARCHIVE="$DIST/incident-enricher-${VERSION}.tgz"

mkdir -p "$DIST"

tar -czf "$ARCHIVE" -C "$ROOT/pack" .

echo "bundle: $ARCHIVE"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$ARCHIVE"
fi
