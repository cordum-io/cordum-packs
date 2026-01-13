#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$ROOT/scripts/bundle.sh"
VERSION=$(awk '/version:/ {print $2; exit}' "$ROOT/pack/pack.yaml" | tr -d '"')
ARCHIVE="$ROOT/dist/incident-enricher-${VERSION}.tgz"

cordumctl pack install "$ARCHIVE" --upgrade "${@}"
