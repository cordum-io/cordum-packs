#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_URL=${CORDUM_GATEWAY_URL:-${CORDUM_GATEWAY:-http://localhost:8081}}
API_KEY=${CORDUM_API_KEY:-}
INGESTER_URL=${INGESTER_URL:-}

workflow_id="incident-enricher.enrich"
input_file="$ROOT/testdata/sample_incident.json"

if [ -n "$INGESTER_URL" ]; then
  response=$(curl -fsS -H "Content-Type: application/json" -d @"$ROOT/testdata/sample_webhook.json" "$INGESTER_URL/webhook/mock")
  pybin="python3"
  if ! command -v "$pybin" >/dev/null 2>&1; then
    pybin="python"
  fi
  run_id=$(echo "$response" | "$pybin" - <<'PY'
import json
import sys

data = json.load(sys.stdin)
print(data.get("run_id", ""))
PY
)
  if [ -z "$run_id" ]; then
    echo "failed to parse run_id from ingester response" >&2
    exit 1
  fi
else
  if ! command -v cordumctl >/dev/null 2>&1; then
    echo "cordumctl is required on PATH when INGESTER_URL is not set" >&2
    exit 1
  fi
  run_id=$(cordumctl run start "$workflow_id" --input "$input_file")
fi

echo "run id: $run_id"

echo "waiting for approval job (post step)..."

deadline=$((SECONDS + 300))
while [ $SECONDS -lt $deadline ]; do
  if "$ROOT/scripts/approve_latest_post.sh" >/dev/null 2>&1; then
    echo "approval granted"
    exit 0
  fi
  sleep 5
  echo "still waiting..."
  if [ -n "$API_KEY" ]; then
    curl -fsS -H "X-API-Key: $API_KEY" "$GATEWAY_URL/api/v1/workflow-runs/$run_id" | tr -d '\n' | head -c 200
    echo
  else
    curl -fsS "$GATEWAY_URL/api/v1/workflow-runs/$run_id" | tr -d '\n' | head -c 200
    echo
  fi
  echo "note: approvals appear only after fetch/summarize workers complete"
  echo
 done

echo "timed out waiting for approval"
exit 1
