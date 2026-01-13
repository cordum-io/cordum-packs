#!/usr/bin/env bash
set -euo pipefail

GATEWAY_URL=${CORDUM_GATEWAY_URL:-${CORDUM_GATEWAY:-http://localhost:8081}}
API_KEY=${CORDUM_API_KEY:-}

headers=()
if [ -n "$API_KEY" ]; then
  headers+=("-H" "X-API-Key: $API_KEY")
fi

response=$(curl -fsS "${headers[@]}" "$GATEWAY_URL/api/v1/approvals?limit=100")

pybin="python3"
if ! command -v "$pybin" >/dev/null 2>&1; then
  pybin="python"
fi

job_id=$(echo "$response" | "$pybin" - <<'PY'
import json
import sys

data = json.load(sys.stdin)
items = data.get("items", [])
filtered = []
for item in items:
    job = item.get("job", {})
    if job.get("topic") == "job.incident-enricher.post":
        filtered.append(job)
if not filtered:
    sys.exit(2)
filtered.sort(key=lambda j: j.get("updated_at", 0), reverse=True)
print(filtered[0].get("id", ""))
PY
) || {
  echo "no pending approvals for job.incident-enricher.post" >&2
  exit 1
}

if [ -z "$job_id" ]; then
  echo "no pending approvals for job.incident-enricher.post" >&2
  exit 1
fi

curl -fsS -X POST "${headers[@]}" "$GATEWAY_URL/api/v1/approvals/${job_id}/approve" >/dev/null

echo "approved job ${job_id}"
