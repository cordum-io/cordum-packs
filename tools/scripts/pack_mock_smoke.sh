#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CORDUM_ROOT="${CORDUM_ROOT:-"$ROOT/../cordum"}"
CORDUMCTL="${CORDUMCTL:-"$CORDUM_ROOT/bin/cordumctl"}"

GATEWAY_URL="${CORDUM_GATEWAY:-http://localhost:8081}"
API_KEY="${CORDUM_API_KEY:-super-secret-key}"

export CORDUM_GATEWAY="$GATEWAY_URL"
export CORDUM_GATEWAY_URL="$GATEWAY_URL"
export CORDUM_API_KEY="$API_KEY"
export CORDUM_NATS_URL="${CORDUM_NATS_URL:-nats://localhost:4222}"
export CORDUM_REDIS_URL="${CORDUM_REDIS_URL:-redis://localhost:6379}"

MOCK_HOST="${MOCK_HOST:-127.0.0.1}"
MOCK_PORT="${MOCK_PORT:-9999}"
MOCK_BASE="http://${MOCK_HOST}:${MOCK_PORT}"
WORKER_STARTUP_DELAY="${WORKER_STARTUP_DELAY:-10}"
JOB_WAIT_ATTEMPTS="${JOB_WAIT_ATTEMPTS:-120}"

LOG_DIR="$ROOT/.tmp/pack-mock"
mkdir -p "$LOG_DIR"

if [[ ! -x "$CORDUMCTL" ]]; then
  echo "cordumctl not found at $CORDUMCTL" >&2
  exit 1
fi

HTTP_MOCK_PID=""
WORKER_PID=""

cleanup() {
  if [[ -n "$HTTP_MOCK_PID" ]]; then
    kill "$HTTP_MOCK_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

start_http_mock() {
  python3 "$ROOT/tools/mock/http_server.py" --host "$MOCK_HOST" --port "$MOCK_PORT" --quiet >"$LOG_DIR/http-mock.log" 2>&1 &
  HTTP_MOCK_PID=$!
  sleep 0.5
}

submit_job() {
  local topic="$1"
  local json="$2"
  local tmp
  tmp=$(mktemp)
  printf '%s' "$json" >"$tmp"
  local job_id
  job_id=$("$CORDUMCTL" job submit --topic "$topic" --prompt "mock test" --input "$tmp")
  rm -f "$tmp"
  printf '%s' "$job_id"
}

wait_job() {
  local job_id="$1"
  local state=""
  for _ in $(seq 1 "$JOB_WAIT_ATTEMPTS"); do
    state=$("$CORDUMCTL" job status "$job_id" 2>/dev/null || true)
    if [[ "$state" == "COMPLETED" || "$state" == "SUCCEEDED" || "$state" == "FAILED" ]]; then
      break
    fi
    sleep 1
  done
  printf '%s' "$state"
}

start_worker() {
  local name="$1"
  local dir="$2"
  local cmd="$3"
  shift 3
  local log="$LOG_DIR/${name}.log"
  (cd "$dir" && env "$@" setsid go run "$cmd" >"$log" 2>&1) &
  WORKER_PID=$!
}

stop_worker() {
  local pid="$1"
  if [[ -z "$pid" ]]; then
    return
  fi
  kill -TERM -"$pid" >/dev/null 2>&1 || true
  kill -TERM "$pid" >/dev/null 2>&1 || true
  sleep 0.5
  kill -KILL -"$pid" >/dev/null 2>&1 || true
}

run_worker_test() {
  local name="$1"
  local dir="$2"
  local cmd="$3"
  local topic="$4"
  local json="$5"
  shift 5

  echo "== $name =="
  local pid
  start_worker "$name" "$dir" "$cmd" "$@"
  pid=$WORKER_PID
  sleep "$WORKER_STARTUP_DELAY"

  local job_id
  if ! job_id=$(submit_job "$topic" "$json"); then
    echo "failed to submit job for $name" >&2
    stop_worker "$pid"
    return 1
  fi

  local state
  state=$(wait_job "$job_id")
  if [[ "$state" != "COMPLETED" && "$state" != "SUCCEEDED" ]]; then
    echo "$name failed (state=$state)" >&2
    "$CORDUMCTL" job logs "$job_id" || true
    stop_worker "$pid"
    return 1
  fi
  echo "$name ok"
  stop_worker "$pid"
}

start_http_mock

failures=0

run_worker_test "slack" "$ROOT/packs/slack" "./cmd/cordum-slack" "job.slack.read" \
  '{"profile":"default","action":"auth.test","params":{}}' \
  CORDUM_SLACK_BASE_URL="$MOCK_BASE/slack" \
  CORDUM_SLACK_TOKEN="mock-token" || failures=$((failures+1))

run_worker_test "github" "$ROOT/packs/github" "./cmd/cordum-github" "job.github.read" \
  '{"profile":"default","action":"issues.list","owner":"acme","repo":"demo","per_page":1}' \
  CORDUM_GITHUB_BASE_URL="$MOCK_BASE/github" \
  CORDUM_GITHUB_TOKEN="mock-token" || failures=$((failures+1))

run_worker_test "gitlab" "$ROOT/packs/gitlab" "./cmd/cordum-gitlab" "job.gitlab.read" \
  '{"profile":"default","action":"projects.list","params":{}}' \
  CORDUM_GITLAB_BASE_URL="$MOCK_BASE/gitlab" \
  CORDUM_GITLAB_TOKEN="mock-token" || failures=$((failures+1))

run_worker_test "jira" "$ROOT/packs/jira" "./cmd/cordum-jira" "job.jira.read" \
  '{"profile":"default","action":"projects.list","params":{}}' \
  CORDUM_JIRA_BASE_URL="$MOCK_BASE/jira" \
  CORDUM_JIRA_USERNAME="mock-user" \
  CORDUM_JIRA_TOKEN="mock-token" || failures=$((failures+1))

run_worker_test "msteams" "$ROOT/packs/msteams" "./cmd/cordum-msteams" "job.msteams.read" \
  '{"profile":"default","action":"teams.list","params":{}}' \
  CORDUM_MSTEAMS_BASE_URL="$MOCK_BASE/msteams" \
  CORDUM_MSTEAMS_TOKEN="mock-token" || failures=$((failures+1))

run_worker_test "opentelemetry" "$ROOT/packs/opentelemetry" "./cmd/cordum-opentelemetry" "job.opentelemetry.read" \
  '{"profile":"default","action":"services.list","params":{}}' \
  CORDUM_OTEL_BASE_URL="$MOCK_BASE/opentelemetry" \
  CORDUM_OTEL_TOKEN="mock-token" || failures=$((failures+1))

run_worker_test "prometheus" "$ROOT/packs/prometheus-query" "./cmd/cordum-prometheus-query" "job.prometheus.read" \
  '{"profile":"default","action":"labels.list","params":{}}' \
  CORDUM_PROMETHEUS_BASE_URL="$MOCK_BASE/prometheus" || failures=$((failures+1))

run_worker_test "sentry" "$ROOT/packs/sentry" "./cmd/cordum-sentry" "job.sentry.read" \
  '{"profile":"default","action":"organizations.list","params":{}}' \
  CORDUM_SENTRY_BASE_URL="$MOCK_BASE/sentry" \
  CORDUM_SENTRY_TOKEN="mock-token" || failures=$((failures+1))

run_worker_test "vault" "$ROOT/packs/vault" "./cmd/cordum-vault" "job.vault.read" \
  '{"profile":"default","action":"auth.token.lookup","params":{}}' \
  CORDUM_VAULT_BASE_URL="$MOCK_BASE/vault" \
  CORDUM_VAULT_TOKEN="mock-token" || failures=$((failures+1))

run_worker_test "kubernetes-triage" "$ROOT/packs/kubernetes-triage" "./cmd/cordum-kubernetes-triage" "job.kubernetes-triage.read" \
  '{"profile":"default","action":"nodes.list","params":{}}' \
  CORDUM_K8S_KUBECTL_PATH="$ROOT/tools/mock/kubectl" || failures=$((failures+1))

run_worker_test "terraform" "$ROOT/packs/terraform" "./cmd/cordum-terraform" "job.terraform.read" \
  '{"profile":"default","action":"validate.run","params":{"dir":"'$ROOT'/tools/mock/terraform-workdir"}}' \
  CORDUM_TERRAFORM_PATH="$ROOT/tools/mock/terraform" \
  CORDUM_TERRAFORM_WORKDIR="$ROOT/tools/mock/terraform-workdir" || failures=$((failures+1))

run_worker_test "mcp-bridge" "$ROOT/packs/mcp-bridge" "./cmd/cordum-mcp-bridge" "job.mcp-bridge.tool" \
  '{"tool":"cordum.workflow.run","args":{"workflow_id":"hello-pack.echo","dry_run":true}}' || failures=$((failures+1))

run_worker_test "mcp-client" "$ROOT/packs/mcp-client" "./cmd/cordum-mcp-client" "job.mcp-client.call" \
  '{"transport":"stdio","command":"/usr/bin/env","args":["python3","'$ROOT'/tools/mock/mcp_stdio_server.py"],"method":"tools/list"}' \
  CORDUM_MCP_CLIENT_ALLOW_INLINE_SERVER="true" || failures=$((failures+1))

# Webhooks pack uses an HTTP server instead of an outbound API.
{
  echo "== webhooks =="
  log="$LOG_DIR/webhooks.log"
  (cd "$ROOT/packs/webhooks" && env \
    CORDUM_WEBHOOKS_BIND=":8099" \
    CORDUM_WEBHOOKS_ROUTES='[{"id":"mock","path":"/webhooks/mock","method":"POST","workflow_id":"hello-pack.echo","signature_type":"none"}]' \
    go run ./cmd/cordum-webhooks >"$log" 2>&1 & echo $! >"$LOG_DIR/webhooks.pid")
  webhooks_pid=$(cat "$LOG_DIR/webhooks.pid")
  sleep 1
  curl -sS -X POST "http://127.0.0.1:8099/webhooks/mock" -H "Content-Type: application/json" -d '{"message":"hello"}' >/dev/null || failures=$((failures+1))
  stop_worker "$webhooks_pid"
}

if [[ "$failures" -ne 0 ]]; then
  echo "$failures pack test(s) failed" >&2
  exit 1
fi

echo "all mock smoke tests passed"
