# Mock pack testing (no external credentials)

This guide lets you exercise pack workflows and workers without real third‑party
accounts. It uses local mock servers plus lightweight CLI stubs for packs that
shell out to `kubectl` or `terraform`.

## Prereqs

- Cordum stack running (gateway on `http://localhost:8081`).
- `cordumctl` available (default: `../cordum/bin/cordumctl`).
- Packs installed (see each pack README for install paths).

Set these once:

```bash
export CORDUM_GATEWAY=http://localhost:8081
export CORDUM_API_KEY=super-secret-key
```

## Start mock services

```bash
# From cordum-packs
python3 tools/mock/http_server.py --port 9999
```

Optional mocks:

```bash
# MCP stdio server for the mcp-client pack
python3 tools/mock/mcp_stdio_server.py

# Mock kubectl for kubernetes-triage
export CORDUM_K8S_KUBECTL_PATH=tools/mock/kubectl

# Mock terraform for terraform pack
export CORDUM_TERRAFORM_PATH=tools/mock/terraform
export CORDUM_TERRAFORM_WORKDIR=tools/mock/terraform-workdir
```

## Automated smoke test

```bash
# From cordum-packs
./tools/scripts/pack_mock_smoke.sh
```

The script starts the mock HTTP server, runs each worker locally, submits a
sample job, and checks job completion.

## Pack-by-pack quick inputs

Use these when running workers manually (examples use the mock HTTP server at
`http://localhost:9999/<service>`).

### HTTP-based workers

| Pack | Job topic | Base URL env | Token env | Example action |
| --- | --- | --- | --- | --- |
| slack | `job.slack.read` | `CORDUM_SLACK_BASE_URL` | `CORDUM_SLACK_TOKEN` | `auth.test` |
| github | `job.github.read` | `CORDUM_GITHUB_BASE_URL` | `CORDUM_GITHUB_TOKEN` | `issues.list` |
| gitlab | `job.gitlab.read` | `CORDUM_GITLAB_BASE_URL` | `CORDUM_GITLAB_TOKEN` | `projects.list` |
| jira | `job.jira.read` | `CORDUM_JIRA_BASE_URL` | `CORDUM_JIRA_TOKEN` | `projects.list` |
| msteams | `job.msteams.read` | `CORDUM_MSTEAMS_BASE_URL` | `CORDUM_MSTEAMS_TOKEN` | `teams.list` |
| opentelemetry | `job.opentelemetry.read` | `CORDUM_OTEL_BASE_URL` | `CORDUM_OTEL_TOKEN` | `services.list` |
| prometheus-query | `job.prometheus.read` | `CORDUM_PROMETHEUS_BASE_URL` | (optional) | `labels.list` |
| sentry | `job.sentry.read` | `CORDUM_SENTRY_BASE_URL` | `CORDUM_SENTRY_TOKEN` | `organizations.list` |
| vault | `job.vault.read` | `CORDUM_VAULT_BASE_URL` | `CORDUM_VAULT_TOKEN` | `auth.token.lookup` |

Example (Slack):

```bash
# run worker (cordum-packs/packs/slack)
CORDUM_SLACK_BASE_URL=http://localhost:9999/slack \
CORDUM_SLACK_TOKEN=mock-token \
go run ./cmd/cordum-slack

# submit job (cordum)
./bin/cordumctl job submit --topic job.slack.read \
  --input '{"action":"auth.test","params":{}}'
```

### CLI-based workers

- **kubernetes-triage**
  - Job topic: `job.kubernetes-triage.read`
  - Mock `kubectl`: `CORDUM_K8S_KUBECTL_PATH=tools/mock/kubectl`
  - Example input: `{"action":"nodes.list","params":{}}`

- **terraform**
  - Job topic: `job.terraform.read`
  - Mock `terraform`: `CORDUM_TERRAFORM_PATH=tools/mock/terraform`
  - Working dir: `CORDUM_TERRAFORM_WORKDIR=tools/mock/terraform-workdir`
  - Example input: `{"action":"validate.run","params":{"dir":"/abs/path/to/terraform-workdir"}}`

### MCP packs

- **mcp-bridge**
  - Job topic: `job.mcp-bridge.tool`
  - Example input: `{"tool":"cordum.workflow.run","args":{"workflow_id":"hello-pack.echo","dry_run":true}}`

- **mcp-client**
  - Job topic: `job.mcp-client.call`
  - Allow inline server: `CORDUM_MCP_CLIENT_ALLOW_INLINE_SERVER=true`
  - Example input:
    ```json
    {
      "transport": "stdio",
      "command": "/usr/bin/env",
      "args": ["python3", "/abs/path/to/tools/mock/mcp_stdio_server.py"],
      "method": "tools/list"
    }
    ```

### Webhooks

Run the server and POST a payload to the mock route:

```bash
# cordum-packs/packs/webhooks
CORDUM_WEBHOOKS_BIND=:8099 \
CORDUM_WEBHOOKS_ROUTES='[{"id":"mock","path":"/webhooks/mock","method":"POST","workflow_id":"hello-pack.echo","signature_type":"none"}]' \
go run ./cmd/cordum-webhooks

curl -X POST http://localhost:8099/webhooks/mock \
  -H "Content-Type: application/json" \
  -d '{"message":"hello"}'
```

## Packs without workers in this repo

These packs install workflows/schemas and assume a compatible worker is deployed
elsewhere. You can still install them and validate policy simulations with
`cordumctl pack verify <id>`.

- aws
- azure
- cron-triggers
- datadog
- gcp
- pagerduty
- servicenow
- hello-pack (example workflow only)

## Known blockers

- `incident-enricher` requires core `>= 0.6.0`. The current gateway in this
  environment is `v0.1.3`, so install and mock testing are blocked until core is
  upgraded.
