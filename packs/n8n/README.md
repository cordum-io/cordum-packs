# n8n Pack

Bidirectional n8n integration for Cordum.

- **Outbound:** Cordum triggers n8n workflows, lists workflows/executions, and activates/deactivates workflows through the n8n REST API.
- **Inbound:** n8n can call a signed webhook exposed by this pack, which starts a mapped Cordum workflow through the Gateway API.

## Topics & Policy

| Topic | Actions | Policy |
|-------|---------|--------|
| `job.n8n.read` | `workflow.list`, `workflow.get`, `execution.get`, `execution.list`, `credentials.list` | ALLOW |
| `job.n8n.write` | `workflow.execute`, `workflow.activate`, `workflow.deactivate` | REQUIRE_APPROVAL |

Requests sent to the wrong topic are rejected by the worker.

## Actions

| Action | Description |
|--------|-------------|
| `workflow.list` | List available n8n workflows |
| `workflow.get` | Fetch a workflow definition by id |
| `workflow.execute` | Trigger a workflow with input payload |
| `workflow.activate` | Activate a workflow |
| `workflow.deactivate` | Deactivate a workflow |
| `execution.get` | Fetch an execution by id |
| `execution.list` | List executions with optional filters |
| `credentials.list` | List available credentials |

## Authentication

The pack uses the n8n REST API with the `X-N8N-API-KEY` header. Configure:

- `N8N_API_URL`
- `N8N_API_KEY`

You can also define multiple profiles with different n8n base URLs, API keys, and workflow allow/deny rules.

## Quick Start

```bash
# 1. Configure n8n access
export N8N_API_URL=https://n8n.example.com
export N8N_API_KEY=your-api-key

# 2. Optional: enable reverse n8n -> Cordum triggers
export CORDUM_N8N_WEBHOOK_ENABLED=true
export CORDUM_N8N_WEBHOOK_SECRET=shared-secret
export CORDUM_N8N_WEBHOOK_WORKFLOW_MAP='{"/hooks/inbound":"cordum-workflow-id"}'

# 3. Build and run
cd packs/n8n
go build -o cordum-n8n ./cmd/cordum-n8n/
./cordum-n8n
```

## Example: Execute an n8n Workflow

The pack ships an example workflow id: `n8n-bridge-workflow`.

Submit to `job.n8n.write`:

```json
{
  "action": "workflow.execute",
  "params": {
    "workflow_id": "123",
    "payload": {
      "customer_id": "cus_42",
      "event": "invoice.created"
    },
    "wait_for_completion": true,
    "poll_interval_ms": 2000,
    "completion_timeout_sec": 60
  }
}
```

When `wait_for_completion` is true, the worker polls the execution until it reaches a terminal state or the configured timeout expires.

## Example: List Workflows

Submit to `job.n8n.read`:

```json
{
  "action": "workflow.list",
  "params": {
    "limit": 25,
    "active": true
  }
}
```

## Example: Reverse Trigger (n8n -> Cordum)

1. Enable the webhook bridge in the pack configuration.
2. Map an inbound path to a Cordum workflow id using `CORDUM_N8N_WEBHOOK_WORKFLOW_MAP`.
3. Configure n8n to `POST` to that path with JSON and an `X-N8N-Signature` header containing an HMAC-SHA256 signature of the raw body.

Example webhook request:

```http
POST /hooks/inbound HTTP/1.1
Host: cordum.example.com:9100
Content-Type: application/json
X-N8N-Signature: sha256=<hex-signature>

{"workflowId":"n8n-order-router","executionId":"exec-42","orderId":123}
```

The webhook bridge normalizes the payload into the `n8n/N8nWebhookPayload` shape and starts the mapped Cordum workflow through the Gateway API.

## Workflow Restrictions

Use allow/deny lists to restrict which workflows a profile may touch:

```bash
CORDUM_N8N_ALLOWED_WORKFLOWS=billing-*,crm-*
CORDUM_N8N_DENIED_WORKFLOWS=danger-*,debug-*
```

Deny rules take priority over allow rules. Workflow listings are filtered to the workflows allowed by the active profile.

## Environment Variables

See [`deploy/env.example`](deploy/env.example) for the full list.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `N8N_API_URL` | Yes | `http://localhost:5678` | Base n8n URL |
| `N8N_API_KEY` | Yes | — | n8n API key used as `X-N8N-API-KEY` |
| `CORDUM_N8N_EXECUTION_POLL_INTERVAL` | No | `2s` | Poll interval for `wait_for_completion` |
| `CORDUM_N8N_EXECUTION_WAIT_TIMEOUT` | No | `5m` | Max wait time for `wait_for_completion` |
| `CORDUM_N8N_WEBHOOK_ENABLED` | No | `false` | Start inbound webhook bridge |
| `CORDUM_N8N_WEBHOOK_LISTEN` | No | `:9100` | Webhook listener address |
| `CORDUM_N8N_WEBHOOK_SECRET` | No | — | Shared secret for HMAC-SHA256 verification |
| `CORDUM_N8N_WEBHOOK_WORKFLOW_MAP` | No | — | JSON path -> Cordum workflow id mapping |

## Security & Operations

- Uses a pooled HTTP client for both n8n API calls and Cordum Gateway calls
- Enforces topic separation between read and write actions
- Supports per-profile workflow allow/deny rules
- Supports signed inbound webhook requests with HMAC-SHA256 verification
- Propagates execution ids as idempotency keys when bridging inbound webhooks to Cordum
- Supports execution polling for synchronous-style workflow triggers
