# Zapier Pack

Zapier integration pack for Cordum.

It supports two independent code paths:

- **Webhook alias dispatch** — Cordum sends JSON payloads to configured Zapier catch-hook URLs without ever exposing raw hook URLs in workflow input.
- **Zapier AI Actions / legacy NLA** — Cordum lists stored AI Actions, executes them from natural-language instructions, previews them safely, and fetches execution logs.

If `ZAPIER_NLA_API_KEY` is not configured, webhook dispatch still works; only `nla.*` actions return a clear configuration error.

## Topics & Policy

| Topic | Actions | Policy |
|-------|---------|--------|
| `job.zapier.read` | `nla.list`, `nla.log`, `webhook.send` | ALLOW |
| `job.zapier.write` | `nla.execute`, `nla.preview` | REQUIRE_APPROVAL |

The worker rejects requests sent to the wrong topic.

## Actions

| Action | Description |
|--------|-------------|
| `nla.list` | List stored Zapier AI Actions available to the configured API key |
| `nla.execute` | Execute an AI Action from a natural-language instruction |
| `nla.preview` | Force preview/review mode for the AI Action request |
| `nla.log` | Fetch a previous execution log by `execution_log_id` |
| `webhook.send` | Send a JSON payload to a configured webhook alias |

## Safety Model

### Preview mode

Use `nla.preview` or set `preview_only: true` to ask Zapier for a review/preview response instead of committing the action immediately.

### Action allow/deny rules

The pack supports `CORDUM_ZAPIER_ALLOWED_ACTIONS` and `CORDUM_ZAPIER_DENIED_ACTIONS` glob rules. When either list is configured, `nla.execute` and `nla.preview` must include `action_id` so the worker can enforce policy before sending the request to Zapier.

### Webhook aliasing

Cordum workflows pass a logical alias such as `orders` or `alerts`. The actual Zapier catch-hook URLs stay in `CORDUM_ZAPIER_WEBHOOK_URLS`, for example:

```bash
CORDUM_ZAPIER_WEBHOOK_URLS='{"orders":"https://hooks.zapier.com/hooks/catch/123456/orders"}'
```

The worker resolves the alias server-side and rejects raw URL input.

## Current Zapier product state

Zapier has deprecated AI Actions for new deployments in favor of newer MCP/AI surfaces, but existing API-key based deployments can still use the endpoints documented under Zapier AI Actions. This pack therefore:

- defaults `ZAPIER_NLA_BASE_URL` to `https://actions.zapier.com/api/v2`
- keeps webhook delivery fully functional even if AI Actions are unavailable
- sends both `x-api-key` and `Authorization: Bearer ...` headers for compatibility across current and legacy AI Actions/NLA variants

Also note: the approved implementation plan for this task centers on webhook aliases and AI Actions. Official Zapier Workflow API docs currently allow Zap listing, but do **not** expose a generic on/off endpoint for existing user Zaps, so this pack does not attempt unsupported Zap toggling.

## Quick Start

```bash
# 1. Configure Zapier AI Actions (optional for webhook-only mode)
export ZAPIER_NLA_API_KEY=your-api-key
export ZAPIER_NLA_BASE_URL=https://actions.zapier.com/api/v2

# 2. Configure one or more catch-hook aliases
export CORDUM_ZAPIER_WEBHOOK_URLS='{"orders":"https://hooks.zapier.com/hooks/catch/123456/orders"}'

# 3. Build and run
cd packs/zapier
go build -o cordum-zapier ./cmd/cordum-zapier/
./cordum-zapier
```

## Example: Execute a Zapier AI Action

The pack ships an example workflow id: `zapier-nla-workflow`.

Submit to `job.zapier.write`:

```json
{
  "action": "nla.execute",
  "params": {
    "action_id": "act_123",
    "instruction": "Draft and send an invoice reminder to Acme for invoice INV-4421",
    "preview_only": true,
    "params_hints": {
      "email": "billing@acme.example"
    }
  }
}
```

## Example: Send a Webhook Alias

Submit to `job.zapier.read`:

```json
{
  "action": "webhook.send",
  "params": {
    "webhook_name": "orders",
    "payload": {
      "order_id": 42,
      "status": "paid"
    }
  }
}
```

## Example: Fetch an Execution Log

```json
{
  "action": "nla.log",
  "params": {
    "execution_log_id": "log_123"
  }
}
```

## Environment Variables

See [`deploy/env.example`](deploy/env.example) for the full list.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ZAPIER_NLA_API_KEY` | No | — | API key for Zapier AI Actions / legacy NLA |
| `ZAPIER_NLA_BASE_URL` | No | `https://actions.zapier.com/api/v2` | Base URL for Zapier AI Actions / legacy NLA |
| `CORDUM_ZAPIER_WEBHOOK_URLS` | Yes for `webhook.send` | `{}` | JSON alias -> catch-hook URL mapping |
| `CORDUM_ZAPIER_ALLOWED_ACTIONS` | No | — | Comma-separated action-id allowlist glob patterns |
| `CORDUM_ZAPIER_DENIED_ACTIONS` | No | — | Comma-separated action-id denylist glob patterns |
| `CORDUM_ZAPIER_ALLOWED_WEBHOOKS` | No | — | Comma-separated webhook alias allowlist glob patterns |
| `CORDUM_ZAPIER_DENIED_WEBHOOKS` | No | — | Comma-separated webhook alias denylist glob patterns |

## Testing

```bash
cd packs/zapier
go test -mod=mod ./...
```

## Operational Notes

- Uses pooled `http.Client` instances for Zapier AI Actions and webhook traffic
- Keeps webhook and AI Action code paths separate so webhook-only deployments remain usable
- Filters listed AI Actions through the configured allow/deny rules
- Returns a clear `NLA API key not configured` error for `nla.*` actions when credentials are absent
