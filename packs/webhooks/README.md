# Cordum Webhooks Pack

Inbound webhook receiver that starts Cordum workflow runs with strong routing and signature checks.
The receiver runs as a standalone HTTP service and calls the Cordum gateway to start workflows.

## What you get

- **Webhook receiver**: HTTP server that validates signatures and starts workflow runs.
- **Tenant-aware routing**: map routes to workflow IDs with optional org/team scoping.
- **Audit-friendly payloads**: headers, query params, and body forwarded into workflow input.

## Runtime component

The pack runtime is the `cordum-webhooks` service in `cmd/cordum-webhooks`.
Installing the pack only registers schemas and config overlays; you must run or
deploy the receiver so webhook traffic can start workflows.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/webhooks/pack
```

### 2) Run the receiver

```bash
cd path/to/cordum-packs/packs/webhooks

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_WEBHOOKS_BIND=:8089 \
CORDUM_WEBHOOKS_ROUTES='[
  {
    "id": "github",
    "path": "/webhooks/github",
    "method": "POST",
    "workflow_id": "incident-enricher.enrich",
    "signature_type": "hmac_sha256",
    "signature_header": "X-Hub-Signature-256",
    "secret_env": "GITHUB_WEBHOOK_SECRET",
    "idempotency_header": "X-GitHub-Delivery"
  }
]'

GITHUB_WEBHOOK_SECRET=*** \

go run ./cmd/cordum-webhooks
```

## Environment

- `CORDUM_GATEWAY_URL` (default `http://localhost:8081`)
- `CORDUM_API_KEY` (optional; required for enterprise installs)
- `CORDUM_WEBHOOKS_BIND` (default `:8089`)
- `CORDUM_WEBHOOKS_MAX_BODY_BYTES` (default `1048576`)
- `CORDUM_WEBHOOKS_TRUST_PROXY` (default `false`)
- `CORDUM_WEBHOOKS_ROUTES` (required JSON array; see below)

### Route configuration (`CORDUM_WEBHOOKS_ROUTES`)

Each route config supports:

- `id` (string): route identifier used in payloads.
- `path` (string): HTTP path to listen on.
- `method` (string): HTTP method (default `POST`).
- `workflow_id` (string): Cordum workflow ID to start.
- `org_id` / `team_id` (optional): scope the run to a tenant.
- `signature_type` (string): `none`, `token`, `hmac_sha256`, `hmac_sha1`.
- `signature_header` (string): header holding the signature/token.
- `token_header` (string): default `X-Webhook-Token`.
- `secret` / `secret_env` (string): shared secret for signatures.
- `idempotency_header` (string): header passed as `Idempotency-Key` when starting runs.
- `allowed_ip_ranges` / `denied_ip_ranges` (CIDR lists).
- `max_body_bytes` (optional): per-route override.

## Payload shape

The receiver sends a workflow input shaped like:

```json
{
  "webhook": {
    "id": "github",
    "path": "/webhooks/github",
    "method": "POST",
    "headers": {"X-GitHub-Event": ["push"]},
    "query": {"foo": ["bar"]},
    "body": {"action": "opened"},
    "raw_body": "{...}",
    "source_ip": "203.0.113.10",
    "received_at": "2025-01-01T00:00:00Z"
  }
}
```

## Security

- **Signature checks**: enforce HMAC or token-based verification.
- **IP allow/deny lists**: restrict ingress by CIDR.
- **Idempotency**: forward unique delivery IDs to prevent duplicate runs.

## License

BUSL-1.1 (same as Cordum core).
