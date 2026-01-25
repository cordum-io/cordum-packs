# Security Hardening Guide

We are a security company. Production deployments must be security-ready, least-privilege, and safe by default.
This guide explains the hardened defaults and the knobs you can enable when you truly need them.

## Baseline requirements (all packs)

- Run workers on private networks with restricted inbound access.
- Use a dedicated service principal API key with the minimum required permissions.
- Store secrets in a secret manager and inject via env vars (never inline in job input).
- Keep logs free of secrets; avoid printing request headers/bodies in production.
- Enforce allowlists (repos/projects/paths/actions) and keep deny lists as backstops.

## Inline auth (all packs that support it)

Inline auth is **disabled by default**. Enabling inline auth is a two-step gate:

1) Allow inline auth (non-secret fields):
- `CORDUM_<PACK>_ALLOW_INLINE_AUTH=true`

2) Allow inline secrets (raw tokens/passwords in job input):
- `CORDUM_<PACK>_ALLOW_INLINE_SECRETS=true`

Production guidance:
- Keep `ALLOW_INLINE_SECRETS=false`.
- Prefer `*_env` fields so secrets come from environment variables.

Supported packs with inline auth gates:
- GitHub, GitLab, Jira, Slack, Sentry, MSTeams, Prometheus Query, OpenTelemetry, Vault

## MCP client hardening

- Default posture: **named servers only** via `CORDUM_MCP_CLIENT_SERVERS`.
- `CORDUM_MCP_CLIENT_ALLOW_INLINE_SERVER=true` only allows safe header overrides.
- `CORDUM_MCP_CLIENT_ALLOW_INLINE_UNSAFE_SERVER=true` is required for inline transport/command/url/args/env.

Production guidance:
- Keep `ALLOW_INLINE_UNSAFE_SERVER=false`.
- Define servers explicitly and lock down tool allow/deny lists.

## Terraform hardening

- Auto-approve is disabled by default.
- To allow `auto_approve`, set `CORDUM_TERRAFORM_ALLOW_AUTO_APPROVE=true`.

Production guidance:
- Prefer `plan` + explicit `plan_file` for apply.
- Constrain `CORDUM_TERRAFORM_ALLOWED_DIRS` and `CORDUM_TERRAFORM_ALLOW_ACTIONS`.

## Webhooks hardening

- Require HMAC or token signatures (`signature_type`).
- Use IP allow/deny lists where possible.
- If behind a proxy, set:
  - `CORDUM_WEBHOOKS_TRUST_PROXY=true`
  - `CORDUM_WEBHOOKS_TRUST_PROXY_CIDRS=<trusted proxy CIDRs>`
- Header redaction is on by default:
  - `CORDUM_WEBHOOKS_REDACT_HEADERS=true`
  - Optional: `CORDUM_WEBHOOKS_REDACT_HEADER_NAMES=...`

## Secrets handling

- Prefer `*_ENV` variables in profiles.
- Avoid writing secrets to disk or to logs.
- Rotate credentials regularly and scope tokens to the minimum permissions required.

## Network boundaries

- Restrict outbound access for workers to only required APIs.
- Consider egress allowlists for GitHub, GitLab, Jira, Slack, etc.
- Terminate TLS at the edge and use TLS for all external API calls.

## Quick hardening checklist

- [ ] API keys stored in secret manager and injected via env.
- [ ] Inline secrets disabled (`ALLOW_INLINE_SECRETS=false`).
- [ ] All packs configured with allowlists (repos/projects/paths/actions).
- [ ] Webhooks signatures enabled and proxy CIDRs set if applicable.
- [ ] Terraform auto-approve disabled unless explicitly required.
- [ ] MCP client uses named servers only.
- [ ] Logs scrubbed or redacted; no secrets in payloads.

