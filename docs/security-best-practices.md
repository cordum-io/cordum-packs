# Pack security best practices

This guide applies to all packs and workers in `cordum-packs`. It focuses on
least-privilege configuration, safe defaults, and operational hardening.

## General guidance (all packs)

- **Least privilege**: use the smallest token scope / service account permissions.
- **Restrict scope**: set allowlists for repos, channels, projects, namespaces, or paths.
- **Disable inline auth in production**: keep `*_ALLOW_INLINE_AUTH=false` unless you
  explicitly need per-job credentials.
- **Prefer HTTPS**: keep base URLs on TLS unless testing locally.
- **Rotate secrets**: store tokens in env vars or secret managers; rotate regularly.
- **Set timeouts**: use the `*_REQUEST_TIMEOUT` envs to avoid hanging calls.
- **Audit with policy**: run `cordumctl pack verify <id>` to validate policy simulations.

## Pack-specific hardening tips

### GitHub / GitLab / Jira / Sentry / Slack / MS Teams / Datadog / PagerDuty / ServiceNow

- Use allowlists (`*_ALLOWED_*`) for repos, projects, channels, teams, orgs.
- Disable inline auth. Prefer profile-based config with env-backed secrets.
- Avoid broad tokens (admin scopes, global read/write) unless required.

### Webhooks

- Use `signature_type: hmac_sha256` with a strong secret in `secret_env`.
- Keep `CORDUM_WEBHOOKS_ALLOW_INSECURE=false` in production (default).
- Restrict `allowed_ip_ranges` when possible.
- Lower `max_body_bytes` per route for safety.

### Kubernetes-triage

- Run the worker with a **read-only** Kubernetes RBAC service account.
- Set `CORDUM_K8S_ALLOWED_NAMESPACES` (and/or `DENIED_NAMESPACES`).
- Keep `CORDUM_K8S_ALLOW_UNSAFE_NAMESPACES=false` in production (default).
- Use a dedicated kubeconfig with least privilege.

### Terraform

- Set `CORDUM_TERRAFORM_ALLOWED_DIRS` to a strict allowlist.
- Use a dedicated working directory and CI-scoped credentials.
- Keep `CORDUM_TERRAFORM_ALLOW_UNSAFE_DIRS=false` in production (default).
- Avoid `apply.run` in production unless fully approved.

### MCP-bridge / MCP-client

- Keep `CORDUM_MCP_CLIENT_ALLOW_INLINE_SERVER=false` in production.
- Prefer a fixed server list via `CORDUM_MCP_CLIENT_SERVERS`.
- Restrict tools with `allow_tools` / `deny_tools` in MCP client config.

### Incident-enricher

- Gate `post` actions with approval (policy already enforces this).
- Treat LLM inputs/outputs as untrusted; log and review summaries.

## CI / ops suggestions

- Add a scheduled job to run `cordumctl pack verify` for all packs with policy tests.
- Run workers in isolated containers and restrict outbound networking where possible.
- Record approvals, job results, and API response metadata for audit trails.
