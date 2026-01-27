# Pack Runtime Guide (Security-Hardened)

This guide explains how to run pack runtimes safely in production.

## 1) Install the pack bundle

From the Cordum repo:

```bash
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/<pack>/pack
```

This registers workflows/schemas/policy fragments. It does **not** run the worker.

## 2) Run the worker/runtime

Each pack has a runtime under `cmd/`. Use the pack's `README.md` for the full env list.

Minimal secure template:

```bash
CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=... \
CORDUM_TENANT_ID=default \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_<PACK>_ALLOW_INLINE_AUTH=false \
CORDUM_<PACK>_ALLOW_INLINE_SECRETS=false \
CORDUM_<PACK>_ALLOW_ACTIONS=... \
CORDUM_<PACK>_DENY_ACTIONS=... \
# plus pack-specific allowlists and auth env vars

go run ./cmd/cordum-<pack>
```

## 3) Security defaults to keep

- Inline auth secrets are off by default.
- Use allowlists for repos/projects/paths/actions.
- Keep write actions behind approval (default policy).

## 4) Recommended production controls

- Run workers in isolated namespaces with least-privilege credentials.
- Restrict outbound access and disable shell access on runtime hosts.
- Enable log redaction where available (webhooks).
- Use per-pack profiles to scope tokens and actions.

## 5) Troubleshooting

- Verify the worker is subscribed to the correct job topics (e.g., `job.github.*`).
- Check the gateway logs for rejected jobs or policy decisions.
- Ensure allowlists include the requested resource (repo/project/path).

