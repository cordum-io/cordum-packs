# Hello Pack (Example)

This pack installs a single workflow that dispatches `job.hello-pack.echo` and
validates input/output with JSON Schemas.

## Runtime component

The runtime is the `cordum-hello-pack` worker in `cmd/cordum-hello-pack`. Installing
the pack only registers workflows/schemas; you must run or deploy the worker so
`job.hello-pack.echo` jobs are executed.

## Run the worker

```bash
cd path/to/cordum-packs/packs/hello-pack

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_TENANT_ID=default \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \

go run ./cmd/cordum-hello-pack
```

See `deploy/env.example` for all environment variables.

## Install

From your Cordum core repo:

```bash
go run ./cmd/cordumctl pack install path/to/cordum-packs/packs/hello-pack
```

## Run

```bash
curl -sS -X POST http://localhost:8081/api/v1/workflows/hello-pack.echo/runs \
  -H "X-API-Key: ${CORDUM_API_KEY:-super-secret-key}" \
  -H "X-Tenant-ID: ${CORDUM_TENANT_ID:-default}" \
  -H "Content-Type: application/json" \
  -d '{"message":"hello from pack","author":"demo"}'
```

`author` is optional; omit it if you want the default to be used by the worker.

## Uninstall

```bash
go run ./cmd/cordumctl pack uninstall hello-pack
```

## Signing (reference workflow)

Every published pack ships with an Ed25519 signature that binds
`pack.yaml` and its referenced schemas/workflows/overlays to a
known publisher. The toolchain is documented at
[`docs/packs/signing.md`](../../../cordum/docs/packs/signing.md); the
short version for this reference pack is:

```bash
# One-time: generate a signing key.
cordumctl pack keygen

# Sign the pack. Writes pack.yaml.sig next to pack.yaml.
cordumctl pack sign packs/hello-pack

# Export the public key for registry submission.
cordumctl pack export-key

# Operators verify with a trusted keyring.
cordumctl pack verify-signature packs/hello-pack \
  --trusted-keys /etc/cordum/trusted-pack-keys
```

This reference pack intentionally does **not** ship a checked-in
`pack.yaml.sig`. Committing a signing key (even labelled
"test-only") invites drive-by copy-paste into a production pack;
the round-trip is proven by `cmd/cordumctl/pack_sign_test.go`
instead.
