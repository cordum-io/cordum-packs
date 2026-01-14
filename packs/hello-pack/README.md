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
  -H "Content-Type: application/json" \
  -d '{"message":"hello from pack","author":"demo"}'
```

## Uninstall

```bash
go run ./cmd/cordumctl pack uninstall hello-pack
```
