# Hello Pack (Example)

This pack installs a single workflow that dispatches `job.hello-pack.echo` and
validates input/output with JSON Schemas.

## Runtime component

The pack runtime is the hello worker in the Cordum core repo at
`examples/hello-worker-go`. Installing the pack only registers workflows/schemas;
you must run or deploy the worker so `job.hello-pack.echo` jobs are executed.

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
