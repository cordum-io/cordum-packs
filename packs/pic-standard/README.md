# PIC Standard Pack

Provenance & Intent Contract (PIC) verification gate for Cordum workflows.
This pack adds a `job.pic-standard.verify` worker topic that checks proposed
tool calls against PIC contracts before execution.

## How it works

PIC explains *why* an action is justified (provenance verification). Cordum
controls *whether* it executes (Safety Kernel + policy). This pack bridges
the two by exposing a verification step that workflows compose as a gate.

**Workflow routing:**

| output.next         | Meaning                                |
|---------------------|----------------------------------------|
| `proceed`           | PIC verification passed — continue     |
| `fail`              | Verification failed — abort workflow   |
| `require_approval`  | Allowed, but impact requires review    |

## Prerequisites

- A running PIC bridge (`pic-cli serve`) from: https://github.com/madeinplutofabio/pic-standard
- Cordum core with NATS + Redis

## Runtime component

The runtime is the `cordum-pic-standard` worker in `cmd/cordum-pic-standard`.
Installing the pack only registers workflows/schemas; you must run or deploy
the worker so `job.pic-standard.verify` jobs are executed.

## Run the worker

```bash
cd path/to/cordum-packs/packs/pic-standard

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_TENANT_ID=default \
NATS_URL=nats://localhost:4222 \
REDIS_URL=redis://localhost:6379 \
CORDUM_PIC_STANDARD_BRIDGE_URL=http://localhost:3100 \
go run ./cmd/cordum-pic-standard
```

See `deploy/env.example` for all environment variables.

## Install

From your Cordum core repo:

```bash
go run ./cmd/cordumctl pack install path/to/cordum-packs/packs/pic-standard/pack
```

## Run (example)

```bash
curl -sS -X POST http://localhost:8081/api/v1/workflows/pic-standard.pic_verify/runs \
  -H "X-API-Key: ${CORDUM_API_KEY:-super-secret-key}" \
  -H "X-Tenant-ID: ${CORDUM_TENANT_ID:-default}" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"payments_send","tool_args":{"amount":500,"to":"vendor@example.com"}}'
```

## Output semantics

- `allowed`: whether PIC verification succeeded
- `next`: workflow routing decision (`proceed` / `fail` / `require_approval`)
- `impact`: PIC impact classification (e.g. `money`, `privacy`) or `null`
- `reason`: human-readable explanation or `null`
- `eval_ms`: bridge evaluation time in milliseconds

`allowed=true` + `next=require_approval` is valid: PIC approved the action,
but its impact type is configured to require human sign-off.

## Uninstall

```bash
go run ./cmd/cordumctl pack uninstall pic-standard
```

## License

BUSL-1.1 (same as the cordum-packs repository).
