# Cordum OpenTelemetry Pack

Query traces, services, and dependency graphs from OpenTelemetry-compatible backends (defaulting to Jaeger query APIs).

## Runtime component

The runtime is the `cordum-opentelemetry` worker in `cmd/cordum-opentelemetry`. Installing the pack only registers workflows/schemas; you must run or deploy the worker so `job.opentelemetry.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/opentelemetry/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/opentelemetry

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_OTEL_BASE_URL=http://localhost:16686/api \
CORDUM_OTEL_ALLOWED_SERVICES=api-gateway \

go run ./cmd/cordum-opentelemetry
```

See `deploy/env.example` for the full list of environment variables.

## Supported actions

All actions use `job.opentelemetry.read`:

- `services.list`
- `operations.list`
- `traces.search`
- `traces.get`
- `dependencies.graph`

## Action parameters

`traces.search`:

```json
{
  "action": "traces.search",
  "params": {
    "service": "api-gateway",
    "operation": "GET /v1/orders",
    "limit": 20
  }
}
```

`traces.get`:

```json
{
  "action": "traces.get",
  "params": {
    "trace_id": "7a45f9d4f0b2f23b"
  }
}
```

`dependencies.graph`:

```json
{
  "action": "dependencies.graph",
  "params": {
    "endTs": 1737000000000,
    "lookback": "1h"
  }
}
```

## Security

- Use `CORDUM_OTEL_ALLOWED_SERVICES` and `CORDUM_OTEL_DENIED_SERVICES` to constrain service names.
- All requests are tagged `read` and routed through the Safety Kernel.
