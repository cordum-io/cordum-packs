# Cordum Prometheus Query Pack

Run PromQL queries, inspect alerts, and list labels/series from Prometheus with governed access.

## Runtime component

The runtime is the `cordum-prometheus-query` worker in `cmd/cordum-prometheus-query`. Installing the pack only registers workflows/schemas; you must run or deploy the worker so `job.prometheus-query.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/prometheus-query/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/prometheus-query

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_PROMETHEUS_BASE_URL=https://prom.example \
CORDUM_PROMETHEUS_TOKEN_ENV=PROM_TOKEN \
PROM_TOKEN=example \


go run ./cmd/cordum-prometheus-query
```

See `deploy/env.example` for the full list of environment variables.

## Supported actions

All actions use `job.prometheus-query.read`:

- `query.instant`
- `query.range`
- `labels.list`
- `label.values`
- `series.list`
- `alerts.list`
- `rules.list`
- `targets.list`

## Action parameters

`query.instant`:

```json
{
  "action": "query.instant",
  "params": {
    "query": "sum(rate(http_requests_total[5m]))",
    "time": "2025-01-01T00:00:00Z"
  }
}
```

`query.range`:

```json
{
  "action": "query.range",
  "params": {
    "query": "sum(rate(http_requests_total[5m]))",
    "start": "2025-01-01T00:00:00Z",
    "end": "2025-01-01T01:00:00Z",
    "step": "30s"
  }
}
```

`label.values`:

```json
{
  "action": "label.values",
  "params": {
    "label": "job",
    "match": ["up", "process_start_time_seconds"]
  }
}
```

## Security

- Use `CORDUM_PROMETHEUS_ALLOW_ACTIONS` and `CORDUM_PROMETHEUS_DENY_ACTIONS` to constrain actions.
- All requests are tagged `read` and routed through the Safety Kernel.
