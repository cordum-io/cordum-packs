# Cordum Datadog Pack

Connect Cordum workflows to Datadog metrics, logs, traces, and monitor controls with governed access.

## Runtime component

The runtime is the `cordum-datadog` worker in `cmd/cordum-datadog`. Installing the pack only registers workflows/schemas; you must run or deploy the worker so `job.datadog.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/datadog/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/datadog

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_DATADOG_API_KEY_ENV=DD_API_KEY \
CORDUM_DATADOG_APP_KEY_ENV=DD_APP_KEY \
DD_API_KEY=example \
DD_APP_KEY=example \

go run ./cmd/cordum-datadog
```

See `deploy/env.example` for the full list of environment variables.

## Supported actions

Read actions (use `job.datadog.read`):

- `metrics.query`
- `logs.search`
- `traces.search`
- `monitors.list`
- `monitors.get`

Write actions (use `job.datadog.write`):

- `monitors.mute`
- `monitors.unmute`

## Action parameters

`metrics.query`:

```json
{
  "action": "metrics.query",
  "params": {
    "from": 1735689600,
    "to": 1735693200,
    "query": "avg:system.cpu.user{*} by {host}"
  }
}
```

`logs.search`:

```json
{
  "action": "logs.search",
  "params": {
    "filter": {
      "query": "service:webapp status:error",
      "from": "now-15m",
      "to": "now"
    },
    "sort": "timestamp"
  }
}
```

`monitors.mute`:

```json
{
  "action": "monitors.mute",
  "params": {
    "id": "123456",
    "message": "investigating incident",
    "scope": "env:prod"
  }
}
```

## Security

- Use `CORDUM_DATADOG_ALLOW_ACTIONS` and `CORDUM_DATADOG_DENY_ACTIONS` to constrain actions per profile.
- Write actions require approval by default (per pack policy fragment).
