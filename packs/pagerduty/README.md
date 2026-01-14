# Cordum PagerDuty Pack

Manage PagerDuty incidents and on-call schedules with governed access from Cordum workflows.

## Runtime component

The runtime is the `cordum-pagerduty` worker in `cmd/cordum-pagerduty`. Installing the pack only registers workflows/schemas; you must run or deploy the worker so `job.pagerduty.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/pagerduty/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/pagerduty

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_PAGERDUTY_TOKEN_ENV=PAGERDUTY_TOKEN \
PAGERDUTY_TOKEN=example \

go run ./cmd/cordum-pagerduty
```

See `deploy/env.example` for the full list of environment variables.

## Supported actions

Read actions (use `job.pagerduty.read`):

- `incidents.list`
- `incidents.get`
- `oncalls.list`
- `schedules.list`
- `schedules.get`

Write actions (use `job.pagerduty.write`):

- `incidents.acknowledge`
- `incidents.resolve`

## Action parameters

`incidents.list`:

```json
{
  "action": "incidents.list",
  "params": {
    "statuses[]": ["triggered", "acknowledged"],
    "urgencies[]": ["high"]
  }
}
```

`incidents.acknowledge` (requires a `from` header value):

```json
{
  "action": "incidents.acknowledge",
  "params": {
    "id": "P123456",
    "from": "oncall@example.com"
  }
}
```

## Security

- Use `CORDUM_PAGERDUTY_ALLOW_ACTIONS` and `CORDUM_PAGERDUTY_DENY_ACTIONS` to constrain actions per profile.
- Write actions require approval by default (per pack policy fragment).
