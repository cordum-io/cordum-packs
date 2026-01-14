# Cordum Cron Triggers Pack

Schedule workflow runs with cron expressions. This pack installs read/write workflows and a worker that maintains schedules and triggers Cordum workflows on a cadence.

## Runtime component

The runtime is the `cordum-cron-triggers` worker in `cmd/cordum-cron-triggers`. Installing the pack only registers workflows/schemas; you must run or deploy the worker so `job.cron-triggers.*` jobs are executed and schedules fire.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/cron-triggers/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/cron-triggers

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \

# Allow scheduling hello-pack workflows
CORDUM_CRON_ALLOWED_WORKFLOWS=hello-pack.* \

go run ./cmd/cordum-cron-triggers
```

See `deploy/env.example` for the full list of environment variables.

## Supported actions

Read actions (use `job.cron-triggers.read`):

- `schedules.list`
- `schedules.get`

Write actions (use `job.cron-triggers.write`):

- `schedules.create`
- `schedules.update`
- `schedules.delete`
- `schedules.enable`
- `schedules.disable` (`schedules.pause`)
- `schedules.resume`

## Action parameters

`schedules.create` params:

```json
{
  "id": "optional-id",
  "name": "daily-hello",
  "cron": "0 9 * * *",
  "workflow_id": "hello-pack.echo",
  "input": {"message": "good morning"},
  "enabled": true,
  "timezone": "UTC",
  "dry_run": false,
  "idempotency_key": "daily-hello"
}
```

`schedules.update` params accept the same fields; unset fields are preserved.

`schedules.get`/`delete`/`enable`/`disable` params:

```json
{"id": "schedule-id"}
```

## Security

- Use `CORDUM_CRON_ALLOWED_WORKFLOWS` and `CORDUM_CRON_DENIED_WORKFLOWS` to constrain which workflows can be scheduled.
- Writes require approval by default (per pack policy fragment).

## Notes

- The worker uses Redis for schedule storage and distributed run locks.
- `CORDUM_CRON_ALLOW_SECONDS=true` enables 6-field cron syntax (with seconds).
