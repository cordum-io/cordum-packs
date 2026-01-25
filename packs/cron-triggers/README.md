# Cordum Cron Triggers Pack

Scheduled runs that trigger Cordum workflows on a cadence.

## What you get

- Read/write workflows: `cron-triggers.read`, `cron-triggers.write`.
- Schemas: `cron-triggers/CronTriggersActionInput`, `cron-triggers/CronTriggersActionResult`.
- Policy overlays: read is allowed by default; write requires approval.

## Runtime component

This pack does not ship a worker in this repo. You must deploy a compatible
cron trigger worker that listens on `job.cron-triggers.read` and
`job.cron-triggers.write`.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/cron-triggers/pack
```

### 2) Run your cron trigger worker

Configure your worker to subscribe to `job.cron-triggers.*` and use the schemas
in this pack.

### 3) Submit a job

```bash
cd path/to/cordum
./bin/cordumctl job submit --topic job.cron-triggers.read \
  --input '{"action":"<worker-action>","params":{}}'
```

## Mock testing

See `docs/mock-testing.md` for a no-credentials workflow and the shared mock
harness in `tools/mock`.


## Security best practices

- Follow `docs/security-best-practices.md` for least-privilege guidance and hardening tips.

## License

BUSL-1.1 (same as Cordum core).
