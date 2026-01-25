# Cordum PagerDuty Pack

PagerDuty incident and on-call actions packaged as Cordum workflows.

## What you get

- Read/write workflows: `pagerduty.read`, `pagerduty.write`.
- Schemas: `pagerduty/PagerDutyActionInput`, `pagerduty/PagerDutyActionResult`.
- Policy overlays: read is allowed by default; write requires approval.

## Runtime component

This pack does not ship a worker in this repo. You must deploy a compatible
PagerDuty worker that listens on `job.pagerduty.read` and `job.pagerduty.write`.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/pagerduty/pack
```

### 2) Run your PagerDuty worker

Configure your worker to subscribe to `job.pagerduty.*` and use the schemas in
this pack.

### 3) Submit a job

```bash
cd path/to/cordum
./bin/cordumctl job submit --topic job.pagerduty.read \
  --input '{"action":"<worker-action>","params":{}}'
```

## Mock testing

See `docs/mock-testing.md` for a no-credentials workflow and the shared mock
harness in `tools/mock`.


## Security best practices

- Follow `docs/security-best-practices.md` for least-privilege guidance and hardening tips.

## License

BUSL-1.1 (same as Cordum core).
