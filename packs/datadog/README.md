# Cordum Datadog Pack

Datadog metrics, logs, traces, and monitor actions packaged as Cordum workflows.

## What you get

- Read/write workflows: `datadog.read`, `datadog.write`.
- Schemas: `datadog/DatadogActionInput`, `datadog/DatadogActionResult`.
- Policy overlays: read is allowed by default; write requires approval.

## Runtime component

This pack does not ship a worker in this repo. You must deploy a compatible
Datadog worker that listens on `job.datadog.read` and `job.datadog.write`.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/datadog/pack
```

### 2) Run your Datadog worker

Configure your worker to subscribe to `job.datadog.*` and use the schemas in this
pack.

### 3) Submit a job

```bash
cd path/to/cordum
./bin/cordumctl job submit --topic job.datadog.read \
  --input '{"action":"<worker-action>","params":{}}'
```

## Mock testing

See `docs/mock-testing.md` for a no-credentials workflow and the shared mock
harness in `tools/mock`.


## Security best practices

- Follow `docs/security-best-practices.md` for least-privilege guidance and hardening tips.

## License

BUSL-1.1 (same as Cordum core).
