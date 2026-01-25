# Cordum GCP Pack

GCP logging/monitoring queries and service inspection workflows for Cordum.

## What you get

- Read/write workflows: `gcp.read`, `gcp.write`.
- Schemas: `gcp/GcpActionInput`, `gcp/GcpActionResult`.
- Policy overlays: read is allowed by default; write requires approval.

## Runtime component

This pack does not ship a worker in this repo. You must deploy a compatible
GCP worker that listens on `job.gcp.read` and `job.gcp.write`.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/gcp/pack
```

### 2) Run your GCP worker

Configure your worker to subscribe to `job.gcp.*` and use the schemas in this
pack.

### 3) Submit a job

```bash
cd path/to/cordum
./bin/cordumctl job submit --topic job.gcp.read \
  --input '{"action":"<worker-action>","params":{}}'
```

## Mock testing

See `docs/mock-testing.md` for a no-credentials workflow and the shared mock
harness in `tools/mock`.


## Security best practices

- Follow `docs/security-best-practices.md` for least-privilege guidance and hardening tips.

## License

BUSL-1.1 (same as Cordum core).
