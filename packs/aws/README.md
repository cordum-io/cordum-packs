# Cordum AWS Pack

AWS observability and inspection actions bundled as Cordum workflows and schemas.

## What you get

- Read/write workflows: `aws.read`, `aws.write`.
- Schemas: `aws/AwsActionInput`, `aws/AwsActionResult`.
- Policy overlays: read is allowed by default; write requires approval.

## Runtime component

This pack does not ship a worker in this repo. You must deploy a compatible
AWS worker that listens on `job.aws.read` and `job.aws.write`.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/aws/pack
```

### 2) Run your AWS worker

Configure your worker to subscribe to `job.aws.*` and use the schemas in this
pack.

### 3) Submit a job

```bash
cd path/to/cordum
./bin/cordumctl job submit --topic job.aws.read \
  --input '{"action":"<worker-action>","params":{}}'
```

## Mock testing

See `docs/mock-testing.md` for a no‑credentials workflow and the shared mock
harness in `tools/mock`.

## License

BUSL-1.1 (same as Cordum core).
