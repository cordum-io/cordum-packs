# Cordum ServiceNow Pack

ServiceNow incidents, changes, and CMDB actions packaged as Cordum workflows.

## What you get

- Read/write workflows: `servicenow.read`, `servicenow.write`.
- Schemas: `servicenow/ServiceNowActionInput`, `servicenow/ServiceNowActionResult`.
- Policy overlays: read is allowed by default; write requires approval.

## Runtime component

This pack does not ship a worker in this repo. You must deploy a compatible
ServiceNow worker that listens on `job.servicenow.read` and
`job.servicenow.write`.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/servicenow/pack
```

### 2) Run your ServiceNow worker

Configure your worker to subscribe to `job.servicenow.*` and use the schemas in
this pack.

### 3) Submit a job

```bash
cd path/to/cordum
./bin/cordumctl job submit --topic job.servicenow.read \
  --input '{"action":"<worker-action>","params":{}}'
```

## Mock testing

See `docs/mock-testing.md` for a no-credentials workflow and the shared mock
harness in `tools/mock`.


## Security best practices

- Follow `docs/security-best-practices.md` for least-privilege guidance and hardening tips.

## License

BUSL-1.1 (same as Cordum core).
