# Cordum Azure Pack

Azure Monitor queries and service inspection workflows for Cordum.

## What you get

- Read/write workflows: `azure.read`, `azure.write`.
- Schemas: `azure/AzureActionInput`, `azure/AzureActionResult`.
- Policy overlays: read is allowed by default; write requires approval.

## Runtime component

This pack does not ship a worker in this repo. You must deploy a compatible
Azure worker that listens on `job.azure.read` and `job.azure.write`.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/azure/pack
```

### 2) Run your Azure worker

Configure your worker to subscribe to `job.azure.*` and use the schemas in this
pack.

### 3) Submit a job

```bash
cd path/to/cordum
./bin/cordumctl job submit --topic job.azure.read \
  --input '{"action":"<worker-action>","params":{}}'
```

## Mock testing

See `docs/mock-testing.md` for a no‑credentials workflow and the shared mock
harness in `tools/mock`.

## License

BUSL-1.1 (same as Cordum core).
