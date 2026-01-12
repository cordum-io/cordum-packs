# Cordum MCP Bridge (stdio)

This pack project provides a **stdio MCP server** that exposes Cordum control‑plane actions as MCP tools and Cordum run/job data as MCP resources. The bridge submits MCP tool calls as Cordum jobs (so they are **policy‑gated**) and executes them via a worker subscribed to `job.mcp-bridge.*`.
Part of the `cordum-packs` monorepo.

## What you get

- **MCP tools**: start/rerun/cancel workflows, approve/reject/remediate jobs, retry DLQ.
- **MCP resources**: job detail + decisions, run detail + timeline, artifacts, pointers.
- **Safety Kernel integration**: each tool call becomes a Cordum job and is evaluated before dispatch.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/mcp-bridge/pack
```

This adds the pool mapping, timeouts, and a policy fragment that requires approval for `write` actions.

### 2) Run the bridge

```bash
cd path/to/cordum-packs/packs/mcp-bridge

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \

go run ./cmd/cordum-mcp-bridge
```

The bridge runs as a stdio MCP server (reads JSON‑RPC from stdin, writes to stdout).

## Environment

- `CORDUM_GATEWAY_URL` (default `http://localhost:8081`)
- `CORDUM_API_KEY` (required for enterprise installs)
- `CORDUM_NATS_URL` (default `nats://localhost:4222`)
- `CORDUM_REDIS_URL` (default `redis://localhost:6379`)
- `CORDUM_MCP_POOL` (default `mcp-bridge`)
- `CORDUM_MCP_QUEUE` (default `mcp-bridge`)
- `CORDUM_MCP_SUBJECTS` (default `job.mcp-bridge.*`)
- `CORDUM_MCP_JOB_TOPIC` (default `job.mcp-bridge.tool`)
- `CORDUM_MCP_CALL_TIMEOUT` (default `30s`)
- `CORDUM_MCP_POLL_INTERVAL` (default `750ms`)
- `CORDUM_MCP_MAX_PARALLEL` (default `0` = unlimited)

## MCP tools (v0)

- `cordum.workflow.run`
- `cordum.workflow.rerun`
- `cordum.workflow.cancel`
- `cordum.job.approve`
- `cordum.job.reject`
- `cordum.job.remediate`
- `cordum.dlq.retry`

All tool calls are submitted as Cordum jobs on `job.mcp-bridge.tool` with labels:
`mcp.server`, `mcp.tool`, `mcp.action=call`.

## MCP resources (v0)

- `cordum://jobs/{job_id}`
- `cordum://jobs/{job_id}/decisions`
- `cordum://runs/{run_id}`
- `cordum://runs/{run_id}/timeline`
- `cordum://artifacts/{artifact_ptr}`
- `cordum://memory?ptr=redis://ctx:<job_id>`

## Security

The bridge expects an API key with admin permissions for gateway reads/writes.
In enterprise setups, use a dedicated service principal with scoped permissions.

## License

BUSL‑1.1 (same as Cordum core).
