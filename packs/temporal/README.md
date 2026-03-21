# Temporal Pack

Temporal durable workflow execution bridge for Cordum — start, query, signal, cancel workflows, and manage schedules.

## Hybrid Orchestration Pattern

```
Cordum (governance + policy)        Temporal (durable execution + retries)
  │                                    │
  ├── Policy evaluation                ├── Workflow execution
  ├── CAP Safety Kernel                ├── Activity retries
  ├── Audit trail                      ├── Timer management
  └── Topic routing                    └── State persistence
         │                                    ▲
         └── cordum-temporal pack ────────────┘
              (bridge layer)
```

Cordum handles governance, policy, and audit. Temporal handles durable execution, retries, and state. This pack bridges the two.

## Capabilities

| Topic | Actions | Policy |
|-------|---------|--------|
| `job.temporal.read` | query, describe, list, schedule.list/describe | ALLOW |
| `job.temporal.write` | start, signal, schedule.create/pause/unpause | REQUIRE_APPROVAL |
| `job.temporal.destructive` | cancel, terminate, schedule.delete | REQUIRE_APPROVAL |

## Quick Start

```bash
# Start Temporal dev server
temporal server start-dev

# Build and run
cd packs/temporal
go build -o cordum-temporal.exe ./cmd/cordum-temporal/
./cordum-temporal.exe
```

## Example: Start Workflow

```json
{
  "action": "workflow.start",
  "params": {
    "workflow_type": "OrderProcessing",
    "workflow_id": "order-12345",
    "task_queue": "orders",
    "input": {"order_id": 12345, "customer": "acme"}
  }
}
```

## Example: Query Workflow State

```json
{
  "action": "workflow.query",
  "params": {
    "workflow_id": "order-12345",
    "query_type": "getStatus"
  }
}
```

## Example: Signal Workflow

```json
{
  "action": "workflow.signal",
  "params": {
    "workflow_id": "order-12345",
    "signal_name": "approve",
    "input": {"approved_by": "admin"}
  }
}
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TEMPORAL_ADDRESS` | No | `localhost:7233` | Temporal server address |
| `TEMPORAL_NAMESPACE` | No | `default` | Temporal namespace |
| `TEMPORAL_API_KEY` | No | — | Temporal Cloud API key |
| `CORDUM_TEMPORAL_ALLOWED_TASK_QUEUES` | No | (all) | Task queue allow list |
| `CORDUM_TEMPORAL_DENIED_WORKFLOWS` | No | (none) | Workflow deny list |

## Security

- 3-tier policy: read ALLOW, write REQUIRE_APPROVAL, destructive REQUIRE_APPROVAL (0 retries)
- Task queue and workflow type allow/deny lists
- TLS support for Temporal Cloud
- API key authentication for Temporal Cloud
- Topic-intent enforcement: destructive actions require destructive topic
