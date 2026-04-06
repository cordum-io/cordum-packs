# langchain-guard

Full CAP integration for LangChain agents. Tool calls become real CAP jobs — policy-evaluated, scheduled, worker-executed, and audited through the Cordum control plane.

**Not just a policy check — Cordum owns the execution.**

## How It Works

```
LangChain Agent → tool call → CAP job submitted
  → Safety Kernel evaluates policy
  → Scheduler dispatches to worker pool
  → Worker executes tool (inside Cordum's infrastructure)
  → Result flows back to the agent
```

## Install

```bash
# Server-side: policies, schemas, workflows
cordum packs install langchain-guard

# Client-side: Python SDK
pip install cordum-langchain-guard[langchain]
```

## Quick Start

### Pattern A: Per-Agent Wrapping (granular control)

```python
from cordum_langchain_guard import CordumAgent

cordum = CordumAgent("http://localhost:8081", api_key="...")

# 1 line change per agent — tools now run through full CAP
safe_tools = cordum.govern(tools, risk_tags=["write"])
agent = create_react_agent(llm, safe_tools)
```

### Pattern B: Global Hook (zero per-agent changes)

```python
from cordum_langchain_guard import patch_langchain

# One-time setup at app startup
patch_langchain(
    gateway_url="http://localhost:8081",
    api_key="...",
)

# All agents — zero changes. Every tool call goes through CAP.
agent = create_react_agent(llm, tools)  # unchanged
```

## Migration Path

| Phase | Approach | Effort |
|-------|----------|--------|
| Day 1 | `patch_langchain()` | Zero code changes, instant governance |
| Week 2 | `cordum.govern(tools)` for critical agents | 1 line per agent |
| Month 1 | Full per-agent governance with custom policies | Per-agent risk tags |

## Policy Defaults

The pack ships sensible default policies:

| Risk Tag | Decision | Behavior |
|----------|----------|----------|
| `read` | ALLOW | Execute immediately |
| `write` | REQUIRE_APPROVAL | Wait for human approval in dashboard |
| `destructive` | DENY | Blocked, error returned to LLM |
| `secrets` | DENY | Blocked, error returned to LLM |

## Approval Handling

When a tool requires human approval, the adapter returns immediately to the LLM:

```
[AWAITING APPROVAL] delete_file: write actions require human approval
(ref=apr-123, job_id=j-456). A human must approve this action in the
Cordum dashboard before it will execute.
```

The LLM can continue doing other work while the approval is pending. No blocking.

## Remote Workers (Production)

For production deployments, run tool execution as a separate worker process:

```python
from cordum_langchain_guard import ToolRegistry, create_remote_worker

registry = ToolRegistry()
registry.register_many(my_tools)

worker = create_remote_worker(
    registry,
    nats_url="nats://nats:4222",
    redis_url="redis://redis:6379",
)
asyncio.run(worker.run())
```

Requires: `pip install cordum-langchain-guard[nats]`

## Development

```bash
cd packs/langchain-guard/sidecar
pip install -e ".[langchain,dev]"
pytest tests/ -v
```
