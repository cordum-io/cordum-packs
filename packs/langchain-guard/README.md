# langchain-guard

Govern your LangChain agents through Cordum. Tool calls become real CAP jobs — policy-evaluated, scheduled, worker-executed, and audited. Cordum doesn't just check permissions — it owns the execution.

## Prerequisites

- A running Cordum instance ([quickstart](https://docs.cordum.io/quickstart))
- Your `CORDUM_API_KEY` and gateway URL (default: `http://localhost:8081`)
- A LangChain agent with tools you want to govern

## Install

```bash
# 1. Install the pack (adds policies, schemas, and workflows to your Cordum instance)
cordum packs install langchain-guard

# 2. Install the Python SDK in your agent's environment
pip install cordum-langchain-guard[langchain]
```

## Quick Start

### Option A: Govern specific agents (recommended)

Best when you need different risk tags or policies per agent.

```python
from langchain.agents import create_react_agent
from langchain_community.tools import DuckDuckGoSearchRun, ShellTool
from cordum_langchain_guard import CordumAgent

# Your existing tools
tools = [DuckDuckGoSearchRun(), ShellTool()]

# Connect to Cordum (one-time setup, reuse across agents)
cordum = CordumAgent(
    gateway_url="http://localhost:8081",
    api_key="your-api-key",
)

# Wrap tools — this is the only change to your agent code
safe_tools = cordum.govern(tools, risk_tags=["write"])

# Use the governed tools in your agent as normal
agent = create_react_agent(llm, safe_tools)
agent.invoke({"input": "List files in /tmp"})
```

**What happens now:**
- `DuckDuckGoSearchRun` → submitted as a CAP job → Safety Kernel checks policy → worker executes → result returned
- `ShellTool` with `risk_tags=["write"]` → policy requires human approval → LLM gets `[AWAITING APPROVAL]` message immediately → human approves in Cordum dashboard → tool executes

### Option B: Govern all agents at once (zero code changes)

Best for quick adoption across many agents. Call once at app startup.

```python
from cordum_langchain_guard import patch_langchain

# One line at startup — every LangChain tool call now goes through Cordum
patch_langchain(
    gateway_url="http://localhost:8081",
    api_key="your-api-key",
    default_risk_tags=["write"],
)

# All your existing agents work unchanged
agent1 = create_react_agent(llm, tools_1)  # governed automatically
agent2 = create_react_agent(llm, tools_2)  # governed automatically
```

To undo: `from cordum_langchain_guard import unpatch_langchain; unpatch_langchain()`

## What the LLM Sees

When a tool call goes through Cordum, the LLM gets different responses depending on the policy decision:

| Decision | What the LLM receives | What happens |
|----------|----------------------|--------------|
| **ALLOW** | The normal tool result | Tool executed by Cordum worker, result returned |
| **DENY** | `[BLOCKED] tool_name: reason` | Tool blocked, LLM can try a different approach |
| **REQUIRE_APPROVAL** | `[AWAITING APPROVAL] tool_name: reason (job_id=...)` | Human must approve in dashboard; LLM can continue other work |
| **THROTTLE** | The normal tool result (after a delay) | Cordum delays execution, then proceeds |

## Default Policies

The pack ships these policies out of the box:

| Risk Tag | Decision | Why |
|----------|----------|-----|
| `read` | ALLOW | Read-only operations are safe |
| `write` | REQUIRE_APPROVAL | Write operations need a human in the loop |
| `destructive` | DENY | Destructive operations are blocked entirely |
| `secrets` | DENY | Accessing secrets is blocked entirely |

### Customizing policies

Edit the policy rules after installing the pack:

```yaml
# Override via Cordum dashboard (Policy Studio) or API:
# POST /api/v1/policies
rules:
  - id: allow-search-tools
    match:
      capabilities: ["duckduckgo_search", "wikipedia"]
      risk_tags: ["read"]
    decision: allow

  - id: approve-file-writes
    match:
      capabilities: ["shell_tool", "file_write"]
      risk_tags: ["write"]
    decision: require_approval
    reason: "File system access requires approval"

  - id: block-dangerous
    match:
      risk_tags: ["destructive"]
    decision: deny
    reason: "Destructive operations are not permitted"
```

## Migration Guide

For teams with many existing LangChain agents:

| Phase | What to do | Effort |
|-------|-----------|--------|
| **Day 1** | Add `patch_langchain()` to your app startup | 1 line, zero agent changes |
| **Week 2** | Move critical agents to `cordum.govern()` with per-agent risk tags | 1 line per agent |
| **Month 1** | Define custom policies per agent type in Cordum dashboard | Policy YAML |

## Configuration

### CordumAgent parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `gateway_url` | `http://localhost:8081` | Cordum API Gateway URL |
| `api_key` | `""` | API key for authentication |
| `tenant_id` | `"default"` | Tenant for multi-tenant deployments |
| `timeout` | `20.0` | HTTP request timeout (seconds) |
| `poll_interval` | `0.75` | How often to poll for job completion (seconds) |
| `poll_timeout` | `60.0` | Max time to wait for a job to complete (seconds) |

### govern() parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `tools` | required | List of LangChain `BaseTool` instances |
| `risk_tags` | `[]` | Risk tags applied to all tool calls (e.g. `["write", "network"]`) |
| `topic` | `job.langchain-guard.tool` | CAP topic for job submission |
| `labels` | `{}` | Extra key-value labels for policy matching |
| `start_worker` | `True` | Start an in-process worker for tool execution |

## Production: Remote Workers

By default, tool execution happens in-process (same Python process as your agent). For production, run workers separately so they can scale independently:

**Agent process** (submits jobs):
```python
cordum = CordumAgent("http://gateway:8081", api_key="...")
safe_tools = cordum.govern(tools, start_worker=False)  # no local worker
```

**Worker process** (executes tools):
```python
import asyncio
from cordum_langchain_guard import ToolRegistry, create_remote_worker

registry = ToolRegistry()
registry.register_many(my_tools)

worker = create_remote_worker(
    registry,
    nats_url="nats://nats:4222",
    redis_url="redis://redis:6379",
    max_parallel=4,
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
