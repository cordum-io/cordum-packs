# langchain-guard

Govern your LangChain agents through Cordum. Tool calls become real CAP jobs — policy-evaluated, scheduled, worker-executed, and audited. Cordum doesn't just check permissions — it owns the execution.

## Why This Exists

Without governance, your LangChain agent can call any tool, any time, with any arguments. That's fine in development. In production, you need:

- **Policy enforcement** — block dangerous operations before they execute
- **Human approval gates** — require sign-off for sensitive actions
- **Audit trails** — know exactly what every agent did, when, and why it was allowed
- **Centralized control** — one dashboard to manage policies across all your agents

`langchain-guard` gives you all of this with minimal code changes.

## How It Works

```
Without langchain-guard:
  LangChain Agent → tool._run() → executes locally → no oversight

With langchain-guard:
  LangChain Agent → tool call intercepted
    → CAP job submitted to Cordum gateway
    → Safety Kernel evaluates policy rules
    → Decision: ALLOW / DENY / REQUIRE_APPROVAL / THROTTLE
    → If allowed: Scheduler dispatches to worker pool
    → Worker executes tool inside Cordum's infrastructure
    → Result + audit record flows back to the agent
```

The key difference: **your agent doesn't execute tools directly anymore**. Every tool call goes through Cordum's full governance pipeline. You get policy enforcement, approval workflows, and audit logging — all without changing your agent logic.

## Prerequisites

Before you start, you need:

1. **A running Cordum instance** — [quickstart guide](https://docs.cordum.io/quickstart)
   ```bash
   cd cordum && ./tools/scripts/quickstart.sh
   ```
2. **Your API key** — set during Cordum setup (check your `.env` file)
3. **Gateway URL** — default is `https://localhost:8081` (Cordum uses TLS by default)
4. **A LangChain agent** with tools you want to govern

> **Note:** Cordum generates self-signed TLS certificates during setup. For local development, you may need to disable certificate verification — see the [Configuration](#configuration) section below.

## Install

```bash
# Step 1: Install the pack into your Cordum instance
# This adds default policies, schemas, and workflows
cordum packs install langchain-guard

# Step 2: Install the Python SDK in your agent's environment
pip install cordum-langchain-guard[langchain]
```

Verify the install:
```python
>>> from cordum_langchain_guard import CordumAgent
>>> print("Ready!")
```

---

## Quick Start

### Option A: Govern specific agents (recommended)

Best when you need different risk tags or policies per agent.

```python
from langchain.agents import create_react_agent
from langchain_openai import ChatOpenAI
from langchain_community.tools import DuckDuckGoSearchRun, ShellTool
from cordum_langchain_guard import CordumAgent

# --- Your existing code (unchanged) ---
llm = ChatOpenAI(model="gpt-4")
tools = [DuckDuckGoSearchRun(), ShellTool()]

# --- Add these 2 lines ---
cordum = CordumAgent("https://localhost:8081", api_key="your-api-key")
safe_tools = cordum.govern(tools, risk_tags=["write"])

# --- Use safe_tools instead of tools ---
agent = create_react_agent(llm, safe_tools)
result = agent.invoke({"input": "Search for the weather in London"})
print(result)
```

That's it. Two lines added, one line changed (`tools` → `safe_tools`).

### Option B: Govern all agents at once (zero code changes)

Best for quick adoption when you have many agents. Call once at app startup.

```python
# app.py — add this before any agent code runs
from cordum_langchain_guard import patch_langchain

patch_langchain(
    gateway_url="https://localhost:8081",
    api_key="your-api-key",
    default_risk_tags=["write"],
)

# --- Everything below is your existing code, completely unchanged ---

from langchain.agents import create_react_agent
from langchain_community.tools import DuckDuckGoSearchRun, ShellTool

agent1 = create_react_agent(llm, [DuckDuckGoSearchRun()])  # governed
agent2 = create_react_agent(llm, [ShellTool()])             # governed
agent3 = create_react_agent(llm, my_custom_tools)           # governed
# Every tool call across ALL agents now goes through Cordum
```

To undo at any time:
```python
from cordum_langchain_guard import unpatch_langchain
unpatch_langchain()  # back to normal
```

---

## What Your Agent Sees

When a tool call goes through Cordum, the LLM gets different responses depending on the policy decision:

### ALLOW — tool executes normally
```
Agent: "I'll search for the weather."
Tool result: "London weather: 15°C, partly cloudy..."
```
The agent doesn't know governance is happening. It just gets the result.

### DENY — tool is blocked
```
Agent: "I'll delete the database."
Tool result: "[BLOCKED] delete_db: Destructive operations are not permitted"
```
The LLM sees the block reason and can try a different approach.

### REQUIRE_APPROVAL — waiting for a human
```
Agent: "I'll send the email."
Tool result: "[AWAITING APPROVAL] send_email: write actions require human approval
(ref=apr-123, job_id=j-456). A human must approve this action in the
Cordum dashboard before it will execute."
```
The LLM gets this **immediately** (no blocking) and can continue doing other work. A human approves or rejects in the Cordum dashboard.

### THROTTLE — delayed execution
```
Agent: "I'll call the API."
[Cordum waits 5 seconds]
Tool result: "API response: {data: ...}"
```
The agent sees the result after a delay. Rate limiting is transparent.

---

## Default Policies

The pack ships these policies out of the box. No configuration needed — they apply as soon as you install the pack:

| Risk Tag | Decision | What happens |
|----------|----------|-------------|
| `read` | **ALLOW** | Tool executes immediately. Search, lookup, and read operations are safe by default. |
| `write` | **REQUIRE_APPROVAL** | A human must approve in the Cordum dashboard before the tool executes. |
| `destructive` | **DENY** | Tool is blocked. The LLM gets a `[BLOCKED]` message with the reason. |
| `secrets` | **DENY** | Tool is blocked. Access to secrets, credentials, and keys is denied. |

### How risk tags work

You assign risk tags when you govern your tools:

```python
# All tools in this agent get the "write" risk tag
safe_tools = cordum.govern(tools, risk_tags=["write"])

# Different tags for different groups of tools
read_tools = cordum.govern([search, lookup], risk_tags=["read"])
write_tools = cordum.govern([file_write, send_email], risk_tags=["write"])
admin_tools = cordum.govern([delete_user, drop_table], risk_tags=["destructive"])

# Combine them in one agent
agent = create_react_agent(llm, read_tools + write_tools + admin_tools)
```

### Customizing policies

You can modify policies after installing the pack — through the Cordum dashboard (Policy Studio) or via the API:

```bash
# Example: allow a specific tool even with "write" tag
curl -X POST https://localhost:8081/api/v1/policies \
  -H "X-API-Key: $CORDUM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "rules": [
      {
        "id": "allow-send-slack",
        "match": {
          "capabilities": ["send_slack_message"],
          "risk_tags": ["write"]
        },
        "decision": "allow",
        "reason": "Slack messages are pre-approved"
      }
    ]
  }'
```

Policy rules are evaluated in order. The first matching rule wins.

---

## Migration Guide

For teams with many existing LangChain agents:

### Day 1: Instant governance (5 minutes)

```python
# Add to your app startup — that's it
from cordum_langchain_guard import patch_langchain
patch_langchain(gateway_url="https://localhost:8081", api_key="...")
```

All 20+ agents are now governed. Zero code changes to any agent file. Monitor the Cordum dashboard to see what your agents are doing.

### Week 2: Per-agent control

Move critical agents to explicit governance with tailored risk tags:

```python
# agents/financial_agent.py
from my_app.cordum_config import cordum  # shared CordumAgent instance
safe_tools = cordum.govern(tools, risk_tags=["write", "financial"])
```

### Month 1: Custom policies per team

Define policies per agent type, team, or environment in the Cordum dashboard:

```yaml
rules:
  - id: finance-team-approval
    match:
      labels: { team: "finance" }
      risk_tags: ["financial"]
    decision: require_approval
    reason: "Financial operations require CFO approval"
```

---

## Configuration Reference

### CordumAgent

```python
cordum = CordumAgent(
    gateway_url="https://localhost:8081",  # Cordum API Gateway URL
    api_key="your-key",                   # API key (from .env or secrets manager)
    tenant_id="default",                  # Tenant for multi-tenant setups
    timeout=20.0,                         # HTTP request timeout (seconds)
    poll_interval=0.75,                   # Job completion poll frequency (seconds)
    poll_timeout=60.0,                    # Max wait for job completion (seconds)
)
```

### TLS / Self-Signed Certificates

For local development with Cordum's self-signed certs, set the environment variable:

```bash
export CORDUM_TLS_INSECURE=true
```

Or in Python, configure `httpx` before creating the agent:

```python
import httpx
# For development only — do not use in production
cordum = CordumAgent("https://localhost:8081", api_key="...")
# The gateway client uses httpx which respects SSL_CERT_FILE env var
```

For production, point to your CA certificate:

```bash
export SSL_CERT_FILE=/path/to/cordum/certs/ca.crt
```

### cordum.govern()

```python
safe_tools = cordum.govern(
    tools,                                # List of LangChain BaseTool instances
    risk_tags=["write"],                  # Risk tags for policy matching
    topic="job.langchain-guard.tool",     # CAP topic (usually leave as default)
    labels={"team": "backend"},           # Extra labels for policy matching
    start_worker=True,                    # Start in-process worker (True for dev)
)
```

### patch_langchain()

```python
patch_langchain(
    gateway_url="https://localhost:8081",
    api_key="your-key",
    tenant_id="default",
    default_risk_tags=["write"],          # Applied to ALL tool calls globally
    topic="job.langchain-guard.tool",
    poll_timeout=60.0,
)
```

---

## Testing Without Cordum

You can test your governed agents without a running Cordum instance by mocking the gateway:

```python
import respx
from httpx import Response
from cordum_langchain_guard import CordumAgent

# Mock the gateway to always allow
with respx.mock:
    respx.post("http://mock:8081/api/v1/jobs").mock(
        return_value=Response(200, json={"job_id": "test-1", "trace_id": "t-1"})
    )
    respx.get("http://mock:8081/api/v1/jobs/test-1").mock(
        return_value=Response(200, json={
            "id": "test-1",
            "state": "SUCCEEDED",
            "result": "mocked tool output",
        })
    )

    cordum = CordumAgent("http://mock:8081")
    safe_tools = cordum.govern(my_tools, risk_tags=["read"])
    # Run your agent tests here
```

To test denial:
```python
respx.get("http://mock:8081/api/v1/jobs/test-1").mock(
    return_value=Response(200, json={
        "id": "test-1",
        "state": "DENIED",
        "safety_reason": "blocked by test policy",
    })
)
```

---

## Error Handling

The adapter handles errors gracefully so your agent doesn't crash:

| Scenario | What happens |
|----------|-------------|
| **Cordum gateway unreachable** | `ToolException` raised — LLM sees `[GATEWAY ERROR]` and can retry or skip |
| **Job times out** | `ToolException` raised after `poll_timeout` seconds |
| **Worker crashes** | Job state becomes `FAILED`, LLM sees `[FAILED] tool_name: error message` |
| **Invalid tool input** | Serialized as-is — Cordum validates at the worker level |

If you want to catch governance errors in your application code:

```python
from cordum_langchain_guard import GatewayError, ApprovalRequiredError

try:
    result = agent.invoke({"input": "do something dangerous"})
except Exception as e:
    if "[BLOCKED]" in str(e):
        print("Agent tried something that was blocked by policy")
```

---

## Async Support

Both `govern()` and `patch_langchain()` work with async LangChain agents out of the box:

```python
# Async agent — no extra setup needed
result = await agent.ainvoke({"input": "search for something"})
```

The adapter automatically uses the async gateway client for `_arun` calls.

---

## Production: Remote Workers

By default, tools execute in-process (same Python process as your agent). For production, separate them:

### Why separate workers?

- **Scale independently** — run 10 workers for heavy tools, 1 for lightweight ones
- **Isolation** — tool crashes don't take down your agent
- **Security** — workers can run in restricted environments with limited permissions
- **Multi-agent** — multiple agents share the same worker pool

### Agent process (submits jobs, no local execution)

```python
cordum = CordumAgent("http://gateway:8081", api_key="...")
safe_tools = cordum.govern(tools, start_worker=False)  # disable local worker
```

### Worker process (executes tools)

```python
import asyncio
from cordum_langchain_guard import ToolRegistry, create_remote_worker
from my_app.tools import search_tool, write_tool, analyze_tool

registry = ToolRegistry()
registry.register_many([search_tool, write_tool, analyze_tool])

worker = create_remote_worker(
    registry,
    nats_url="nats://nats:4222",
    redis_url="redis://redis:6379",
    pool="langchain-guard",
    max_parallel=4,  # handle 4 tool calls concurrently
)

asyncio.run(worker.run())
```

Requires: `pip install cordum-langchain-guard[nats]`

---

## Comparison: langchain-guard vs cordum-guard

| | `langchain-guard` (this pack) | `cordum-guard` (CAP SDK) |
|--|--|--|
| **Architecture** | Full CAP — tools execute through Cordum workers | HTTP shortcut — policy check only, tools run locally |
| **Cordum controls execution?** | Yes | No — agent runs tools itself |
| **Audit trail** | Complete — Cordum sees inputs, outputs, timing | Partial — only the policy decision |
| **Worker scaling** | Yes — separate worker processes | No — always in-process |
| **Approval workflows** | Non-blocking, returns to LLM immediately | Blocking or polling |
| **Install** | `cordum packs install` + `pip install` | `pip install` only |
| **Best for** | Production deployments, compliance | Quick prototyping, local development |

If you're just getting started, `cordum-guard` is simpler. When you need real governance in production, upgrade to `langchain-guard`.

---

## Troubleshooting

**"Connection refused" when calling tools**
- Is Cordum running? Check `curl -sk https://localhost:8081/api/v1/health -H "X-API-Key: $CORDUM_API_KEY"`
- Is your `gateway_url` correct?

**Tools execute but nothing shows in the dashboard**
- Make sure you installed the pack: `cordum packs install langchain-guard`
- Check that `api_key` matches your Cordum instance

**"[GATEWAY ERROR]" in tool responses**
- Check Cordum gateway logs for details
- Increase `timeout` if the gateway is slow to respond

**All tools are DENIED**
- Check your risk tags — `destructive` and `secrets` are denied by default
- Review policies in the Cordum dashboard (Policy Studio)

**Agent hangs waiting for tool result**
- Increase `poll_timeout` (default: 60s)
- Check if the job is stuck in `APPROVAL_REQUIRED` — approve or reject it in the dashboard

---

## Development

```bash
cd packs/langchain-guard/sidecar
pip install -e ".[langchain,dev]"
pytest tests/ -v
```

23 tests covering: gateway client, tool adapter, agent wrapper, and worker execution.
