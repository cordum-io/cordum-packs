# CrewAI adapter for Cordum

Bridge your CrewAI agents to the governed Cordum MCP surface in one
import. Every tool your Crew calls flows through Cordum's policy engine,
producing the approval gates, audit chain, and SIEM events you already
get from the control plane — no extra configuration on the Crew side.

This tutorial walks you from `pip install` to a running two-agent Crew
in about 15 minutes.

---

## 1. Install

```bash
pip install cordum-adapters[crewai]
```

The `[crewai]` extra pulls in `crewai>=0.30` + `crewai-tools>=0.1`.
The core package has no framework dependencies, so you can install
multiple extras side-by-side (`[crewai,openai-agents]`) without
conflict. Note that `[autogen]` and `[autogen-classic]` are mutually
exclusive — pick one.

## 2. Prerequisites

You need three things running:

1. **A Cordum MCP bridge** — the `cordum-mcp-bridge` subprocess (Go
   binary from `cordum-packs/packs/mcp-bridge/`) that exposes the MCP
   stdio protocol on behalf of your gateway.
2. **A Cordum gateway** — the bridge talks to `CORDUM_GATEWAY_URL` and
   authenticates via `CORDUM_API_KEY`.
3. **A tool registry** — one or more tools registered in Cordum with
   the runtime MCP policy config attached. See the gateway docs for
   the `/api/v1/config?scope=system&id=mcp_policy` write path.

Example environment for the bridge subprocess:

```bash
export CORDUM_GATEWAY_URL=https://gateway.cordum.internal
export CORDUM_API_KEY=...your-key...
export CORDUM_TENANT_ID=default
```

## 3. Your first governed Crew — end to end

```python
from cordum_agent_adapters import McpStdioClient
from cordum_agent_adapters.crewai import build_crew

client = McpStdioClient(
    command=["cordum-mcp-bridge"],
    timeout=30.0,
)

crew = build_crew(
    client,
    agents_config=[
        {
            "role": "repo_researcher",
            "goal": "Find the three most-active repos in the cordum org",
            "backstory": "A pragmatic engineer who loves GitHub stats.",
            "allowed_tool_names": ["list_repos", "get_repo_stats"],
        },
        {
            "role": "writer",
            "goal": "Draft a short summary from the researcher's findings",
            "backstory": "A concise technical writer.",
        },
    ],
    tasks_config=[
        {
            "description": "Pull the cordum org repos and rank by commit count.",
            "expected_output": "A JSON list of repo names ordered by activity.",
            "agent": "repo_researcher",
        },
        {
            "description": "Write a 3-sentence summary.",
            "expected_output": "Plain-text paragraph.",
            "agent": "writer",
        },
    ],
)

result = crew.kickoff()
print(result)
client.close()
```

Or use the client as a context manager so `close()` is guaranteed even
if `kickoff()` raises:

```python
with McpStdioClient(command=["cordum-mcp-bridge"]) as client:
    crew = build_crew(client, ...)
    result = crew.kickoff()
```

## 4. Retry policy

Transient gateway blips are handled by the retry driver. Attach a
`RetryPolicy` to the tool factory and every `_run` wraps in
`retry_call`:

```python
from cordum_agent_adapters.retry import RetryPolicy

policy = RetryPolicy(
    max_attempts=4,
    initial_backoff_s=1.0,
    max_backoff_s=10.0,
    jitter=0.3,
    backoff_multiplier=2.0,
)

crew = build_crew(client, agents_config, tasks_config, retry_policy=policy)
```

### Custom retryable predicate

The default predicate retries every `McpError` except deterministic
tool-denied results (`McpToolError` with `isError=True`). To customise,
pass your own:

```python
from cordum_agent_adapters import McpRpcError
from cordum_agent_adapters.retry import RetryPolicy

def only_rpc_errors(exc: BaseException) -> bool:
    return isinstance(exc, McpRpcError)

policy = RetryPolicy(max_attempts=3, retryable=only_rpc_errors)
```

## 5. Async agents

CrewAI's async agents call `_arun` instead of `_run`. Set `async_mode=True`
and the adapter wires an async coroutine that offloads the MCP call to a
thread (preserving the single-reader-thread invariant of the stdio
client):

```python
crew = build_crew(client, agents_config, tasks_config, async_mode=True)
```

You can combine `retry_policy=` and `async_mode=True` — retries use
`asyncio.sleep` and don't block the event loop.

## 6. Policy enforcement

When a governed tool's call is denied, the gateway returns an MCP
`tool/call` response with `isError: true` and a policy-specific reason.
The adapter wraps this as an `AdapterToolCallError`:

```python
from cordum_agent_adapters import AdapterToolCallError, McpToolError

try:
    result = tool._run(tool, location="SF")
except AdapterToolCallError as err:
    if isinstance(err.cause, McpToolError) and err.cause.result.get("isError"):
        print("Tool denied:", err.cause.message)
    else:
        raise
```

`err.tool_args` carries the redacted arguments (see §8 for what
redaction does). `err.elapsed_ms` is the wall-clock latency. `err.cause`
preserves the original `McpError` subclass so you can introspect
denial codes (`err.cause.result.get("denialCode")`).

### Approvals

Tools gated by the per-tool approval system surface an extra round-trip:
the first call gets denied, an approval record appears in the
`/api/v1/mcp/approvals` queue, and once an admin approves, the same
arguments succeed on retry. Your Crew code doesn't need to know — just
catch `AdapterToolCallError` and prompt the user, or swallow it and let
CrewAI's agent reason about the denial.

## 7. Troubleshooting

### Enable DEBUG logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("cordum_agent_adapters").setLevel(logging.DEBUG)
```

You'll see structured log records on every call:

```
INFO  mcp tool call ok  tool=list_repos elapsed_ms=42
WARN  mcp call retry    attempt=1 backoff_s=0.5 error_class=McpError tool_name=list_repos
```

### Timeout tuning

The stdio client default is 60 seconds; override via the constructor:

```python
client = McpStdioClient(command=[...], timeout=120.0)
```

### Subprocess died

`McpStdioClient.is_alive()` returns `False` when the bridge has exited.
Combine with a retry policy that recreates the client on fatal errors
if you're running long-lived Crews:

```python
if not client.is_alive():
    client = McpStdioClient(command=[...])
```

### Debug the bridge itself

The stub gateway in `tests/integration/_gateway_stub.py` is a good
reference for the wire shape the bridge must produce. Run with
`CORDUM_ADAPTERS_E2E=1 pytest tests/integration/` to see a green path.

## 8. Security notes

### Argument redaction

Every `AdapterToolCallError` scrubs values for any key whose name
matches the regex:

```
(?i)(password|passwd|secret|token|api[_\-]?key|authorization|auth)
```

with word boundaries so `api_version` stays readable while `api_key`,
`apiKey`, and `x-api-key` are replaced with `***REDACTED***`. To extend
the pattern you can post-process arguments before they reach `_run`, or
fork the redaction helper in a wrapping tool. A future release will
make the pattern configurable.

### Never log tool results

The adapter deliberately does NOT log tool return values. Results
frequently contain PII pulled from backing systems (customer records,
support tickets, repo contents). If you need to surface results into a
log, wrap them with your own redactor first.

### Tool-arg provenance

Because `tool_args` on the exception is redacted and captured at call
time, operators can correlate failures in dashboards without risking a
credentials leak. Pair it with the `approval_id` surfaced by the
gateway's audit chain to reconstruct who authorised what.

---

## Reference

- API: `cordum_agent_adapters.crewai.build_crewai_tools`,
  `cordum_agent_adapters.crewai.build_crew`.
- Errors: `AdapterToolCallError`, `AdapterRetryExhaustedError`,
  `AdapterSchemaError`, `AdapterTimeoutError`.
- Retry: `RetryPolicy`, `retry_call`, `retry_call_async`.
- Async: `McpStdioClient.call_tool_async`, `.list_tools_async`,
  `async with client:`.
- Integration test: `tests/integration/test_crewai_e2e.py` (run with
  `CORDUM_ADAPTERS_E2E=1`).
