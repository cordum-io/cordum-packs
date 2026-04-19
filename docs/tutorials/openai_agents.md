# 15 minutes: governed OpenAI Agents SDK agent

Build a governed agent using OpenAI's [Agents SDK](https://github.com/openai/openai-agents-python)
with every tool call routed through Cordum's safety kernel. Policy
denials become LLM-visible strings instead of crashing the run, so the
agent can gracefully switch strategy when the kernel refuses a call.

## Prerequisites

- A running Cordum gateway (`make dev-up` from the `cordum` repo).
- An API key for the gateway (`CORDUM_API_KEY`).
- An OpenAI API key (`OPENAI_API_KEY`), or follow the FakeModel
  pathway below to run without OpenAI costs.
- The `cordum-mcp-bridge` binary on your `PATH` (install from
  `cordum-packs/packs/mcp-bridge`).
- Python 3.9+ with:

  ```bash
  pip install cordum-agent-adapters[openai-agents]
  ```

## 1. Spawn the MCP bridge

```python
import os
from cordum_agent_adapters.mcp_client import McpStdioClient

client = McpStdioClient(
    command=["cordum-mcp-bridge"],
    env={
        **os.environ,
        "CORDUM_GATEWAY_URL": os.environ["CORDUM_GATEWAY_URL"],
        "CORDUM_API_KEY": os.environ["CORDUM_API_KEY"],
    },
)
```

`McpStdioClient` owns the subprocess and its stdio pipes. Use it as a
context manager so the process is always cleaned up:

```python
with client:
    tools = client.list_tools()
    print(f"{len(tools)} governed tools available")
```

## 2. Build `FunctionTool` instances

```python
from cordum_agent_adapters.openai_agents import build_openai_agent_tools

cordum_tools = build_openai_agent_tools(client)
```

Each MCP tool is converted into an Agents SDK `FunctionTool` with a
strict JSON Schema (`additionalProperties: false`, every property
typed). The async `on_invoke_tool` callback marshals arguments,
proxies through `client.call_tool`, and flattens the MCP content
blocks into a string for the LLM.

## 3. Wire up an `Agent`

```python
from agents import Agent
from cordum_agent_adapters.openai_agents import register_cordum_mcp

base_agent = Agent(
    name="ops-bot",
    instructions="You operate the Cordum control plane. Use the tools sparingly.",
    model="gpt-4.1-mini",
)

agent = register_cordum_mcp(base_agent, client)
```

`register_cordum_mcp` returns a fresh Agent with the Cordum tools
merged onto any existing `tools` list. It refuses to run when
`agent.mcp_servers` is already set — the SDK's native MCP support
and the Cordum bridge are two sources of truth and we don't want
silent ambiguity.

## 4. Run with governance + session audit

```python
import asyncio
from cordum_agent_adapters.audit import CordumConversationLogger
from cordum_agent_adapters.openai_agents import run_governed, tee_events

logger = CordumConversationLogger(client)

async def main():
    result = await run_governed(
        agent,
        "What workflows are defined in this tenant?",
        client=client,
        logger=logger,
    )
    async for ev in tee_events(result, logger):
        # Emit to stdout, a websocket, your own UI — whatever you need.
        print(getattr(ev, "type", "?"), getattr(ev, "item", ""))
    print(f"Session {logger.session_id} audited {logger.session_id!r}")

asyncio.run(main())
```

`run_governed` is a thin wrapper over `Runner.run_streamed`: it
injects a `cordum_session_id` into `trace_metadata` so the SDK's
native tracing correlates with Cordum's audit chain. `tee_events`
yields every SDK stream event to the caller **and** tees
tool-call/output items to `CordumConversationLogger.log_turn` so the
full conversation lands in the gateway's audit pipeline.

## 5. See `[POLICY DENIED]` in action

Seed a deny rule for one of the tools (via the dashboard or the
`cordumctl policy` CLI) — say you block `cordum.dlq.retry` for the
tenant you're logged in as. On the next run the agent's tool call
will receive:

```
[POLICY DENIED] tool=cordum.dlq.retry approval_id=<id> reason=<rule>.
Try a different approach or request approval.
```

as the tool result. Because this arrives as a string (not an
exception), the Runner loop continues and the LLM sees the denial in
its next turn. A well-instructed agent will adjust plan, surface the
approval id to the user, or skip the destructive step.

## 6. Run without OpenAI costs

The integration test ships a `FakeModel` that scripts tool calls
deterministically. Use it to test your agent wiring without burning
tokens:

```python
from tests.integration._fake_model import FakeModel, ScriptedTurn

model = FakeModel([
    ScriptedTurn(tool_calls=[{"name": "cordum.workflow.list", "arguments": {}}]),
    ScriptedTurn(tool_calls=[{"name": "cordum.dlq.retry", "arguments": {"job_id": "j1"}}]),
    ScriptedTurn(content="I listed workflows and attempted a retry."),
])
agent = Agent(name="fake", tools=cordum_tools, model=model)
```

This is the same test double the `test_openai_agents_e2e.py`
integration test uses, so it's a good baseline for CI.

## Next steps

- [CrewAI adapter](./crewai.md) — `Crew` + `Agent` integration.
- [AutoGen adapter](./autogen.md) — classic + AG2 variants.
- [Error handling](../crewai.md#typed-errors) — the shared
  `AdapterError` hierarchy and the `mcp_error_to_openai_agents_message`
  translator live in `cordum_agent_adapters.errors`.
