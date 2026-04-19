# 15 minutes: a governed AutoGen agent (AG2 0.4+)

This walkthrough wires an `autogen-agentchat` assistant to the Cordum
governed-tool surface. At the end you will have:

- an `AssistantAgent` whose tools come from `cordum-mcp-bridge`,
- every tool call audited in Cordum's tamper-evident chain,
- a policy deny that the agent receives as a readable tool-result
  message rather than an exception that kills the loop.

## Prerequisites

| Requirement | How to get it |
|---|---|
| Cordum running locally (gateway + scheduler + safety kernel + NATS + Redis) | `make dev-up` in the `cordum/` repo |
| Cordum API key | `cordumctl auth login` or copy from `.env` |
| `cordum-mcp-bridge` on PATH | `cd cordum-packs/packs/mcp-bridge && go build -o cordum-mcp-bridge ./cmd/cordum-mcp-bridge && mv cordum-mcp-bridge ~/bin/` |
| Python 3.9+ | https://www.python.org |
| An OpenAI-compatible model key | `OPENAI_API_KEY=...`, or point `autogen-ext` at Anthropic / Azure / Ollama |

## 1. Install the adapter

```bash
pip install 'cordum-adapters[autogen]'
```

Do NOT install `[autogen-classic]` in the same interpreter — the two
extras pin incompatible openai versions.

## 2. Connect to the bridge

```python
import os
from cordum_agent_adapters.mcp_client import McpStdioClient

client = McpStdioClient(
    command=["cordum-mcp-bridge"],
    env={
        **os.environ,
        "CORDUM_GATEWAY_URL": "http://localhost:8081",
        "CORDUM_API_KEY": os.environ["CORDUM_API_KEY"],
        "CORDUM_NATS_URL": "nats://localhost:4222",
        "CORDUM_REDIS_URL": "redis://localhost:6379",
    },
)
```

The bridge is a subprocess; the Python client owns its lifecycle — call
`client.close()` on shutdown (a `try/finally` or an `atexit` handler
is fine).

## 3. Build the tool list

```python
from cordum_agent_adapters.autogen import build_ag2_tools

tools = build_ag2_tools(client)
print([t.name for t in tools])
# ['cordum.workflow.run', 'cordum.workflow.cancel', ...]
```

Each tool is an `autogen_core.tools.FunctionTool` with:

- a pydantic args model derived from the MCP `inputSchema`,
- an async wrapper that runs the blocking `client.call_tool` on a worker
  thread so the event loop stays responsive,
- structured exceptions (`CordumPolicyDeniedError`,
  `CordumToolExecutionError`, `ValueError`, `RuntimeError`) for the
  agent to render as tool-result messages.

## 4. Wire up an assistant

```python
from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient

model = OpenAIChatCompletionClient(model="gpt-4.1-mini")
assistant = AssistantAgent(
    name="governed_runner",
    model_client=model,
    tools=tools,
    system_message="You use Cordum tools to run governed workflows.",
)
```

Or let the adapter wire + introspect in one call:

```python
from cordum_agent_adapters.autogen import register_cordum_tools

binding = register_cordum_tools(assistant, client)
# binding.tools == tools, binding.api == 'modern'
```

## 5. Turn on the conversation logger

The gateway's MCP middleware already audits every `tools/call`, so
tool-call turns land in the audit chain for free. Pure-LLM chatter
(no tool call) is recorded by the client-side logger, which ships each
turn through the `cordum.audit.log_turn` MCP tool.

```python
from cordum_agent_adapters.autogen import CordumConversationLogger

logger = CordumConversationLogger(client)   # session_id auto-generated
# In your agent loop, after each message:
logger.log_turn({
    "kind": "message",
    "sender": "assistant",
    "recipient": "user",
    "content": reply_text,
})
```

When the bridge doesn't advertise `cordum.audit.log_turn` (e.g. an
older deployment), the logger emits a single stderr warning and
short-circuits every subsequent turn — the agent never crashes because
audit is degraded.

## 6. Observe the audit trail

```bash
# CLI
cordumctl audit list --session=$SESSION_ID --limit 20

# Or: dashboard → Policy Decision Log, filter by session_id
```

Every tool call is chained with its input, outcome, and policy
decision. The session id lets you correlate a multi-turn run.

## 7. Seed a deny policy, watch the agent recover

Create a policy that denies `cordum.dlq.retry` for the test tenant:

```bash
cordumctl policy bundle create --tenant=demo --yaml <<'YAML'
id: deny-dlq-retry
rules:
  - when: {tool: "cordum.dlq.retry"}
    decision: deny
    reason: "manual review required"
YAML
```

Now drive the agent:

```python
import asyncio
from autogen_agentchat.messages import TextMessage
from autogen_agentchat.ui import Console

async def main():
    msg = TextMessage(content="Retry DLQ job job-123.", source="user")
    await Console(assistant.run_stream(task=msg))

asyncio.run(main())
```

What you should see:

1. The assistant picks `cordum.dlq.retry`.
2. The gateway policy denies it.
3. The adapter translates the `-32099` RPC error into
   `CordumPolicyDeniedError`.
4. AG2 renders that as a ToolCallResultEvent containing the reason
   (`"manual review required"`), so the assistant can apologise,
   explain, and either give up or escalate — WITHOUT the loop crashing.

## Next steps

- Read [autogen_classic.md](autogen_classic.md) if you are still on
  `pyautogen~=0.2`.
- Browse `tests/integration/test_autogen_e2e.py` for a hermetic
  end-to-end example (no OpenAI key required — uses a scripted stub).
- See the [CrewAI tutorial](../crewai.md) if you have colleagues on
  CrewAI; the Cordum surface is identical.
