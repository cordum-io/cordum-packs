# 15 minutes: a governed AutoGen agent (classic pyautogen 0.2)

Companion to [autogen.md](autogen.md) for teams still on the
pre-0.4 API. The adapter keeps the legacy
`(functions, function_map)` shape intact so existing
`ConversableAgent.register_function` callers work unchanged.

## Prerequisites

Same as the modern walkthrough (Cordum running, API key,
`cordum-mcp-bridge` on PATH, an OpenAI-compatible model key) plus:

- Python 3.9+
- `pyautogen~=0.2` (install via the extra below).

Do **not** install the `[autogen]` extra in the same interpreter —
`autogen` (AG2 0.4+) and `autogen-classic` pin incompatible openai
versions.

## 1. Install

```bash
pip install 'cordum-adapters[autogen-classic]'
```

## 2. Connect + build tools

```python
import os
from autogen import ConversableAgent
from cordum_agent_adapters.autogen import (
    build_autogen_tools,
    CordumConversationLogger,
    register_cordum_tools,
)
from cordum_agent_adapters.mcp_client import McpStdioClient

client = McpStdioClient(
    command=["cordum-mcp-bridge"],
    env={**os.environ, "CORDUM_GATEWAY_URL": "http://localhost:8081"},
)

functions, function_map = build_autogen_tools(client)
```

`functions` is a list of OpenAI function schemas; `function_map` maps
tool names to callables. A classic ConversableAgent consumes both.

## 3. Wire the agent

```python
agent = ConversableAgent(
    name="governed_runner",
    llm_config={"functions": functions, "config_list": [{"model": "gpt-4"}]},
)
agent.register_function(function_map)
```

Or let the adapter do it:

```python
logger = CordumConversationLogger(client)
register_cordum_tools(agent, client, logger=logger, api="classic")
```

`register_cordum_tools` also attaches a reply hook that feeds the
conversation logger on every turn.

## 4. Error handling

pyautogen 0.2 terminates the conversation if a registered function
raises. The adapter protects you: every MCP error is translated to an
`ERROR:`-prefixed string that the LLM reads on the next turn and can
respond to. For example, a policy deny comes back as:

```
ERROR: policy denied (manual review required) — approval_id=apr-42
```

The model typically apologises to the user and either escalates or
tries a different tool — exactly the UX you want for a governed
agent.

## 5. Observe the audit trail

Same as the modern path: the gateway's MCP middleware audits every
`tools/call`. The CordumConversationLogger records pure-LLM turns via
`cordum.audit.log_turn`. Inspect:

```bash
cordumctl audit list --session=$LOGGER_SESSION_ID
```

## Migration to AG2 0.4+

The same `register_cordum_tools(agent, client)` call works for both
APIs — it duck-types the agent and picks the right path. When you
upgrade, swap the extra:

```bash
pip uninstall cordum-adapters pyautogen
pip install 'cordum-adapters[autogen]'
```

Then follow [autogen.md](autogen.md) for the modern wire-up. Your
existing Cordum policy bundles, audit chain, and tool definitions all
roll forward unchanged.
