# cordum-adapters

Ship any AI-agent framework through [Cordum](https://cordum.io) for
scope-filtered, policy-gated, tamper-evidently audited tool calls —
with a one-line adapter plus your existing framework code.

## What this is

`cordum-adapters` wraps the [Cordum MCP bridge](https://github.com/cordum-io/cordum-packs/tree/main/packs/mcp-bridge)
as native tool objects for four agent frameworks:

| Framework | Install | Tool type | Module |
|---|---|---|---|
| CrewAI | `pip install cordum-adapters[crewai]` | `crewai.tools.BaseTool` | `cordum_agent_adapters.crewai` |
| AutoGen 0.4+ (AG2) | `pip install cordum-adapters[autogen]` | `autogen_core.tools.BaseTool` | `cordum_agent_adapters.autogen` |
| pyautogen 0.2 (legacy) | `pip install cordum-adapters[autogen-classic]` | `(functions, function_map)` | `cordum_agent_adapters.autogen` |
| OpenAI Agents SDK | `pip install cordum-adapters[openai-agents]` | `agents.FunctionTool` | `cordum_agent_adapters.openai_agents` |
| LangChain | `pip install cordum-adapters[langchain]` | `langchain_core.tools.BaseTool` | `cordum_agent_adapters.langchain` |

Every adapter funnels calls through the same MCP stdio client, so the
Cordum gateway's scope filter, approval gate, outbound signer, and
`mcp.tool_invocation` audit chain all apply uniformly.

## Install

Base install (no framework deps, MCP stdio client only):

```bash
pip install cordum-adapters
```

Per-framework install — pick exactly one of `autogen` / `autogen-classic`
(they pin incompatible openai versions):

```bash
pip install cordum-adapters[crewai]
pip install cordum-adapters[autogen]          # AG2 0.4+
pip install cordum-adapters[autogen-classic]  # pyautogen 0.2
pip install cordum-adapters[openai-agents]
pip install cordum-adapters[langchain]
pip install cordum-adapters[all]              # picks modern AG2
```

Python 3.10+ supported (framework deps `crewai>=0.30`, `autogen-core>=0.4`,
`openai-agents>=0.1` all require ≥3.10). `[dev]` adds pytest + build +
twine for contributors.

## MCP client quickstart (5 lines)

```python
from cordum_agent_adapters.mcp_client import McpStdioClient

client = McpStdioClient(
    command=["cordum-mcp-bridge"],
    env={"CORDUM_GATEWAY_URL": "http://localhost:8081",
         "CORDUM_API_KEY": "<your-key>"},
)
print([tool["name"] for tool in client.list_tools()])
```

`cordum-mcp-bridge` is a Go binary shipped by
[cordum-packs/packs/mcp-bridge](https://github.com/cordum-io/cordum-packs/tree/main/packs/mcp-bridge).
Build with `go install` or copy from a release artefact onto your
`$PATH`.

## CrewAI — 15-minute tutorial

```python
from cordum_agent_adapters.crewai import build_crewai_tools
tools = build_crewai_tools(client)

# Attach to your Crew's Agent.tools, or use the convenience wrapper
# build_crew() to wire agents + tasks from declarative config.
```

Full walkthrough with retry, async, policy-denied `AdapterToolCallError`
handling, and the `build_crew()` declarative helper:
[docs/crewai.md](docs/crewai.md).

## AutoGen (AG2 0.4+) — 15-minute tutorial

```python
from cordum_agent_adapters.autogen import (
    build_ag2_tools, register_cordum_tools, CordumConversationLogger,
)

tools = build_ag2_tools(client)                          # list[BaseTool]
logger = CordumConversationLogger(client)                # audits each turn
binding = register_cordum_tools(assistant, client, logger=logger)
```

Full walkthrough including `AssistantAgent` wiring,
`RoundRobinGroupChat`, and the seed-a-deny-policy walkthrough:
[docs/tutorials/autogen.md](docs/tutorials/autogen.md).

Legacy `pyautogen` 0.2? See
[docs/tutorials/autogen_classic.md](docs/tutorials/autogen_classic.md).

## OpenAI Agents SDK — 15-minute tutorial

```python
from cordum_agent_adapters.openai_agents import (
    build_openai_agent_tools, register_cordum_mcp, run_governed, tee_events,
)
from cordum_agent_adapters.audit import CordumConversationLogger

tools = build_openai_agent_tools(client)          # list[agents.FunctionTool]
agent = register_cordum_mcp(my_agent, client)     # clones agent with tools
logger = CordumConversationLogger(client)

result = await run_governed(agent, "task prompt", client=client, logger=logger)
async for event in tee_events(result, logger):
    ...
```

Full walkthrough with scripted-model E2E test + policy-deny handling:
[../../docs/tutorials/openai_agents.md](../../docs/tutorials/openai_agents.md).

## LangChain — 15-minute tutorial

```python
from cordum_agent_adapters.langchain import build_langchain_tools
tools = build_langchain_tools(client)            # list[BaseTool]
# Pass into create_react_agent / create_openai_tools_agent / …
```

The LangChain adapter is a thin wrapper; a dedicated tutorial is
tracked for a future release.

## FAQ

**Can I install `[autogen]` and `[autogen-classic]` together?**
No. pyautogen 0.2 transitively requires `openai<1.0`; autogen-agentchat
0.4+ requires `openai>=1.0`. `pip install` will error. Pick one. If you
need to migrate, uninstall pyautogen first, then install the `[autogen]`
extra.

**Python version matrix.** Python 3.11 and 3.12 are CI-covered
(matrix `python-version: ['3.11', '3.12']` in
`.github/workflows/agent-adapters.yml`). 3.10 is supported per
`requires-python=">=3.10"` in `pyproject.toml` but not in CI. 3.13 is
expected to work; raise an issue if you hit a snag. Python 3.9 is
NOT supported — the underlying framework SDKs (crewai>=0.30,
autogen-core>=0.4, openai-agents) require ≥3.10.

**Windows path caveat.** `cordum-mcp-bridge` must be on `PATH`. On
Windows/MSYS use forward slashes or rely on `shutil.which`; the
adapter never hard-codes a path separator.

**Where do audit events land?**
The Cordum gateway's Merkle audit chain captures every inbound tool
call. Outbound calls (adapter → gateway) also land on
`mcp.tool_outbound_invocation` SIEMEvents when `CORDUM_NATS_URL` is
set (the bridge auto-routes through it). Query
`GET /api/v1/audit/export` or the dashboard Policy Decision Log.

**License.** Business Source License 1.1 (see `LICENSE`). Free to use
with the documented additional-use grant — open an issue or contact
engineering@cordum.io for commercial licensing.

## Links

- [Cordum docs](https://cordum.io/docs)
- [Cordum API reference](https://github.com/cordum/cordum/blob/main/docs/api/openapi/cordum-api.yaml)
- [Changelog](CHANGELOG.md)
- [Issues](https://github.com/cordum-io/cordum-packs/issues)
