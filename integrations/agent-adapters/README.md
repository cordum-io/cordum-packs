# Cordum Agent Adapters

Adapters that expose Cordum MCP tools to popular agent frameworks. The core is a
minimal MCP stdio client plus tool-schema helpers.

## Layout

- `cordum_agent_adapters/mcp_client.py`: MCP stdio client.
- `cordum_agent_adapters/openai_tools.py`: MCP tool -> OpenAI tool schema.
- `cordum_agent_adapters/langchain.py`: LangChain adapter.

## Requirements

- Python 3.9+
- `langchain-core` and `pydantic` are optional (required only for the LangChain adapter).

## MCP client (stdio)

```python
from cordum_agent_adapters.mcp_client import McpStdioClient

client = McpStdioClient(
    command=["/usr/local/bin/cordum-mcp-bridge"],
    env={
        "CORDUM_GATEWAY_URL": "http://localhost:8081",
        "CORDUM_API_KEY": "super-secret-key",
        "CORDUM_NATS_URL": "nats://localhost:4222",
        "CORDUM_REDIS_URL": "redis://localhost:6379",
    },
)
client.initialize()

for tool in client.list_tools():
    print(tool["name"])
```

## OpenAI tool schema

```python
from cordum_agent_adapters.openai_tools import mcp_tools_to_openai_tools

tools = client.list_tools()
openai_tools = mcp_tools_to_openai_tools(tools)
```

## LangChain adapter

```python
from cordum_agent_adapters.langchain import build_langchain_tools

langchain_tools = build_langchain_tools(client)
```

## Notes

- The MCP server must be running (use `packs/mcp-bridge`).
- Tool calls are policy-gated by Cordum.
