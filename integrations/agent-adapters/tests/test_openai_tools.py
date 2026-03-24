"""Tests for the OpenAI tools adapter."""

from cordum_agent_adapters.openai_tools import (
    mcp_tool_to_openai_tool,
    mcp_tools_to_openai_tools,
)


def test_mcp_tool_to_openai_tool_basic():
    tool = {
        "name": "search",
        "description": "Search the web",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    }
    result = mcp_tool_to_openai_tool(tool)
    assert result["type"] == "function"
    assert result["function"]["name"] == "search"
    assert result["function"]["description"] == "Search the web"
    assert result["function"]["parameters"]["type"] == "object"
    assert "query" in result["function"]["parameters"]["properties"]


def test_mcp_tool_to_openai_tool_missing_schema():
    tool = {"name": "ping", "description": "Ping"}
    result = mcp_tool_to_openai_tool(tool)
    assert result["function"]["parameters"]["type"] == "object"
    assert result["function"]["parameters"]["properties"] == {}


def test_mcp_tools_to_openai_tools_list():
    tools = [
        {"name": "a", "description": "Tool A"},
        {"name": "b", "description": "Tool B"},
    ]
    results = mcp_tools_to_openai_tools(tools)
    assert len(results) == 2
    assert results[0]["function"]["name"] == "a"
    assert results[1]["function"]["name"] == "b"


def test_mcp_tool_to_openai_tool_deep_copies_schema():
    """Verify the input schema is deep-copied so mutations don't leak."""
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}
    tool = {"name": "t", "description": "d", "inputSchema": schema}
    result = mcp_tool_to_openai_tool(tool)
    result["function"]["parameters"]["properties"]["injected"] = True
    assert "injected" not in schema["properties"]
