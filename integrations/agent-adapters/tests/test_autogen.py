"""Tests for the AutoGen adapter."""

from unittest.mock import MagicMock

from cordum_agent_adapters.autogen import build_autogen_tools, build_autogen_openai_tools


def test_build_autogen_tools_returns_functions_and_map():
    client = MagicMock()
    tool_defs = [
        {"name": "echo", "description": "Echo input", "inputSchema": {"type": "object"}},
        {"name": "ping", "description": "Ping", "inputSchema": {"type": "object"}},
    ]
    functions, function_map = build_autogen_tools(client, tools=tool_defs)
    assert len(functions) == 2
    assert "echo" in function_map
    assert "ping" in function_map
    assert callable(function_map["echo"])


def test_build_autogen_tools_calls_client():
    client = MagicMock()
    client.call_tool.return_value = {"content": "ok"}
    tool_defs = [{"name": "test", "description": "Test", "inputSchema": {"type": "object"}}]
    _, function_map = build_autogen_tools(client, tools=tool_defs)
    result = function_map["test"](key="value")
    client.call_tool.assert_called_once_with("test", {"key": "value"})
    assert result == {"content": "ok"}


def test_build_autogen_openai_tools():
    tools = [
        {"name": "a", "description": "A"},
        {"name": "b", "description": "B"},
    ]
    result = build_autogen_openai_tools(tools)
    assert len(result) == 2
    assert result[0]["function"]["name"] == "a"


def test_build_autogen_tools_with_transform():
    client = MagicMock()
    client.call_tool.return_value = {"content": "raw"}
    transform = MagicMock(return_value="transformed")
    tool_defs = [{"name": "t", "description": "d"}]
    _, function_map = build_autogen_tools(client, tools=tool_defs, result_transform=transform)
    result = function_map["t"](x=1)
    transform.assert_called_once_with({"content": "raw"})
    assert result == "transformed"
