"""Tests for cordum_agent_adapters.openai_agents.

Requires the ``openai-agents`` optional extra. Tests are skipped in
environments where the SDK is not installed.
"""
from __future__ import annotations

import asyncio
import dataclasses
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("agents")

from cordum_agent_adapters.mcp_client import McpRpcError, McpToolError  # noqa: E402
from cordum_agent_adapters.openai_agents import (  # noqa: E402
    build_openai_agent_tools,
    register_cordum_mcp,
)


TOOL_DEFS: List[Dict[str, Any]] = [
    {
        "name": "cordum.workflow.list",
        "description": "list workflows",
        "inputSchema": {"properties": {"limit": {"type": "integer"}}},
    },
    {
        "name": "cordum.dlq.retry",
        "description": "retry a DLQ entry",
        "inputSchema": {
            "type": "object",
            "properties": {"job_id": {"type": "string"}},
            "required": ["job_id"],
        },
    },
]


class _FakeClient:
    """McpStdioClient test double with deterministic list_tools."""

    def __init__(self, raise_on_call: Exception | None = None) -> None:
        self.raise_on_call = raise_on_call
        self.calls: List[Dict[str, Any]] = []

    def list_tools(self) -> List[Dict[str, Any]]:
        return TOOL_DEFS

    def call_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append({"name": name, "args": args})
        if self.raise_on_call is not None:
            raise self.raise_on_call
        return {"content": [{"type": "text", "text": f"{name} ok"}]}


def _run(coro: Any) -> Any:
    return asyncio.get_event_loop().run_until_complete(coro) if asyncio.get_event_loop().is_running() is False else asyncio.run(coro)


def test_build_openai_agent_tools_returns_function_tools() -> None:
    from agents import FunctionTool

    client = _FakeClient()
    tools = build_openai_agent_tools(client)
    assert len(tools) == len(TOOL_DEFS)
    assert all(isinstance(t, FunctionTool) for t in tools)
    # Names preserved, descriptions preserved.
    names = {t.name for t in tools}
    assert names == {"cordum.workflow.list", "cordum.dlq.retry"}
    # Strict-mode normalisation kicked in: additionalProperties:false on every object schema.
    for t in tools:
        schema = t.params_json_schema
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False


def test_build_openai_agent_tools_uses_explicit_tool_list() -> None:
    client = _FakeClient()
    tools = build_openai_agent_tools(
        client, tools=[{"name": "just.one", "inputSchema": {}, "description": ""}]
    )
    assert len(tools) == 1
    assert tools[0].name == "just.one"


def test_on_invoke_tool_happy_path_returns_text() -> None:
    client = _FakeClient()
    tool = build_openai_agent_tools(client)[0]
    result = asyncio.run(tool.on_invoke_tool(None, '{"limit": 5}'))
    assert "cordum.workflow.list ok" in result
    assert client.calls == [{"name": "cordum.workflow.list", "args": {"limit": 5}}]


def test_on_invoke_tool_uses_to_thread() -> None:
    client = _FakeClient()
    tool = build_openai_agent_tools(client)[0]
    original = asyncio.to_thread

    async def spy_to_thread(fn: Any, *args: Any, **kwargs: Any) -> Any:
        spy_to_thread.called = True  # type: ignore[attr-defined]
        return await original(fn, *args, **kwargs)

    spy_to_thread.called = False  # type: ignore[attr-defined]
    with patch("cordum_agent_adapters.openai_agents.asyncio.to_thread", side_effect=spy_to_thread):
        _ = asyncio.run(tool.on_invoke_tool(None, "{}"))
    assert spy_to_thread.called is True  # type: ignore[attr-defined]


def test_on_invoke_tool_policy_denied_returns_string() -> None:
    client = _FakeClient(
        raise_on_call=McpRpcError(
            -32099, "denied", data={"approval_id": "a1", "tool": "cordum.dlq.retry"}
        )
    )
    tool = build_openai_agent_tools(client)[1]
    result = asyncio.run(tool.on_invoke_tool(None, '{"job_id": "j1"}'))
    assert result.startswith("[POLICY DENIED]")
    assert "approval_id=a1" in result


def test_on_invoke_tool_invalid_params_prefix() -> None:
    client = _FakeClient(raise_on_call=McpRpcError(-32602, "missing job_id"))
    tool = build_openai_agent_tools(client)[1]
    result = asyncio.run(tool.on_invoke_tool(None, "{}"))
    assert result.startswith("[TOOL ARG ERROR]")


def test_on_invoke_tool_mcp_tool_error_prefix() -> None:
    client = _FakeClient(raise_on_call=McpToolError("tool blew up", result={"isError": True}))
    tool = build_openai_agent_tools(client)[0]
    result = asyncio.run(tool.on_invoke_tool(None, "{}"))
    assert result.startswith("[TOOL ERROR]")


def test_on_invoke_tool_malformed_args_json_returns_error() -> None:
    client = _FakeClient()
    tool = build_openai_agent_tools(client)[0]
    result = asyncio.run(tool.on_invoke_tool(None, "{not json"))
    assert result.startswith("[TOOL ARG ERROR]")
    # No upstream call should have fired.
    assert client.calls == []


def test_on_invoke_tool_unexpected_exception_maps_to_internal() -> None:
    client = _FakeClient(raise_on_call=ZeroDivisionError("oops"))
    tool = build_openai_agent_tools(client)[0]
    result = asyncio.run(tool.on_invoke_tool(None, "{}"))
    # Wrapped as AdapterToolCallError → [TOOL ERROR] via the translator.
    assert result.startswith("[TOOL ERROR]")


def test_result_transform_applied_on_success() -> None:
    client = _FakeClient()

    def upper(result: Any) -> Any:
        # Rewrite the content block in place.
        if isinstance(result, dict):
            return {
                "content": [
                    {"type": "text", "text": (b.get("text") or "").upper()}
                    for b in result.get("content", [])
                    if isinstance(b, dict)
                ]
            }
        return result

    tools = build_openai_agent_tools(client, result_transform=upper)
    out = asyncio.run(tools[0].on_invoke_tool(None, "{}"))
    assert "CORDUM.WORKFLOW.LIST OK" in out


def test_logger_log_tool_invocation_called_once() -> None:
    client = _FakeClient()
    logger = MagicMock()
    tools = build_openai_agent_tools(client, logger=logger)
    asyncio.run(tools[0].on_invoke_tool(None, "{}"))
    logger.log_tool_invocation.assert_called_once()
    args, _ = logger.log_tool_invocation.call_args
    assert args[0] == "cordum.workflow.list"


def test_strict_false_passes_strict_json_schema_false() -> None:
    client = _FakeClient()
    tools = build_openai_agent_tools(client, strict=False)
    # strict_json_schema is a SDK-version-dependent attribute; check it
    # if available, otherwise fall back to asserting the schema was NOT
    # normalised with additionalProperties:false.
    for t in tools:
        attr = getattr(t, "strict_json_schema", None)
        if attr is not None:
            assert attr is False
        else:
            assert t.params_json_schema.get("additionalProperties") is not False


def test_register_cordum_mcp_merges_tools_on_dataclass_agent() -> None:
    from agents import FunctionTool

    # Build a tiny dataclass stand-in so we don't depend on a specific
    # Agent signature across SDK releases.
    @dataclasses.dataclass
    class _Agent:
        name: str
        tools: List[Any] = dataclasses.field(default_factory=list)
        mcp_servers: Any = None

    existing = FunctionTool(
        name="local.tool",
        description="",
        params_json_schema={"type": "object", "additionalProperties": False, "properties": {}},
        on_invoke_tool=lambda ctx, args: "ok",
    )
    agent = _Agent(name="tester", tools=[existing])
    client = _FakeClient()
    new_agent = register_cordum_mcp(agent, client)
    # Original agent left alone (dataclass clone).
    assert len(agent.tools) == 1
    assert len(new_agent.tools) == 1 + len(TOOL_DEFS)
    assert new_agent.tools[0] is existing


def test_register_cordum_mcp_refuses_when_mcp_servers_present() -> None:
    @dataclasses.dataclass
    class _Agent:
        name: str
        tools: List[Any] = dataclasses.field(default_factory=list)
        mcp_servers: Any = None

    agent = _Agent(name="x", mcp_servers=["some-server"])
    client = _FakeClient()
    with pytest.raises(ValueError, match="two MCP sources of truth"):
        register_cordum_mcp(agent, client)
