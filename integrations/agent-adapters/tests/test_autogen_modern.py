"""Tests for the modern AG2 AutoGen adapter (autogen-core>=0.4)."""
from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock

import pytest

from cordum_agent_adapters.autogen.errors import (
    CordumPolicyDeniedError,
    CordumToolExecutionError,
)
from cordum_agent_adapters.autogen.modern import _serialise_result
from cordum_agent_adapters.mcp_client import McpRpcError, McpToolError


# --- _serialise_result covers the common output shapes without needing AG2. ---


def test_serialise_joins_text_blocks():
    out = _serialise_result({"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]})
    assert out == "a\nb"


def test_serialise_json_encodes_non_text_blocks():
    out = _serialise_result({"content": [{"type": "image", "data": "x"}]})
    assert "image" in out


def test_serialise_structured_payload_as_json():
    out = _serialise_result({"workflow_id": "wf-1"})
    assert json.loads(out) == {"workflow_id": "wf-1"}


def test_serialise_handles_non_dict():
    assert _serialise_result("raw") == "raw"


# --- build_ag2_tools requires autogen-core; skip when not installed. ---


ag2_tools = pytest.importorskip("autogen_core.tools")


def _build(tool_defs, client=None):
    """Thin wrapper so each test stays self-contained."""
    from cordum_agent_adapters.autogen.modern import build_ag2_tools

    return build_ag2_tools(client or MagicMock(), tools=tool_defs)


def test_build_ag2_tools_returns_function_tool_per_def():
    tool_defs = [
        {"name": "echo", "description": "Echo", "inputSchema": {"type": "object"}},
        {"name": "ping", "description": "Ping", "inputSchema": {"type": "object"}},
    ]
    tools = _build(tool_defs)
    assert len(tools) == 2
    names = {t.name for t in tools}
    assert names == {"echo", "ping"}


def test_build_ag2_tools_skips_nameless_defs():
    tools = _build([{"name": "", "description": "x"}, {"description": "y"}])
    assert tools == []


def test_build_ag2_tools_calls_list_tools_when_no_tools_arg():
    client = MagicMock()
    client.list_tools.return_value = [
        {"name": "autoload", "description": "auto", "inputSchema": {}}
    ]
    from cordum_agent_adapters.autogen.modern import build_ag2_tools

    tools = build_ag2_tools(client)
    client.list_tools.assert_called_once()
    assert len(tools) == 1


def test_async_caller_invokes_client_call_tool():
    client = MagicMock()
    client.call_tool.return_value = {"content": [{"type": "text", "text": "ok"}]}
    tools = _build([{"name": "echo", "description": "E", "inputSchema": {"type": "object"}}], client=client)
    caller = _tool_callable(tools[0])
    result = asyncio.run(caller(message="hi"))
    client.call_tool.assert_called_once()
    call_args = client.call_tool.call_args
    assert call_args.args[0] == "echo"
    # payload survives the pydantic round-trip on schemas with no properties.
    assert result == "ok"


def test_async_caller_translates_policy_deny():
    client = MagicMock()
    client.call_tool.side_effect = McpRpcError(
        code=-32099,
        message="policy deny: tool on deny-list",
        data={"approval_id": "apr-1", "reason": "deny-list"},
    )
    tools = _build([{"name": "dlq.retry", "description": "d", "inputSchema": {}}], client=client)
    caller = _tool_callable(tools[0])
    with pytest.raises(CordumPolicyDeniedError) as ei:
        asyncio.run(caller())
    assert ei.value.approval_id == "apr-1"


def test_async_caller_translates_invalid_params():
    client = MagicMock()
    client.call_tool.side_effect = McpRpcError(code=-32602, message="bad field")
    tools = _build([{"name": "x", "description": "x", "inputSchema": {}}], client=client)
    caller = _tool_callable(tools[0])
    with pytest.raises(ValueError):
        asyncio.run(caller())


def test_async_caller_translates_tool_error_with_content():
    client = MagicMock()
    client.call_tool.side_effect = McpToolError(
        message="tool failed",
        result={"isError": True, "content": [{"type": "text", "text": "bad input"}]},
    )
    tools = _build([{"name": "echo", "description": "d", "inputSchema": {}}], client=client)
    caller = _tool_callable(tools[0])
    with pytest.raises(CordumToolExecutionError) as ei:
        asyncio.run(caller())
    assert ei.value.tool_name == "echo"
    assert "bad input" in str(ei.value)


def test_strict_mode_applied_when_additional_properties_false():
    # This is a smoke test — the constructor shape varies across AG2 versions;
    # we only assert the tool was built (build_ag2_tools caught any TypeError
    # on unsupported strict= kwarg).
    tools = _build([
        {
            "name": "strict_tool",
            "description": "s",
            "inputSchema": {"type": "object", "additionalProperties": False, "properties": {"a": {"type": "string"}}},
        }
    ])
    assert len(tools) == 1


# --- helpers ------------------------------------------------------------


def _tool_callable(tool):
    """Return the underlying coroutine the FunctionTool wraps.

    autogen_core versions differ: 0.4 uses ``_func``; pre-0.4 betas used
    ``func``. Fall back to ``run`` which always exists and invokes the
    wrapped callable.
    """
    for attr in ("_func", "func", "_callable"):
        fn = getattr(tool, attr, None)
        if callable(fn):
            return fn
    # Last resort: call the tool's run method directly — it takes keyword
    # arguments via an args model and returns a coroutine.
    async def _via_run(**kwargs):
        return await tool.run_json(kwargs, cancellation_token=None)  # type: ignore[attr-defined]

    return _via_run
