"""Tests for the AutoGen adapter's MCP → AutoGen error mapping."""
from __future__ import annotations

from cordum_agent_adapters.autogen.errors import (
    CordumAutoGenError,
    CordumPolicyDeniedError,
    CordumToolExecutionError,
    mcp_error_to_classic_message,
    mcp_error_to_modern_exception,
)
from cordum_agent_adapters.mcp_client import McpError, McpRpcError, McpToolError


def test_policy_denied_maps_to_cordum_policy_denied_error_with_metadata():
    exc = McpRpcError(
        code=-32099,
        message="policy deny: tool on deny-list",
        data={"approval_id": "apr-123", "reason": "deny-list"},
    )
    out = mcp_error_to_modern_exception(exc, tool_name="cordum.dlq.retry")
    assert isinstance(out, CordumPolicyDeniedError)
    assert out.approval_id == "apr-123"
    assert out.reason == "deny-list"
    assert "deny" in str(out)


def test_policy_denied_with_string_data_falls_back_cleanly():
    exc = McpRpcError(code=-32099, message="policy deny", data="tenant over quota")
    out = mcp_error_to_modern_exception(exc)
    assert isinstance(out, CordumPolicyDeniedError)
    assert out.approval_id is None
    assert out.reason == "tenant over quota"


def test_invalid_params_maps_to_value_error():
    exc = McpRpcError(code=-32602, message="missing field 'name'")
    out = mcp_error_to_modern_exception(exc)
    assert isinstance(out, ValueError)
    assert "name" in str(out)


def test_unknown_rpc_code_maps_to_runtime_error():
    exc = McpRpcError(code=-1, message="internal")
    out = mcp_error_to_modern_exception(exc)
    assert isinstance(out, RuntimeError)
    assert "internal" in str(out)


def test_tool_error_flattens_content_blocks():
    result = {
        "isError": True,
        "content": [
            {"type": "text", "text": "line one"},
            {"type": "image", "data": "..."},
            {"type": "text", "text": "line two"},
        ],
    }
    exc = McpToolError(message="tool failed", result=result)
    out = mcp_error_to_modern_exception(exc, tool_name="echo")
    assert isinstance(out, CordumToolExecutionError)
    assert out.tool_name == "echo"
    assert "line one" in str(out)
    assert "line two" in str(out)
    assert "[image]" in str(out)
    assert out.content == result["content"]


def test_tool_error_without_content_falls_back_to_message():
    exc = McpToolError(message="no content", result={})
    out = mcp_error_to_modern_exception(exc, tool_name="x")
    assert isinstance(out, CordumToolExecutionError)
    assert "no content" in str(out)
    assert out.content == []


def test_raw_mcp_error_maps_to_runtime_error():
    out = mcp_error_to_modern_exception(McpError("transport dead"))
    assert isinstance(out, RuntimeError)
    assert "transport dead" in str(out)


def test_non_mcp_exception_passthrough():
    src = KeyError("missing")
    out = mcp_error_to_modern_exception(src)
    assert out is src


def test_classic_policy_deny_message_has_approval_id():
    exc = McpRpcError(
        code=-32099,
        message="deny",
        data={"approval_id": "apr-9", "reason": "needs review"},
    )
    msg = mcp_error_to_classic_message(exc)
    assert msg.startswith("ERROR:")
    assert "apr-9" in msg
    assert "needs review" in msg


def test_classic_invalid_params_message():
    msg = mcp_error_to_classic_message(McpRpcError(code=-32602, message="bad"))
    assert msg.startswith("ERROR:")
    assert "invalid arguments" in msg


def test_classic_tool_error_includes_tool_name():
    exc = McpToolError(
        message="boom",
        result={"content": [{"type": "text", "text": "tool output"}]},
    )
    msg = mcp_error_to_classic_message(exc, tool_name="echo")
    assert msg.startswith("ERROR:")
    assert "'echo'" in msg
    assert "tool output" in msg


def test_classic_handles_unexpected_exception():
    msg = mcp_error_to_classic_message(TypeError("bad cast"))
    assert msg.startswith("ERROR: TypeError")


def test_cordum_policy_denied_is_cordum_autogen_error():
    assert issubclass(CordumPolicyDeniedError, CordumAutoGenError)
    assert issubclass(CordumToolExecutionError, CordumAutoGenError)
