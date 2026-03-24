"""Tests for McpStdioClient error types."""

from cordum_agent_adapters.mcp_client import McpError, McpRpcError, McpToolError


def test_mcp_error_hierarchy():
    """All MCP exceptions inherit from McpError."""
    assert issubclass(McpRpcError, McpError)
    assert issubclass(McpToolError, McpError)


def test_mcp_rpc_error_attributes():
    err = McpRpcError(-32600, "Invalid Request", {"detail": "missing id"})
    assert err.code == -32600
    assert err.message == "Invalid Request"
    assert err.data == {"detail": "missing id"}
    assert "-32600" in str(err)


def test_mcp_tool_error_attributes():
    err = McpToolError("tool failed", {"isError": True, "content": []})
    assert err.result == {"isError": True, "content": []}
    assert "tool failed" in str(err)


def test_mcp_error_is_exception():
    try:
        raise McpError("test")
    except McpError as e:
        assert str(e) == "test"
