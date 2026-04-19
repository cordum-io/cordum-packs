"""Tests for McpStdioClient error types + async/context-manager surface.

The sync call_tool/list_tools paths are exercised end-to-end by the
integration test; here we pin the async wrappers and lifecycle helpers
so a future refactor of run_in_executor won't silently regress them.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest

from cordum_agent_adapters.mcp_client import (
    McpError,
    McpRpcError,
    McpStdioClient,
    McpToolError,
)


def test_mcp_error_hierarchy() -> None:
    """All MCP exceptions inherit from McpError."""
    assert issubclass(McpRpcError, McpError)
    assert issubclass(McpToolError, McpError)


def test_mcp_rpc_error_attributes() -> None:
    err = McpRpcError(-32600, "Invalid Request", {"detail": "missing id"})
    assert err.code == -32600
    assert err.message == "Invalid Request"
    assert err.data == {"detail": "missing id"}
    assert "-32600" in str(err)


def test_mcp_tool_error_attributes() -> None:
    err = McpToolError("tool failed", {"isError": True, "content": []})
    assert err.result == {"isError": True, "content": []}
    assert "tool failed" in str(err)


def test_mcp_error_is_exception() -> None:
    try:
        raise McpError("test")
    except McpError as e:
        assert str(e) == "test"


# ---------------------------------------------------------------------------
# Async + context-manager surface
#
# We bypass the constructor (which launches a subprocess) and build the
# object directly via __new__ so the tests run offline.
# ---------------------------------------------------------------------------


def _bare_client() -> McpStdioClient:
    """Return an McpStdioClient shell whose _proc is a MagicMock.

    The __init__ path launches a subprocess; we can't afford that in a
    unit test. object.__new__ skips __init__, then we poke just the
    attributes the tested methods touch.
    """
    client = object.__new__(McpStdioClient)
    client._proc = MagicMock()
    client._proc.poll.return_value = None  # "still alive"
    return client  # type: ignore[return-value]


def test_is_alive_reads_proc_poll() -> None:
    client = _bare_client()
    client._proc.poll.return_value = None
    assert client.is_alive() is True
    client._proc.poll.return_value = 0
    assert client.is_alive() is False


def test_sync_context_manager_calls_close_on_exit() -> None:
    client = _bare_client()
    client.close = MagicMock()  # type: ignore[method-assign]
    with client as entered:
        assert entered is client
    client.close.assert_called_once()


def test_sync_context_manager_calls_close_when_body_raises() -> None:
    client = _bare_client()
    client.close = MagicMock()  # type: ignore[method-assign]
    # Use explicit try/except instead of nested pytest.raises + with so
    # CodeQL's reachability analysis sees the close assertion below.
    caught: Exception | None = None
    try:
        with client:
            raise RuntimeError("boom")
    except RuntimeError as exc:
        caught = exc
    assert isinstance(caught, RuntimeError), "RuntimeError must propagate"
    client.close.assert_called_once()


@pytest.mark.asyncio
async def test_call_tool_async_delegates_to_sync_once() -> None:
    client = _bare_client()
    client.call_tool = MagicMock(return_value={"content": ["ok"]})  # type: ignore[method-assign]

    result = await client.call_tool_async("echo", {"msg": "hi"})
    assert result == {"content": ["ok"]}
    client.call_tool.assert_called_once_with("echo", {"msg": "hi"})


@pytest.mark.asyncio
async def test_call_tool_async_propagates_exceptions() -> None:
    client = _bare_client()
    err = McpToolError("policy denied", {"isError": True})

    def raise_it(*_: Any, **__: Any) -> Any:
        raise err

    client.call_tool = raise_it  # type: ignore[method-assign]

    with pytest.raises(McpToolError) as excinfo:
        await client.call_tool_async("x", {})
    assert excinfo.value is err


@pytest.mark.asyncio
async def test_list_tools_async_delegates_to_sync() -> None:
    client = _bare_client()
    tools = [{"name": "a"}, {"name": "b"}]
    client.list_tools = MagicMock(return_value=tools)  # type: ignore[method-assign]

    result = await client.list_tools_async()
    assert result == tools
    client.list_tools.assert_called_once()


@pytest.mark.asyncio
async def test_async_context_manager_closes() -> None:
    client = _bare_client()
    client.close = MagicMock()  # type: ignore[method-assign]

    async with client as entered:
        assert entered is client
    # close was called via run_in_executor; give the event loop a tick
    # to drain before asserting.
    await asyncio.sleep(0)
    client.close.assert_called_once()


@pytest.mark.asyncio
async def test_async_context_manager_closes_on_exception() -> None:
    client = _bare_client()
    client.close = MagicMock()  # type: ignore[method-assign]
    # Same explicit try/except pattern as the sync variant so CodeQL's
    # reachability analysis treats the close assertion below as live.
    caught: Exception | None = None
    try:
        async with client:
            raise ValueError("inner")
    except ValueError as exc:
        caught = exc
    assert isinstance(caught, ValueError), "ValueError must propagate"
    await asyncio.sleep(0)
    client.close.assert_called_once()
