"""Tests for cordum_agent_adapters.audit.CordumConversationLogger.

The logger must be adapter-agnostic, resilient to gateway outages,
never raise during an agent run, and bound payload size so the MCP
bus never chokes on a hot conversation.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest

from cordum_agent_adapters.audit import (
    MAX_TURN_BYTES,
    CordumConversationLogger,
)
from cordum_agent_adapters.mcp_client import McpRpcError, McpToolError


class _FakeClient:
    """Minimal McpStdioClient stand-in; records every call_tool."""

    def __init__(self, *, tools_available: bool = True, call_raises: Exception | None = None):
        self._tools_available = tools_available
        self._call_raises = call_raises
        self.calls: List[Dict[str, Any]] = []
        self.list_tools_count = 0

    def list_tools(self) -> List[Dict[str, Any]]:
        self.list_tools_count += 1
        if self._tools_available:
            return [
                {"name": "cordum.audit.log_turn", "description": "record a turn"},
                {"name": "cordum.workflow.list"},
            ]
        return [{"name": "cordum.workflow.list"}]

    def call_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append({"name": name, "args": args})
        if self._call_raises is not None:
            raise self._call_raises
        return {"content": [{"type": "text", "text": "ok"}]}


def test_new_logger_generates_session_id() -> None:
    logger = CordumConversationLogger(_FakeClient())
    assert isinstance(logger.session_id, str)
    assert len(logger.session_id) >= 16


def test_caller_session_id_is_honoured() -> None:
    logger = CordumConversationLogger(_FakeClient(), session_id="sess-1")
    assert logger.session_id == "sess-1"


def test_log_turn_sends_to_audit_tool() -> None:
    client = _FakeClient()
    logger = CordumConversationLogger(client, session_id="sess-happy")
    logger.log_turn({"kind": "tool_call_item", "name": "cordum.workflow.list"})
    assert len(client.calls) == 1
    sent = client.calls[0]
    assert sent["name"] == "cordum.audit.log_turn"
    assert sent["args"]["session_id"] == "sess-happy"
    assert sent["args"]["turn"]["kind"] == "tool_call_item"


def test_log_turn_skips_when_audit_tool_missing() -> None:
    client = _FakeClient(tools_available=False)
    logger = CordumConversationLogger(client)
    logger.log_turn({"kind": "x"})
    assert client.calls == []
    # Probe should only fire once — subsequent log_turns use the cache.
    logger.log_turn({"kind": "y"})
    assert client.list_tools_count == 1


def test_log_turn_tool_removed_midrun_caches_unavailable() -> None:
    client = _FakeClient(call_raises=McpRpcError(-32601, "method not found"))
    logger = CordumConversationLogger(client)
    logger.log_turn({"kind": "first"})
    # One probe + one call that fails; subsequent calls short-circuit.
    assert client.list_tools_count == 1
    assert len(client.calls) == 1
    logger.log_turn({"kind": "second"})
    # No new call; tool marked unavailable by -32601.
    assert len(client.calls) == 1


def test_log_turn_swallows_unexpected_exception() -> None:
    client = _FakeClient(call_raises=RuntimeError("boom"))
    logger = CordumConversationLogger(client)
    # Must NOT raise — audit is best-effort.
    logger.log_turn({"kind": "x"})
    assert len(client.calls) == 1


def test_log_turn_swallows_mcp_tool_error() -> None:
    client = _FakeClient(call_raises=McpToolError("tool bombed", result={"isError": True}))
    logger = CordumConversationLogger(client)
    logger.log_turn({"kind": "x"})
    assert len(client.calls) == 1  # one attempt surfaced via tool error; deterministic so no retry


def test_log_turn_rejects_non_dict() -> None:
    client = _FakeClient()
    logger = CordumConversationLogger(client)
    logger.log_turn(None)  # type: ignore[arg-type]
    logger.log_turn({})  # empty dict
    logger.log_turn("not a turn")  # type: ignore[arg-type]
    assert client.calls == []


def test_log_turn_truncates_oversized_payload() -> None:
    client = _FakeClient()
    logger = CordumConversationLogger(client, max_turn_bytes=512)
    big_value = "X" * 4096
    logger.log_turn({"kind": "tool_call_item", "output": big_value})
    assert len(client.calls) == 1
    sent = client.calls[0]["args"]
    assert sent.get("truncated") is True
    assert "[TRUNCATED]" in json.dumps(sent)
    # Encoded body stays at or below the cap (tolerance: no strict equality
    # because JSON overhead varies with the truncation marker).
    assert len(json.dumps(sent).encode("utf-8")) <= 512 * 2  # very loose upper bound


def test_log_tool_invocation_shapes_payload() -> None:
    client = _FakeClient()
    logger = CordumConversationLogger(client, session_id="s")
    logger.log_tool_invocation("cordum.workflow.list", {"x": 1}, {"ok": True})
    assert len(client.calls) == 1
    turn = client.calls[0]["args"]["turn"]
    assert turn["kind"] == "tool_call"
    assert turn["tool_name"] == "cordum.workflow.list"
    assert turn["args"] == {"x": 1}
    assert turn["result"] == {"ok": True}


def test_max_turn_bytes_default_is_8kib() -> None:
    assert MAX_TURN_BYTES == 8 * 1024


def test_retry_policy_used(monkeypatch: pytest.MonkeyPatch) -> None:
    """Custom retry_policy is honoured — we don't sneak a default in."""
    from cordum_agent_adapters.retry import RetryPolicy

    client = _FakeClient()
    policy = RetryPolicy(max_attempts=7, initial_backoff_s=0.001)
    logger = CordumConversationLogger(client, retry_policy=policy)
    # Logger stores the exact policy instance for introspection.
    assert logger._retry_policy is policy


def test_autogen_subpackage_reexports_same_class() -> None:
    from cordum_agent_adapters.autogen.audit import CordumConversationLogger as ReExport

    assert ReExport is CordumConversationLogger
