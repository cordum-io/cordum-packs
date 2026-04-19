"""Tests for the AutoGen conversation-audit re-export.

The autogen.audit module re-exports the shared
:class:`cordum_agent_adapters.audit.CordumConversationLogger` so every
adapter publishes turns through identical wire conventions. These tests
pin the autogen-side import path AND the behaviour that is load-bearing
for the AutoGen tutorial: session id, graceful tool-not-found
degradation, retry budget exhaustion without raising, and string
truncation above MAX_TURN_BYTES.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from cordum_agent_adapters.autogen.audit import (
    MAX_TURN_BYTES,
    CordumConversationLogger,
)
from cordum_agent_adapters.mcp_client import McpRpcError


def _client_with_tool(name: str = "cordum.audit.log_turn") -> MagicMock:
    client = MagicMock()
    client.list_tools.return_value = [{"name": name, "description": "audit", "inputSchema": {}}]
    return client


def test_reexport_shares_canonical_class() -> None:
    from cordum_agent_adapters.audit import CordumConversationLogger as shared

    assert CordumConversationLogger is shared


def test_session_id_autogenerates_hex() -> None:
    logger = CordumConversationLogger(_client_with_tool())
    assert isinstance(logger.session_id, str)
    assert len(logger.session_id) == 32  # uuid4().hex


def test_session_id_respects_caller_override() -> None:
    logger = CordumConversationLogger(_client_with_tool(), session_id="sess-9")
    assert logger.session_id == "sess-9"


def test_log_turn_invokes_audit_tool() -> None:
    client = _client_with_tool()
    logger = CordumConversationLogger(client)
    logger.log_turn({"kind": "tool_call", "tool_name": "x"})
    client.call_tool.assert_called_once()
    tool_name, payload = client.call_tool.call_args.args[:2]
    assert tool_name == "cordum.audit.log_turn"
    assert payload["session_id"] == logger.session_id
    assert payload["turn"]["tool_name"] == "x"


def test_log_turn_noop_when_audit_tool_missing() -> None:
    client = MagicMock()
    client.list_tools.return_value = [{"name": "cordum.workflow.list"}]  # no audit tool
    logger = CordumConversationLogger(client)
    logger.log_turn({"kind": "x"})
    client.call_tool.assert_not_called()


def test_log_turn_ignores_empty_input() -> None:
    client = _client_with_tool()
    logger = CordumConversationLogger(client)
    logger.log_turn({})
    logger.log_turn(None)  # type: ignore[arg-type]
    client.call_tool.assert_not_called()


def test_log_turn_swallows_rpc_failure() -> None:
    client = _client_with_tool()
    from cordum_agent_adapters.retry import RetryPolicy

    client.call_tool.side_effect = McpRpcError(code=-32603, message="boom")
    logger = CordumConversationLogger(
        client,
        retry_policy=RetryPolicy(max_attempts=1, initial_backoff_s=0.0, max_backoff_s=0.0),
    )
    # Must NOT raise even though the gateway errored.
    logger.log_turn({"kind": "tool_call"})


def test_method_not_found_disables_subsequent_turns() -> None:
    client = _client_with_tool()
    client.call_tool.side_effect = McpRpcError(code=-32601, message="unknown")
    # Default retry policy's predicate short-circuits -32601 (the audit
    # tool is simply not advertised, retrying is pointless); the handler
    # caches the unavailable state and subsequent calls do not re-probe.
    logger = CordumConversationLogger(client)
    logger.log_turn({"kind": "tool_call"})
    client.call_tool.reset_mock()
    logger.list_tools_mock_count_before = client.list_tools.call_count
    logger.log_turn({"kind": "tool_call"})  # second call short-circuits
    client.call_tool.assert_not_called()


def test_oversized_turn_truncated_before_send() -> None:
    client = _client_with_tool()
    logger = CordumConversationLogger(client)
    huge = "x" * (MAX_TURN_BYTES * 4)
    logger.log_turn({"kind": "tool_call", "content": huge})
    payload = client.call_tool.call_args.args[1]
    # Payload must be bounded and carry a truncation marker.
    import json

    body = json.dumps(payload, default=str).encode("utf-8")
    assert len(body) <= MAX_TURN_BYTES * 2  # allow some header overhead
    assert payload.get("truncated") is True


def test_log_tool_invocation_helper_builds_uniform_shape() -> None:
    client = _client_with_tool()
    logger = CordumConversationLogger(client)
    logger.log_tool_invocation("echo", {"a": 1}, {"content": "ok"})
    payload = client.call_tool.call_args.args[1]
    turn = payload["turn"]
    assert turn["kind"] == "tool_call"
    assert turn["tool_name"] == "echo"
    assert turn["args"] == {"a": 1}
    assert turn["result"] == {"content": "ok"}
