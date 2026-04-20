"""Tests for the typed exception hierarchy.

Each subclass has its own __str__/__repr__ shape; tests pin the output
because structured logging greps for specific fields (tool_name, attempts,
elapsed_ms).
"""
from __future__ import annotations

import pytest

from cordum_agent_adapters.errors import (
    AdapterError,
    AdapterRetryExhaustedError,
    AdapterSchemaError,
    AdapterTimeoutError,
    AdapterToolCallError,
)


class TestAdapterError:
    def test_message_preserved(self) -> None:
        err = AdapterError("boom")
        assert err.message == "boom"
        assert str(err) == "boom"

    def test_details_render_in_str(self) -> None:
        err = AdapterError("boom", tool_name="fs.delete", attempt=2)
        s = str(err)
        # Deterministic ordering for grep-friendly logs.
        assert "tool_name='fs.delete'" in s
        assert "attempt=2" in s

    def test_subclass_is_instance_of_base(self) -> None:
        err = AdapterTimeoutError("slow", tool_name="x", elapsed_ms=500)
        assert isinstance(err, AdapterError)


class TestAdapterTimeoutError:
    def test_fields_on_object(self) -> None:
        err = AdapterTimeoutError("deadline exceeded", tool_name="t1", elapsed_ms=42)
        assert err.tool_name == "t1"
        assert err.elapsed_ms == 42
        assert "tool_name='t1'" in str(err)
        assert "elapsed_ms=42" in str(err)


class TestAdapterRetryExhaustedError:
    def test_preserves_cause(self) -> None:
        root = ValueError("transient")
        err = AdapterRetryExhaustedError(
            "give up", last_error=root, attempts=3, elapsed_ms=1200, tool_name="t2"
        )
        assert err.last_error is root
        assert err.attempts == 3
        assert err.tool_name == "t2"
        assert "attempts=3" in str(err)
        assert "last_error_type='ValueError'" in str(err)

    def test_raise_from_preserves_traceback(self) -> None:
        root = RuntimeError("deep")
        try:
            try:
                raise root
            except RuntimeError as e:
                raise AdapterRetryExhaustedError("gave up", last_error=e, attempts=1) from e
        except AdapterRetryExhaustedError as caught:
            assert caught.__cause__ is root


class TestAdapterToolCallError:
    def test_redacted_args_survive_in_exception(self) -> None:
        err = AdapterToolCallError(
            "upstream failure",
            tool_name="dangerous.delete",
            tool_args={"id": "x1", "token": "***"},
            cause=RuntimeError("http 500"),
            attempt=2,
            elapsed_ms=90,
        )
        assert err.tool_name == "dangerous.delete"
        assert err.tool_args == {"id": "x1", "token": "***"}
        s = str(err)
        assert "tool_name='dangerous.delete'" in s
        assert "attempt=2" in s
        assert "cause_type='RuntimeError'" in s

    def test_args_copied_not_shared(self) -> None:
        args = {"k": "v"}
        err = AdapterToolCallError("x", tool_name="t", tool_args=args)
        args["k"] = "MUTATED"
        assert err.tool_args["k"] == "v"


class TestAdapterSchemaError:
    def test_offending_key_in_repr(self) -> None:
        err = AdapterSchemaError("bad schema", tool_name="t", offending_key="properties.foo.type")
        assert err.offending_key == "properties.foo.type"
        assert "offending_key='properties.foo.type'" in str(err)


def test_base_repr_stable() -> None:
    # Change-detection for log aggregators that grep on repr().
    err = AdapterError("x")
    assert repr(err) == "AdapterError('x')"
    err2 = AdapterError("x", k="v")
    assert "AdapterError('x', " in repr(err2)
    assert "'k': 'v'" in repr(err2)


def test_exceptions_are_raisable() -> None:
    for cls in (
        AdapterError,
        AdapterTimeoutError,
        AdapterRetryExhaustedError,
        AdapterSchemaError,
    ):
        with pytest.raises(AdapterError):
            raise cls("x")
    with pytest.raises(AdapterToolCallError):
        raise AdapterToolCallError("x", tool_name="t")


# ---------------------------------------------------------------------------
# Cordum-specific error classes + mcp_error_to_openai_agents_message.
# Added for task-d9fdcfbd (OpenAI Agents SDK adapter).
# ---------------------------------------------------------------------------


from cordum_agent_adapters.errors import (  # noqa: E402
    CordumPolicyDeniedError,
    CordumToolExecutionError,
    mcp_error_to_openai_agents_message,
)
from cordum_agent_adapters.mcp_client import McpRpcError, McpToolError  # noqa: E402


class TestCordumPolicyDeniedError:
    def test_round_trips_every_field(self) -> None:
        exc = CordumPolicyDeniedError(
            "policy blocked",
            approval_id="app-1",
            tool_name="cordum.dlq.retry",
            reason="destructive",
            tenant_id="default",
        )
        assert exc.approval_id == "app-1"
        assert exc.tool_name == "cordum.dlq.retry"
        assert exc.reason == "destructive"
        assert exc.tenant_id == "default"
        assert exc.details["approval_id"] == "app-1"
        assert exc.message == "policy blocked"
        # Catchable via the adapter-wide base class.
        assert isinstance(exc, AdapterError)


class TestCordumToolExecutionError:
    def test_round_trips_content(self) -> None:
        content = [{"type": "text", "text": "failed"}]
        exc = CordumToolExecutionError("exec failed", tool_name="t1", content=content)
        assert exc.tool_name == "t1"
        assert exc.content == content
        assert isinstance(exc, AdapterError)


class TestMcpErrorToOpenAIAgentsMessage:
    def test_policy_denied_via_cordum_error_type(self) -> None:
        exc = CordumPolicyDeniedError(
            "blocked",
            approval_id="app-9",
            tool_name="cordum.dlq.retry",
            reason="requires human sign-off",
        )
        msg = mcp_error_to_openai_agents_message(exc)
        assert msg.startswith("[POLICY DENIED]")
        assert "approval_id=app-9" in msg
        assert "tool=cordum.dlq.retry" in msg
        assert "requires human sign-off" in msg

    def test_policy_denied_via_mcp_rpc_32099(self) -> None:
        exc = McpRpcError(
            -32099,
            "denied",
            data={"approval_id": "a-7", "tool": "tool-x", "reason": "rule fired"},
        )
        msg = mcp_error_to_openai_agents_message(exc)
        assert msg.startswith("[POLICY DENIED]")
        assert "approval_id=a-7" in msg
        assert "tool=tool-x" in msg
        assert "rule fired" in msg

    def test_invalid_params_prefix(self) -> None:
        exc = McpRpcError(-32602, "bad params: missing 'target'")
        msg = mcp_error_to_openai_agents_message(exc)
        assert msg.startswith("[TOOL ARG ERROR]")
        assert "bad params" in msg

    def test_mcp_tool_error_prefix(self) -> None:
        exc = McpToolError("tool raised", result={"isError": True})
        msg = mcp_error_to_openai_agents_message(exc)
        assert msg.startswith("[TOOL ERROR]")

    def test_cordum_tool_execution_error_prefix(self) -> None:
        exc = CordumToolExecutionError("tool bombed", tool_name="t-err")
        msg = mcp_error_to_openai_agents_message(exc)
        assert msg.startswith("[TOOL ERROR]")
        assert "t-err" in msg

    def test_adapter_tool_call_error_prefix(self) -> None:
        exc = AdapterToolCallError("adapter failed", tool_name="cordum.audit.query")
        msg = mcp_error_to_openai_agents_message(exc)
        assert msg.startswith("[TOOL ERROR]")
        assert "cordum.audit.query" in msg

    def test_unexpected_exception_maps_to_internal_error(self) -> None:
        msg = mcp_error_to_openai_agents_message(RuntimeError("boom"))
        assert msg.startswith("[INTERNAL ERROR]")
        assert "RuntimeError" in msg
        # Never leak a Python stack trace — the LLM would quote it.
        assert "Traceback" not in msg
