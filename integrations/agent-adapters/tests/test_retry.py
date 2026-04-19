"""Tests for ``retry.py``: policy validation, sync driver, async driver.

The jitter tests sample the backoff many times and assert bounds; exact
equality would flake because jitter is a CSPRNG.
"""
from __future__ import annotations

import asyncio
from typing import Any, List

import pytest

from cordum_agent_adapters.errors import AdapterRetryExhaustedError
from cordum_agent_adapters.mcp_client import McpError, McpRpcError, McpToolError
from cordum_agent_adapters.retry import (
    RetryPolicy,
    default_retryable,
    retry_call,
    retry_call_async,
)


# ---------------------------------------------------------------------------
# RetryPolicy validation + compute_backoff
# ---------------------------------------------------------------------------


class TestRetryPolicyValidation:
    @pytest.mark.parametrize(
        "kw",
        [
            {"max_attempts": 0},
            {"initial_backoff_s": -1},
            {"max_backoff_s": -1},
            {"jitter": -0.1},
            {"jitter": 1.5},
            {"backoff_multiplier": 0.5},
        ],
    )
    def test_rejects_bad_inputs(self, kw: dict) -> None:
        with pytest.raises(ValueError):
            RetryPolicy(**kw)

    def test_defaults_are_sensible(self) -> None:
        p = RetryPolicy()
        assert p.max_attempts == 3
        assert p.initial_backoff_s == pytest.approx(0.5)
        assert p.max_backoff_s == pytest.approx(8.0)
        assert p.backoff_multiplier == pytest.approx(2.0)


class TestRetryPolicyBackoff:
    def test_first_attempt_has_zero_backoff(self) -> None:
        p = RetryPolicy(initial_backoff_s=1.0, jitter=0)
        assert p.compute_backoff(1) == 0.0

    def test_backoff_grows_exponentially(self) -> None:
        p = RetryPolicy(initial_backoff_s=1.0, max_backoff_s=100.0, backoff_multiplier=2.0, jitter=0)
        assert p.compute_backoff(2) == pytest.approx(1.0)
        assert p.compute_backoff(3) == pytest.approx(2.0)
        assert p.compute_backoff(4) == pytest.approx(4.0)

    def test_backoff_caps_at_max(self) -> None:
        p = RetryPolicy(initial_backoff_s=5.0, max_backoff_s=6.0, backoff_multiplier=2.0, jitter=0)
        assert p.compute_backoff(5) == pytest.approx(6.0)

    def test_jitter_within_bounds(self) -> None:
        p = RetryPolicy(initial_backoff_s=1.0, max_backoff_s=100.0, backoff_multiplier=1.0, jitter=0.5)
        samples = [p.compute_backoff(2) for _ in range(200)]
        # 1.0 * (1 +/- 0.5) = [0.5, 1.5]
        assert all(0.5 <= s <= 1.5 for s in samples), f"out of bounds: {min(samples)}..{max(samples)}"
        assert min(samples) != max(samples), "jitter did not vary"


# ---------------------------------------------------------------------------
# default_retryable policy
# ---------------------------------------------------------------------------


class TestDefaultRetryable:
    def test_non_mcp_not_retried(self) -> None:
        assert not default_retryable(ValueError("x"))

    def test_generic_mcp_error_retried(self) -> None:
        assert default_retryable(McpError("transport failed"))

    def test_rpc_error_retried(self) -> None:
        assert default_retryable(McpRpcError(code=-32000, message="boom"))

    def test_tool_error_with_is_error_not_retried(self) -> None:
        err = McpToolError(message="policy denied", result={"isError": True, "content": []})
        assert not default_retryable(err)

    def test_tool_error_without_is_error_retried(self) -> None:
        err = McpToolError(message="transient", result={"content": []})
        assert default_retryable(err)


# ---------------------------------------------------------------------------
# retry_call (sync)
# ---------------------------------------------------------------------------


class TestRetryCallSync:
    def test_succeeds_first_try(self) -> None:
        calls: List[int] = []

        def fn() -> str:
            calls.append(1)
            return "ok"

        result = retry_call(fn, RetryPolicy(max_attempts=3, initial_backoff_s=0))
        assert result == "ok"
        assert len(calls) == 1

    def test_succeeds_on_retry(self) -> None:
        calls: List[int] = []

        def fn() -> str:
            calls.append(1)
            if len(calls) < 2:
                raise McpError("transient")
            return "ok"

        result = retry_call(fn, RetryPolicy(max_attempts=3, initial_backoff_s=0))
        assert result == "ok"
        assert len(calls) == 2

    def test_exhausts_and_raises(self) -> None:
        calls: List[int] = []

        def fn() -> str:
            calls.append(1)
            raise McpError("always broken")

        with pytest.raises(AdapterRetryExhaustedError) as excinfo:
            retry_call(
                fn,
                RetryPolicy(max_attempts=3, initial_backoff_s=0, jitter=0),
                tool_name="test.tool",
            )
        assert excinfo.value.attempts == 3
        assert excinfo.value.tool_name == "test.tool"
        assert isinstance(excinfo.value.last_error, McpError)
        assert excinfo.value.__cause__ is excinfo.value.last_error
        assert len(calls) == 3

    def test_non_retryable_passthrough(self) -> None:
        calls: List[int] = []

        def fn() -> str:
            calls.append(1)
            raise ValueError("permanent")

        with pytest.raises(ValueError):
            retry_call(fn, RetryPolicy(max_attempts=5, initial_backoff_s=0))
        assert len(calls) == 1

    def test_custom_retryable(self) -> None:
        calls: List[int] = []

        def retryable(exc: BaseException) -> bool:
            return isinstance(exc, KeyError)

        def fn() -> str:
            calls.append(1)
            if len(calls) < 2:
                raise KeyError("x")
            return "ok"

        result = retry_call(
            fn,
            RetryPolicy(max_attempts=3, initial_backoff_s=0, retryable=retryable),
        )
        assert result == "ok"

    def test_args_kwargs_forwarded(self) -> None:
        def fn(a: int, *, b: int) -> int:
            return a + b

        result = retry_call(fn, RetryPolicy(max_attempts=1, initial_backoff_s=0), 2, b=3)
        assert result == 5


# ---------------------------------------------------------------------------
# retry_call_async
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRetryCallAsync:
    async def test_succeeds_first_try(self) -> None:
        calls: List[int] = []

        async def body() -> str:
            calls.append(1)
            return "ok"

        result = await retry_call_async(body, RetryPolicy(max_attempts=3, initial_backoff_s=0))
        assert result == "ok"
        assert len(calls) == 1

    async def test_succeeds_on_retry(self) -> None:
        calls: List[int] = []

        async def body() -> str:
            calls.append(1)
            if len(calls) < 2:
                raise McpError("transient")
            return "ok"

        result = await retry_call_async(body, RetryPolicy(max_attempts=3, initial_backoff_s=0))
        assert result == "ok"
        assert len(calls) == 2

    async def test_exhausts_and_raises(self) -> None:
        async def body() -> Any:
            raise McpError("always broken")

        with pytest.raises(AdapterRetryExhaustedError) as excinfo:
            await retry_call_async(
                body,
                RetryPolicy(max_attempts=2, initial_backoff_s=0, jitter=0),
                tool_name="async.tool",
            )
        assert excinfo.value.attempts == 2
        assert excinfo.value.tool_name == "async.tool"

    async def test_non_retryable_passthrough(self) -> None:
        async def body() -> Any:
            raise RuntimeError("permanent")

        with pytest.raises(RuntimeError):
            await retry_call_async(body, RetryPolicy(max_attempts=3, initial_backoff_s=0))

    async def test_coroutine_factory_per_attempt(self) -> None:
        # Regression guard: using a pre-created coroutine would fail on
        # the second attempt with "cannot reuse already awaited coroutine".
        calls: List[int] = []

        async def body() -> str:
            calls.append(1)
            if len(calls) < 3:
                raise McpError("retry me")
            return "ok"

        result = await retry_call_async(
            body, RetryPolicy(max_attempts=3, initial_backoff_s=0, jitter=0)
        )
        assert result == "ok"
        assert len(calls) == 3
