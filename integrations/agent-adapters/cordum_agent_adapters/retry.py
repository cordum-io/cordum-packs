"""Retry primitives for the Cordum agent adapters.

``RetryPolicy`` is a dataclass that parameterises exponential backoff
with jitter; ``retry_call`` / ``retry_call_async`` are the sync + async
drivers that adapter code wraps around each MCP invocation.

Design choices:

* ``time.monotonic`` is used for elapsed accounting so wall-clock jumps
  (NTP sync, suspend/resume) don't throw off the budget.
* Jitter is drawn from ``secrets.SystemRandom`` rather than ``random``;
  the security-adjacent context (retry scheduling can affect rate-limit
  patterns a cooperating attacker could observe) makes the CSPRNG a
  defensible default — no meaningful perf cost for a few floats.
* The default ``retryable`` predicate treats every ``McpError`` as
  transient EXCEPT an ``McpToolError`` with client-side ``isError=True``,
  which is a deterministic policy-denial from the governed tool itself —
  retrying would just produce more audit noise.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, TypeVar

from .errors import AdapterRetryExhaustedError
from .mcp_client import McpError, McpToolError

T = TypeVar("T")

logger = logging.getLogger(__name__)

_rand = secrets.SystemRandom()


def default_retryable(exc: BaseException) -> bool:
    """True when ``exc`` is a transient MCP failure worth retrying.

    Policy-denied tool calls (``McpToolError`` with ``isError=True`` in
    the content map) are NOT retried — they're deterministic rejections
    from the governed tool.
    """
    if isinstance(exc, McpToolError):
        result = getattr(exc, "result", None)
        if isinstance(result, dict) and bool(result.get("isError")):
            return False
        return True
    return isinstance(exc, McpError)


@dataclass
class RetryPolicy:
    """Exponential-backoff retry configuration.

    Attributes:
      max_attempts: Total attempts including the first call. ``1`` means
        no retries. Must be ``>= 1``.
      initial_backoff_s: Sleep before the second attempt.
      max_backoff_s: Cap on any single backoff.
      jitter: Fractional jitter in ``[0, 1]``; each sleep is multiplied by
        ``1 + U(-jitter, +jitter)`` so contending clients de-sync.
      backoff_multiplier: Each attempt multiplies the prior backoff by
        this factor (capped at ``max_backoff_s``).
      retryable: Callable that decides if an exception is retryable.
        Defaults to :func:`default_retryable`.
    """

    max_attempts: int = 3
    initial_backoff_s: float = 0.5
    max_backoff_s: float = 8.0
    jitter: float = 0.2
    backoff_multiplier: float = 2.0
    retryable: Callable[[BaseException], bool] = field(default=default_retryable)

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.initial_backoff_s < 0 or self.max_backoff_s < 0:
            raise ValueError("backoff seconds must be non-negative")
        if not 0.0 <= self.jitter <= 1.0:
            raise ValueError("jitter must be in [0, 1]")
        if self.backoff_multiplier < 1.0:
            raise ValueError("backoff_multiplier must be >= 1.0")

    def compute_backoff(self, attempt: int) -> float:
        """Return the sleep duration before ``attempt`` (attempt >= 2).

        ``attempt=2`` yields ``initial_backoff_s`` (with jitter); each
        further attempt multiplies by ``backoff_multiplier`` and caps at
        ``max_backoff_s``.
        """
        if attempt < 2:
            return 0.0
        exponent = attempt - 2
        base = self.initial_backoff_s * (self.backoff_multiplier ** exponent)
        base = min(base, self.max_backoff_s)
        if self.jitter == 0:
            return max(0.0, base)
        # Symmetric jitter: [-jitter, +jitter] as a fraction of base.
        factor = 1.0 + _rand.uniform(-self.jitter, self.jitter)
        return max(0.0, base * factor)


def _log_retry(attempt: int, backoff_s: float, exc: BaseException, tool_name: Optional[str]) -> None:
    logger.warning(
        "mcp call retry",
        extra={
            "attempt": attempt,
            "backoff_s": round(backoff_s, 3),
            "error_class": type(exc).__name__,
            "tool_name": tool_name,
        },
    )


def retry_call(
    fn: Callable[..., T],
    policy: RetryPolicy,
    *args: Any,
    tool_name: Optional[str] = None,
    **kwargs: Any,
) -> T:
    """Invoke ``fn(*args, **kwargs)`` under ``policy``.

    On the final failure raises :class:`AdapterRetryExhaustedError`
    wrapping the last exception via ``raise ... from last``. Elapsed
    wall-clock time is reported in milliseconds on the error.
    """
    start = time.monotonic()
    last_exc: Optional[Exception] = None
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # policy decides retry — BaseException
            # (KeyboardInterrupt / SystemExit) must propagate, never retry.
            last_exc = exc
            if not policy.retryable(exc):
                raise
            if attempt == policy.max_attempts:
                break
            backoff_s = policy.compute_backoff(attempt + 1)
            _log_retry(attempt, backoff_s, exc, tool_name)
            if backoff_s > 0:
                time.sleep(backoff_s)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    assert last_exc is not None  # only reached after a failure
    raise AdapterRetryExhaustedError(
        f"retry budget exhausted after {policy.max_attempts} attempts",
        last_error=last_exc,
        attempts=policy.max_attempts,
        elapsed_ms=elapsed_ms,
        tool_name=tool_name,
    ) from last_exc


async def retry_call_async(
    coro_factory: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
    *,
    tool_name: Optional[str] = None,
) -> T:
    """Async variant of :func:`retry_call`.

    ``coro_factory`` is a zero-arg callable that returns a fresh awaitable
    per attempt — necessary because a coroutine cannot be re-awaited.
    """
    start = time.monotonic()
    last_exc: Optional[Exception] = None
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return await coro_factory()
        except Exception as exc:  # KeyboardInterrupt / SystemExit / asyncio.CancelledError
            # (which is BaseException-derived in 3.8+) must propagate.
            last_exc = exc
            if not policy.retryable(exc):
                raise
            if attempt == policy.max_attempts:
                break
            backoff_s = policy.compute_backoff(attempt + 1)
            _log_retry(attempt, backoff_s, exc, tool_name)
            if backoff_s > 0:
                await asyncio.sleep(backoff_s)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    assert last_exc is not None
    raise AdapterRetryExhaustedError(
        f"retry budget exhausted after {policy.max_attempts} attempts",
        last_error=last_exc,
        attempts=policy.max_attempts,
        elapsed_ms=elapsed_ms,
        tool_name=tool_name,
    ) from last_exc


__all__ = [
    "RetryPolicy",
    "default_retryable",
    "retry_call",
    "retry_call_async",
]
