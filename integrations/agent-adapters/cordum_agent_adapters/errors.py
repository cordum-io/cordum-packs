"""Typed exception hierarchy for the Cordum agent adapters.

Every adapter (CrewAI, AutoGen, OpenAI, LangChain) raises exceptions from
this module so callers have a single `except AdapterError:` clause for
catch-all error handling.

Import-safe: this module depends only on the stdlib so it can be imported
even when optional framework extras (``crewai``, ``openai`` …) are not
installed.
"""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional


class AdapterError(Exception):
    """Base class for every error raised by the Cordum agent adapters.

    Carries structured context as ``kwargs`` so logs and dashboards can
    render stable fields. Subclasses set their own canonical fields and
    append anything extra through ``details``.
    """

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self._message = message
        self.details: Dict[str, Any] = dict(details)

    @property
    def message(self) -> str:
        return self._message

    def __str__(self) -> str:
        if not self.details:
            return self._message
        # Sort for deterministic log lines (helps grep + change-detection).
        rendered = " ".join(f"{k}={v!r}" for k, v in sorted(self.details.items()))
        return f"{self._message} [{rendered}]"

    def __repr__(self) -> str:
        cls = type(self).__name__
        if not self.details:
            return f"{cls}({self._message!r})"
        return f"{cls}({self._message!r}, {self.details!r})"


class AdapterTimeoutError(AdapterError):
    """Raised when an MCP call exceeds its deadline.

    ``tool_name`` is the MCP tool the caller was trying to reach; ``elapsed_ms``
    is how long we waited before giving up.
    """

    def __init__(
        self,
        message: str,
        *,
        tool_name: Optional[str] = None,
        elapsed_ms: Optional[int] = None,
        **details: Any,
    ) -> None:
        extras: Dict[str, Any] = dict(details)
        if tool_name is not None:
            extras["tool_name"] = tool_name
        if elapsed_ms is not None:
            extras["elapsed_ms"] = elapsed_ms
        super().__init__(message, **extras)
        self.tool_name = tool_name
        self.elapsed_ms = elapsed_ms


class AdapterRetryExhaustedError(AdapterError):
    """Raised by ``retry_call`` / ``retry_call_async`` when every attempt fails.

    ``last_error`` is the final exception from the wrapped call; it is wired
    via ``raise ... from last_error`` so tracebacks preserve the chain.
    ``attempts`` is the number of attempts actually made (1 + retries).
    ``elapsed_ms`` is the cumulative wall-clock time.
    """

    def __init__(
        self,
        message: str,
        *,
        last_error: Optional[BaseException] = None,
        attempts: int = 0,
        elapsed_ms: Optional[int] = None,
        tool_name: Optional[str] = None,
        **details: Any,
    ) -> None:
        extras: Dict[str, Any] = dict(details)
        extras["attempts"] = attempts
        if elapsed_ms is not None:
            extras["elapsed_ms"] = elapsed_ms
        if tool_name is not None:
            extras["tool_name"] = tool_name
        if last_error is not None:
            extras["last_error_type"] = type(last_error).__name__
        super().__init__(message, **extras)
        self.last_error = last_error
        self.attempts = attempts
        self.elapsed_ms = elapsed_ms
        self.tool_name = tool_name


class AdapterToolCallError(AdapterError):
    """Raised when an MCP tool invocation fails.

    Carries the tool name and the (redacted) arguments so operators can
    correlate failures without leaking secrets. The original cause is
    preserved via ``raise ... from cause`` so tracebacks remain intact.

    The redacted tool arguments are exposed as ``tool_args`` rather than
    ``args``; ``args`` is reserved by ``BaseException`` for the positional
    constructor tuple and Python coerces it to a tuple on assignment,
    which would lose the dict structure.
    """

    def __init__(
        self,
        message: str,
        *,
        tool_name: str,
        tool_args: Optional[Mapping[str, Any]] = None,
        cause: Optional[BaseException] = None,
        attempt: Optional[int] = None,
        elapsed_ms: Optional[int] = None,
        **details: Any,
    ) -> None:
        extras: Dict[str, Any] = dict(details)
        extras["tool_name"] = tool_name
        if tool_args is not None:
            # tool_args is already expected to be redacted by the caller.
            extras["tool_args"] = dict(tool_args)
        if attempt is not None:
            extras["attempt"] = attempt
        if elapsed_ms is not None:
            extras["elapsed_ms"] = elapsed_ms
        if cause is not None:
            extras["cause_type"] = type(cause).__name__
        super().__init__(message, **extras)
        self.tool_name = tool_name
        self.tool_args: Dict[str, Any] = dict(tool_args) if tool_args is not None else {}
        self.cause = cause
        self.attempt = attempt
        self.elapsed_ms = elapsed_ms


class AdapterSchemaError(AdapterError):
    """Raised when an MCP tool schema cannot be interpreted.

    Examples: invalid JSON Schema, unsupported keyword, or a required
    field missing from a pydantic model build. ``offending_key`` helps
    the caller point an error message at the specific schema field.
    """

    def __init__(
        self,
        message: str,
        *,
        tool_name: Optional[str] = None,
        offending_key: Optional[str] = None,
        **details: Any,
    ) -> None:
        extras: Dict[str, Any] = dict(details)
        if tool_name is not None:
            extras["tool_name"] = tool_name
        if offending_key is not None:
            extras["offending_key"] = offending_key
        super().__init__(message, **extras)
        self.tool_name = tool_name
        self.offending_key = offending_key


class CordumPolicyDeniedError(AdapterError):
    """Gateway rejected a tool call under the active safety policy.

    Carries the ``approval_id`` the LLM can surface to a human plus
    the rule ``reason`` so the caller (or the error-to-message helper)
    can explain the denial. Distinct from :class:`AdapterToolCallError`
    because denial is a policy outcome, not a tool failure.
    """

    def __init__(
        self,
        message: str,
        *,
        approval_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        reason: Optional[str] = None,
        tenant_id: Optional[str] = None,
        **details: Any,
    ) -> None:
        extras: Dict[str, Any] = dict(details)
        if approval_id is not None:
            extras["approval_id"] = approval_id
        if tool_name is not None:
            extras["tool_name"] = tool_name
        if reason is not None:
            extras["reason"] = reason
        if tenant_id is not None:
            extras["tenant_id"] = tenant_id
        super().__init__(message, **extras)
        self.approval_id = approval_id
        self.tool_name = tool_name
        self.reason = reason
        self.tenant_id = tenant_id


class CordumToolExecutionError(AdapterError):
    """A tool reported ``isError=true`` with one or more content blocks.

    ``content`` mirrors the MCP content-block list so callers can
    surface whichever representation (text / image / resource ref)
    the tool produced.
    """

    def __init__(
        self,
        message: str,
        *,
        tool_name: Optional[str] = None,
        content: Optional[Any] = None,
        **details: Any,
    ) -> None:
        extras: Dict[str, Any] = dict(details)
        if tool_name is not None:
            extras["tool_name"] = tool_name
        if content is not None:
            extras["content"] = content
        super().__init__(message, **extras)
        self.tool_name = tool_name
        self.content = content


def mcp_error_to_openai_agents_message(exc: Exception) -> str:
    """Translate an MCP-layer exception to an OpenAI-Agents tool string.

    The Agents SDK Runner halts on an unhandled tool exception, so the
    Cordum adapter must never raise out of ``on_invoke_tool``. Instead
    every error becomes a string beginning with a stable prefix the
    LLM pattern-matches:

    - ``[POLICY DENIED]`` — gateway rejected under the safety policy
      (JSON-RPC ``-32099`` by project convention).
    - ``[TOOL ARG ERROR]`` — client supplied invalid params
      (``-32602``).
    - ``[TOOL ERROR]`` — tool ran but returned ``isError=true`` or a
      ``McpToolError``.
    - ``[INTERNAL ERROR]`` — anything else the adapter could not
      classify. Never leaks a stack trace.
    """
    # Local imports — keep errors.py free of the mcp_client transport.
    try:
        from .mcp_client import McpRpcError, McpToolError
    except Exception:  # pragma: no cover
        McpRpcError = None  # type: ignore[assignment]
        McpToolError = None  # type: ignore[assignment]

    if isinstance(exc, CordumPolicyDeniedError):
        return (
            f"[POLICY DENIED] tool={exc.tool_name or 'unknown'} "
            f"approval_id={exc.approval_id or 'unknown'} "
            f"reason={exc.reason or exc.message}. "
            "Try a different approach or request approval."
        )
    if McpRpcError is not None and isinstance(exc, McpRpcError):
        code = getattr(exc, "code", None)
        data = getattr(exc, "data", None) or {}
        if code == -32099:
            approval_id = _extract_field(data, "approval_id", "approvalId") or "unknown"
            tool_name = _extract_field(data, "tool", "tool_name", "toolName") or "unknown"
            reason = _extract_field(data, "reason", "message") or str(exc)
            return (
                f"[POLICY DENIED] tool={tool_name} approval_id={approval_id} "
                f"reason={reason}. Try a different approach or request approval."
            )
        if code == -32602:
            return f"[TOOL ARG ERROR] {exc}"
        return f"[TOOL ERROR] {exc}"
    if McpToolError is not None and isinstance(exc, McpToolError):
        return f"[TOOL ERROR] {exc}"
    if isinstance(exc, CordumToolExecutionError):
        return f"[TOOL ERROR] tool={exc.tool_name or 'unknown'} {exc.message}"
    if isinstance(exc, AdapterToolCallError):
        tool_name = exc.details.get("tool_name") or getattr(exc, "tool_name", None) or "unknown"
        return f"[TOOL ERROR] tool={tool_name} {exc.message}"
    return f"[INTERNAL ERROR] {type(exc).__name__}: {exc}"


def _extract_field(data: Any, *keys: str) -> Optional[str]:
    """Pluck the first present key from a nested dict-like error body."""
    if not isinstance(data, Mapping):
        return None
    for key in keys:
        value = data.get(key)
        if value:
            return str(value)
    return None


__all__ = [
    "AdapterError",
    "AdapterTimeoutError",
    "AdapterRetryExhaustedError",
    "AdapterToolCallError",
    "AdapterSchemaError",
    "CordumPolicyDeniedError",
    "CordumToolExecutionError",
    "mcp_error_to_openai_agents_message",
]
