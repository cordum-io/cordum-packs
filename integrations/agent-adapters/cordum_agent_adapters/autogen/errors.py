"""MCP → AutoGen error mapping.

Two entry points:

* ``mcp_error_to_classic_message(exc) -> str`` — returns an ``ERROR:``-prefixed
  string. Classic pyautogen 0.2 ``register_function`` callables must NOT raise
  (raising terminates the conversation); returning a string lets the LLM see
  the failure on the next turn and respond to it.
* ``mcp_error_to_modern_exception(exc) -> Exception`` — returns a rich
  exception that AG2 0.4's async tool loop can raise and convert into a
  ``ToolCallResultEvent`` for the LLM to see. The wrapper in ``modern.py``
  calls this inside the ``_call`` coroutine.

Error class hierarchy:

* ``CordumAutoGenError`` — base.
* ``CordumPolicyDeniedError`` — raised for gateway policy denials
  (JSON-RPC code ``-32099``). Carries ``approval_id`` and ``reason`` so
  callers can route the denial to an approval UI.
* ``CordumToolExecutionError`` — raised for tool-side failures
  (``McpToolError``). Carries the tool name and the MCP content blocks
  flattened into a ``.message`` string plus the raw ``content`` list.

Unknown ``McpRpcError`` codes collapse to ``RuntimeError``; invalid-params
(``-32602``) maps to ``ValueError`` so framework-level schema validation
picks it up.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..mcp_client import McpError, McpRpcError, McpToolError


# JSON-RPC codes used by the gateway. -32099 is a server-defined code per
# JSON-RPC 2.0; the gateway reserves it for policy denials so the client
# can distinguish denied-by-policy from generic server errors.
RPC_INVALID_PARAMS = -32602
RPC_METHOD_NOT_FOUND = -32601
RPC_POLICY_DENIED = -32099


class CordumAutoGenError(Exception):
    """Base class for cordum-surfaced AutoGen adapter errors."""


class CordumPolicyDeniedError(CordumAutoGenError):
    """Gateway returned JSON-RPC -32099 (policy-denied)."""

    def __init__(
        self,
        message: str,
        *,
        approval_id: Optional[str] = None,
        reason: Optional[str] = None,
        data: Any = None,
    ) -> None:
        super().__init__(message)
        self.approval_id = approval_id
        self.reason = reason
        self.data = data


class CordumToolExecutionError(CordumAutoGenError):
    """Tool reported isError=True. ``content`` is the raw MCP content list."""

    def __init__(
        self,
        message: str,
        *,
        tool_name: str,
        content: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        super().__init__(message)
        self.tool_name = tool_name
        self.content = content or []


def _flatten_content(content: Optional[List[Dict[str, Any]]]) -> str:
    """Join an MCP content-block list into a single plain-text body.

    MCP tools return ``content`` as a list of blocks; the common case is
    ``[{"type": "text", "text": "..."}]`` but ``image`` / ``resource``
    blocks can appear too. Non-text blocks are represented by their
    ``type`` so the LLM at least knows they were present.
    """
    if not content:
        return ""
    parts: List[str] = []
    for block in content:
        if not isinstance(block, dict):
            parts.append(str(block))
            continue
        if block.get("type") == "text":
            parts.append(str(block.get("text", "")))
        else:
            btype = block.get("type") or "unknown"
            parts.append(f"[{btype}]")
    return "\n".join(part for part in parts if part)


def _extract_policy_metadata(data: Any) -> Dict[str, Optional[str]]:
    """Pull approval_id/reason out of an RPC error's ``data`` field.

    The gateway sends them on the JSON-RPC error object as
    ``{"approval_id": "...", "reason": "..."}`` when denying a call that
    needs an approval, but older emissions are plain strings. Accept
    either and fall back to ``None`` rather than raising.
    """
    if isinstance(data, dict):
        approval_id = data.get("approval_id")
        reason = data.get("reason")
        return {
            "approval_id": str(approval_id) if approval_id is not None else None,
            "reason": str(reason) if reason is not None else None,
        }
    if isinstance(data, str):
        return {"approval_id": None, "reason": data}
    return {"approval_id": None, "reason": None}


def mcp_error_to_modern_exception(exc: BaseException, *, tool_name: str = "") -> Exception:
    """Translate an ``McpError`` into a CordumAutoGenError subclass.

    Non-McpError exceptions are returned unchanged so the caller's
    ``raise`` semantics are preserved for unexpected infrastructure
    failures (network, subprocess death, etc.).
    """
    if isinstance(exc, McpRpcError):
        if exc.code == RPC_POLICY_DENIED:
            meta = _extract_policy_metadata(exc.data)
            return CordumPolicyDeniedError(
                exc.message,
                approval_id=meta["approval_id"],
                reason=meta["reason"],
                data=exc.data,
            )
        if exc.code == RPC_INVALID_PARAMS:
            return ValueError(exc.message)
        return RuntimeError(f"mcp rpc error {exc.code}: {exc.message}")
    if isinstance(exc, McpToolError):
        content = exc.result.get("content") if isinstance(exc.result, dict) else None
        body = _flatten_content(content) or exc.message
        return CordumToolExecutionError(
            body,
            tool_name=tool_name,
            content=content if isinstance(content, list) else None,
        )
    if isinstance(exc, McpError):
        return RuntimeError(str(exc))
    if isinstance(exc, Exception):
        return exc
    # BaseException (KeyboardInterrupt, SystemExit): never swallow.
    return RuntimeError(str(exc))


def mcp_error_to_classic_message(exc: BaseException, *, tool_name: str = "") -> str:
    """Translate an ``McpError`` into an ``ERROR:``-prefixed classic message.

    pyautogen 0.2's ``register_function`` callables must return text the
    LLM can read; raising would abort the conversation loop. The prefix
    lets an LLM (or a human reading a trace) trivially distinguish
    tool-failure strings from tool-success strings.
    """
    if isinstance(exc, McpRpcError):
        if exc.code == RPC_POLICY_DENIED:
            meta = _extract_policy_metadata(exc.data)
            reason = meta["reason"] or exc.message
            approval = meta["approval_id"]
            if approval:
                return f"ERROR: policy denied ({reason}) — approval_id={approval}"
            return f"ERROR: policy denied ({reason})"
        if exc.code == RPC_INVALID_PARAMS:
            return f"ERROR: invalid arguments — {exc.message}"
        return f"ERROR: rpc error {exc.code} — {exc.message}"
    if isinstance(exc, McpToolError):
        content = exc.result.get("content") if isinstance(exc.result, dict) else None
        body = _flatten_content(content) or exc.message
        prefix = f"tool {tool_name!r} failed" if tool_name else "tool call failed"
        return f"ERROR: {prefix} — {body}"
    if isinstance(exc, McpError):
        return f"ERROR: mcp client error — {exc}"
    # Infrastructure / programming errors: still string, still readable.
    return f"ERROR: {type(exc).__name__} — {exc}"
