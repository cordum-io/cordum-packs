"""Adapter-agnostic conversation logger for Cordum agent runs.

:class:`CordumConversationLogger` posts each turn of an agent run to the
``cordum.audit.log_turn`` MCP tool so the gateway records a complete
conversation transcript alongside the policy-decision audit trail. The
class is designed to be safe to use from any framework adapter:

- **Backoff**: each MCP call uses :class:`RetryPolicy` so a single
  flaky request doesn't lose the turn.
- **Graceful degradation**: if the gateway does not advertise the
  ``cordum.audit.log_turn`` tool (older deployments, or a customer
  who has not installed the audit pack), the logger silently falls
  back to a debug log line. It NEVER raises out of an agent run —
  the run's success cannot depend on the audit transport.
- **Truncation**: payloads larger than ``MAX_TURN_BYTES`` (8 KiB) get
  their long fields trimmed with a clear marker so the LLM
  conversation isn't silently lost but the bus payload stays bounded.
- **Session identity**: a fresh uuid4 per logger instance unless the
  caller supplies their own, surfaced through :attr:`session_id`.

This module is import-safe — depends only on stdlib + the
:mod:`cordum_agent_adapters.mcp_client` transport (which is itself
stdlib-only).
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from typing import Any, Dict, Optional

from .errors import AdapterError, AdapterRetryExhaustedError
from .mcp_client import McpRpcError, McpStdioClient, McpToolError
from .retry import RetryPolicy, default_retryable, retry_call


def _audit_retryable(exc: BaseException) -> bool:
    """A tweaked retry predicate for the audit transport.

    ``-32601`` (method not found) means the gateway simply does not
    advertise ``cordum.audit.log_turn``. Retrying is pointless; we
    surface the error immediately so the logger caches the
    tool-unavailable state and short-circuits subsequent turns.
    """
    if isinstance(exc, McpRpcError) and getattr(exc, "code", None) == -32601:
        return False
    return default_retryable(exc)

_logger = logging.getLogger(__name__)

MAX_TURN_BYTES = 8 * 1024
_TRUNCATION_MARKER = "...[TRUNCATED]"
_AUDIT_TOOL_NAME = "cordum.audit.log_turn"


class CordumConversationLogger:
    """Stream conversation turns to the gateway audit pipeline.

    Construct one logger per agent run. The session id ties every
    turn to a single conversation in the audit trail; the dashboard's
    Approvals view filters by session id when it surfaces the
    decision context.
    """

    def __init__(
        self,
        client: McpStdioClient,
        *,
        session_id: Optional[str] = None,
        retry_policy: Optional[RetryPolicy] = None,
        tool_name: str = _AUDIT_TOOL_NAME,
        max_turn_bytes: int = MAX_TURN_BYTES,
    ) -> None:
        self._client = client
        self.session_id: str = session_id or uuid.uuid4().hex
        # Conservative defaults: 2 retries, short backoff. Audit must
        # be best-effort fast or we risk delaying the agent.
        self._retry_policy = retry_policy or RetryPolicy(
            max_attempts=3,
            initial_backoff_s=0.05,
            max_backoff_s=0.5,
            retryable=_audit_retryable,
        )
        self._tool_name = tool_name
        self._max_bytes = max_turn_bytes
        self._tool_available: Optional[bool] = None  # tri-state cache
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_turn(self, turn: Dict[str, Any]) -> None:
        """Send a single conversation turn to the audit pipeline.

        ``turn`` is a free-form dict produced by the calling adapter
        (tee_events for OpenAI Agents, the autogen middleware for
        AutoGen, etc). This method NEVER raises — failures are
        DEBUG-logged so an audit outage does not abort the run.
        """
        if not isinstance(turn, dict) or not turn:
            return
        if not self._is_tool_available():
            _logger.debug(
                "audit tool %s not advertised by gateway; skipping turn",
                self._tool_name,
            )
            return
        payload = self._build_payload(turn)
        try:
            retry_call(
                self._client.call_tool,
                self._retry_policy,
                self._tool_name,
                payload,
                tool_name=self._tool_name,
            )
        except (McpRpcError, McpToolError, AdapterError) as exc:
            # If the gateway has retired the tool mid-run, mark it
            # unavailable so subsequent turns short-circuit instead of
            # spending retry budget for nothing.
            if isinstance(exc, McpRpcError) and getattr(exc, "code", None) == -32601:
                with self._lock:
                    self._tool_available = False
            _logger.debug(
                "audit tool %s failed; turn not recorded",
                self._tool_name,
                exc_info=exc,
            )
        except Exception:  # noqa: BLE001
            _logger.debug(
                "audit tool %s raised unexpectedly; turn not recorded",
                self._tool_name,
                exc_info=True,
            )

    def log_tool_invocation(self, tool_name: str, args: Any, result_or_error: Any) -> None:
        """Helper for adapters that expose a per-tool-call hook.

        Wraps the call into a uniform turn dict so the audit pipeline
        sees a single shape regardless of which adapter produced it.
        """
        self.log_turn(
            {
                "kind": "tool_call",
                "tool_name": tool_name,
                "args": args,
                "result": result_or_error,
            }
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _is_tool_available(self) -> bool:
        with self._lock:
            cached = self._tool_available
        if cached is not None:
            return cached
        try:
            tools = self._client.list_tools()
        except Exception:  # noqa: BLE001
            _logger.debug("list_tools failed during audit probe", exc_info=True)
            with self._lock:
                self._tool_available = False
            return False
        names = {(t.get("name") or "").strip() for t in tools if isinstance(t, dict)}
        ok = self._tool_name in names
        with self._lock:
            self._tool_available = ok
        return ok

    def _build_payload(self, turn: Dict[str, Any]) -> Dict[str, Any]:
        body = {"session_id": self.session_id, "turn": turn}
        # Best-effort truncation: trim only after we hit the byte cap so
        # small turns are passed through as-is. We trim the longest
        # string field first since that's almost always the offender.
        encoded = json.dumps(body, default=str).encode("utf-8")
        if len(encoded) <= self._max_bytes:
            return body
        truncated_turn = self._truncate_turn(turn)
        body = {"session_id": self.session_id, "turn": truncated_turn, "truncated": True}
        encoded = json.dumps(body, default=str).encode("utf-8")
        if len(encoded) > self._max_bytes:
            # Last resort: drop everything except identity + a marker.
            body = {
                "session_id": self.session_id,
                "turn": {"kind": turn.get("kind", "unknown")},
                "truncated": True,
                "reason": "payload exceeded max_turn_bytes after field-level truncation",
            }
        return body

    def _truncate_turn(self, turn: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        # Limit per-field bytes proportionally to keep small fields intact.
        per_field_cap = max(256, self._max_bytes // max(1, len(turn) * 2))
        for key, value in turn.items():
            if isinstance(value, str) and len(value.encode("utf-8")) > per_field_cap:
                trimmed = value.encode("utf-8")[: per_field_cap - len(_TRUNCATION_MARKER)].decode(
                    "utf-8", errors="ignore"
                )
                out[key] = trimmed + _TRUNCATION_MARKER
            elif isinstance(value, (dict, list)):
                # Render then trim — preserves structure as a string.
                rendered = json.dumps(value, default=str)
                if len(rendered.encode("utf-8")) > per_field_cap:
                    out[key] = (
                        rendered[: per_field_cap - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER
                    )
                else:
                    out[key] = value
            else:
                out[key] = value
        return out


__all__ = ["CordumConversationLogger", "MAX_TURN_BYTES"]
