"""Structured audit logger for governance decisions."""

from __future__ import annotations

import json
import logging
import time

logger = logging.getLogger("cordum.langchain_guard.audit")


class AuditLogger:
    """Emits structured JSON audit records for every governance decision.

    Records are written to Python's logging system at INFO level under
    the 'cordum.langchain_guard.audit' logger. Configure handlers as needed
    (file, stdout, external sink).
    """

    def __init__(self, extra_fields: dict[str, str] | None = None):
        self._extra = extra_fields or {}

    def log_submission(
        self,
        *,
        tool_name: str,
        job_id: str,
        trace_id: str = "",
        risk_tags: list[str] | None = None,
        topic: str = "",
    ) -> None:
        record = {
            "event": "tool_submitted",
            "tool_name": tool_name,
            "job_id": job_id,
            "trace_id": trace_id,
            "risk_tags": risk_tags or [],
            "topic": topic,
            "timestamp": time.time(),
            **self._extra,
        }
        logger.info(json.dumps(record, default=str))

    def log_decision(
        self,
        *,
        tool_name: str,
        job_id: str,
        state: str,
        reason: str = "",
        trace_id: str = "",
        execution_ms: float = 0,
    ) -> None:
        record = {
            "event": "tool_decision",
            "tool_name": tool_name,
            "job_id": job_id,
            "state": state,
            "reason": reason,
            "trace_id": trace_id,
            "execution_ms": execution_ms,
            "timestamp": time.time(),
            **self._extra,
        }
        logger.info(json.dumps(record, default=str))

    def log_error(
        self,
        *,
        tool_name: str,
        error: str,
        job_id: str = "",
    ) -> None:
        record = {
            "event": "tool_error",
            "tool_name": tool_name,
            "job_id": job_id,
            "error": error,
            "timestamp": time.time(),
            **self._extra,
        }
        logger.warning(json.dumps(record, default=str))
