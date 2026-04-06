"""HTTP client for the Cordum gateway — job submission, polling, and result retrieval."""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

_JOB_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

logger = logging.getLogger(__name__)

_TERMINAL_STATES = frozenset({
    "SUCCEEDED", "FAILED", "DENIED", "CANCELLED", "TIMEOUT",
    "APPROVAL_REQUIRED", "OUTPUT_QUARANTINED",
})


@dataclass
class JobResult:
    """Parsed result from a completed CAP job."""

    job_id: str
    state: str
    result: Any = None
    error_message: str = ""
    safety_reason: str = ""
    approval_required: bool = False
    approval_ref: str = ""
    safety_remediations: List[Dict[str, Any]] = field(default_factory=list)
    trace_id: str = ""
    execution_ms: float = 0

    @property
    def is_denied(self) -> bool:
        return self.state == "DENIED"

    @property
    def is_approval_required(self) -> bool:
        return self.state == "APPROVAL_REQUIRED" or self.approval_required

    @property
    def is_succeeded(self) -> bool:
        return self.state == "SUCCEEDED"

    @property
    def is_failed(self) -> bool:
        return self.state in ("FAILED", "TIMEOUT", "CANCELLED", "OUTPUT_QUARANTINED")


class GatewayError(Exception):
    """Base error for gateway operations."""


class JobDeniedError(GatewayError):
    """Raised when the Safety Kernel denies a job."""

    def __init__(self, job_id: str, reason: str, remediations: list | None = None):
        self.job_id = job_id
        self.reason = reason
        self.remediations = remediations or []
        super().__init__(f"Job {job_id} denied: {reason}")


class ApprovalRequiredError(GatewayError):
    """Raised when a job requires human approval."""

    def __init__(self, job_id: str, reason: str, approval_ref: str = ""):
        self.job_id = job_id
        self.reason = reason
        self.approval_ref = approval_ref
        super().__init__(
            f"Job {job_id} requires human approval: {reason} (ref={approval_ref})"
        )


class GatewayClient:
    """Synchronous HTTP client for the Cordum API Gateway.

    Modeled after the mcp-bridge gateway client pattern:
    submit job → poll until terminal → return result.
    """

    def __init__(
        self,
        gateway_url: str,
        api_key: str = "",
        tenant_id: str = "default",
        timeout: float = 20.0,
        poll_interval: float = 0.75,
        poll_timeout: float = 60.0,
    ):
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError(
                "httpx is required: pip install cordum-langchain-guard"
            ) from exc

        self._base_url = gateway_url.rstrip("/")
        self._tenant_id = tenant_id
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout

        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key
        if tenant_id:
            headers["X-Tenant-ID"] = tenant_id

        self._client = httpx.Client(
            base_url=self._base_url,
            headers=headers,
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> GatewayClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def submit_job(
        self,
        *,
        topic: str,
        prompt: str,
        context: Any = None,
        capability: str = "",
        risk_tags: list[str] | None = None,
        requires: list[str] | None = None,
        pack_id: str = "langchain-guard",
        labels: dict[str, str] | None = None,
        actor_id: str = "langchain-guard",
        actor_type: str = "service",
    ) -> tuple[str, str]:
        """Submit a CAP job. Returns (job_id, trace_id)."""
        body: Dict[str, Any] = {
            "prompt": prompt,
            "topic": topic,
            "context": context,
            "capability": capability,
            "risk_tags": risk_tags or [],
            "requires": requires or [],
            "pack_id": pack_id,
            "actor_id": actor_id,
            "actor_type": actor_type,
        }
        if labels:
            body["labels"] = labels

        resp = self._client.post("/api/v1/jobs", json=body)
        resp.raise_for_status()
        data = resp.json()

        job_id = data["job_id"]
        trace_id = data.get("trace_id", "")

        # Gateway may return approval_required immediately
        if data.get("status") == "approval_required":
            raise ApprovalRequiredError(
                job_id=job_id,
                reason=data.get("reason", "Policy requires human approval"),
            )

        logger.debug("Submitted job %s (trace=%s)", job_id, trace_id)
        return job_id, trace_id

    def get_job(self, job_id: str) -> JobResult:
        """Fetch current job state."""
        if not _JOB_ID_PATTERN.match(job_id):
            raise GatewayError(f"Invalid job_id: {job_id!r}")
        resp = self._client.get(f"/api/v1/jobs/{job_id}")
        resp.raise_for_status()
        data = resp.json()
        return JobResult(
            job_id=data.get("id", job_id),
            state=data.get("state", "UNKNOWN").upper(),
            result=data.get("result"),
            error_message=data.get("error_message", ""),
            safety_reason=data.get("safety_reason", ""),
            approval_required=data.get("approval_required", False),
            approval_ref=data.get("approval_ref", ""),
            safety_remediations=data.get("safety_remediations") or [],
            trace_id=data.get("trace_id", ""),
        )

    def poll_until_terminal(self, job_id: str) -> JobResult:
        """Poll a job until it reaches a terminal state.

        Raises GatewayError if poll_timeout is exceeded.
        """
        deadline = time.monotonic() + self._poll_timeout
        while True:
            result = self.get_job(job_id)
            if result.state in _TERMINAL_STATES:
                logger.debug(
                    "Job %s reached state %s", job_id, result.state
                )
                return result
            if time.monotonic() >= deadline:
                raise GatewayError(
                    f"Job {job_id} did not reach terminal state within "
                    f"{self._poll_timeout}s (current: {result.state})"
                )
            time.sleep(self._poll_interval)

    def submit_and_wait(
        self,
        *,
        topic: str,
        prompt: str,
        context: Any = None,
        capability: str = "",
        risk_tags: list[str] | None = None,
        requires: list[str] | None = None,
        pack_id: str = "langchain-guard",
        labels: dict[str, str] | None = None,
        actor_id: str = "langchain-guard",
        actor_type: str = "service",
    ) -> JobResult:
        """Submit a job and poll until completion. Convenience wrapper."""
        job_id, _ = self.submit_job(
            topic=topic,
            prompt=prompt,
            context=context,
            capability=capability,
            risk_tags=risk_tags,
            requires=requires,
            pack_id=pack_id,
            labels=labels,
            actor_id=actor_id,
            actor_type=actor_type,
        )
        return self.poll_until_terminal(job_id)


class AsyncGatewayClient:
    """Async HTTP client for the Cordum API Gateway."""

    def __init__(
        self,
        gateway_url: str,
        api_key: str = "",
        tenant_id: str = "default",
        timeout: float = 20.0,
        poll_interval: float = 0.75,
        poll_timeout: float = 60.0,
    ):
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError(
                "httpx is required: pip install cordum-langchain-guard"
            ) from exc

        self._base_url = gateway_url.rstrip("/")
        self._tenant_id = tenant_id
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout

        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key
        if tenant_id:
            headers["X-Tenant-ID"] = tenant_id

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=timeout,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncGatewayClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def submit_job(
        self,
        *,
        topic: str,
        prompt: str,
        context: Any = None,
        capability: str = "",
        risk_tags: list[str] | None = None,
        requires: list[str] | None = None,
        pack_id: str = "langchain-guard",
        labels: dict[str, str] | None = None,
        actor_id: str = "langchain-guard",
        actor_type: str = "service",
    ) -> tuple[str, str]:
        """Submit a CAP job. Returns (job_id, trace_id)."""
        body: Dict[str, Any] = {
            "prompt": prompt,
            "topic": topic,
            "context": context,
            "capability": capability,
            "risk_tags": risk_tags or [],
            "requires": requires or [],
            "pack_id": pack_id,
            "actor_id": actor_id,
            "actor_type": actor_type,
        }
        if labels:
            body["labels"] = labels

        resp = await self._client.post("/api/v1/jobs", json=body)
        resp.raise_for_status()
        data = resp.json()

        job_id = data["job_id"]
        trace_id = data.get("trace_id", "")

        if data.get("status") == "approval_required":
            raise ApprovalRequiredError(
                job_id=job_id,
                reason=data.get("reason", "Policy requires human approval"),
            )

        logger.debug("Submitted job %s (trace=%s)", job_id, trace_id)
        return job_id, trace_id

    async def get_job(self, job_id: str) -> JobResult:
        """Fetch current job state."""
        if not _JOB_ID_PATTERN.match(job_id):
            raise GatewayError(f"Invalid job_id: {job_id!r}")
        resp = await self._client.get(f"/api/v1/jobs/{job_id}")
        resp.raise_for_status()
        data = resp.json()
        return JobResult(
            job_id=data.get("id", job_id),
            state=data.get("state", "UNKNOWN").upper(),
            result=data.get("result"),
            error_message=data.get("error_message", ""),
            safety_reason=data.get("safety_reason", ""),
            approval_required=data.get("approval_required", False),
            approval_ref=data.get("approval_ref", ""),
            safety_remediations=data.get("safety_remediations") or [],
            trace_id=data.get("trace_id", ""),
        )

    async def poll_until_terminal(self, job_id: str) -> JobResult:
        """Poll a job until it reaches a terminal state."""
        import asyncio

        deadline = time.monotonic() + self._poll_timeout
        while True:
            result = await self.get_job(job_id)
            if result.state in _TERMINAL_STATES:
                logger.debug("Job %s reached state %s", job_id, result.state)
                return result
            if time.monotonic() >= deadline:
                raise GatewayError(
                    f"Job {job_id} did not reach terminal state within "
                    f"{self._poll_timeout}s (current: {result.state})"
                )
            await asyncio.sleep(self._poll_interval)

    async def submit_and_wait(
        self,
        *,
        topic: str,
        prompt: str,
        context: Any = None,
        capability: str = "",
        risk_tags: list[str] | None = None,
        requires: list[str] | None = None,
        pack_id: str = "langchain-guard",
        labels: dict[str, str] | None = None,
        actor_id: str = "langchain-guard",
        actor_type: str = "service",
    ) -> JobResult:
        """Submit a job and poll until completion."""
        job_id, _ = await self.submit_job(
            topic=topic,
            prompt=prompt,
            context=context,
            capability=capability,
            risk_tags=risk_tags,
            requires=requires,
            pack_id=pack_id,
            labels=labels,
            actor_id=actor_id,
            actor_type=actor_type,
        )
        return await self.poll_until_terminal(job_id)
