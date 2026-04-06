from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx
from langchain_core.callbacks import BaseCallbackHandler

logger = logging.getLogger(__name__)

DECISION_DENY = "DECISION_TYPE_DENY"
DECISION_REQUIRE_HUMAN = "DECISION_TYPE_REQUIRE_HUMAN"


class CordumGovernanceCallback(BaseCallbackHandler):
    """LangChain callback that evaluates tool calls
    against the Cordum policy gateway before execution."""

    def __init__(
        self,
        cordum_url: str,
        api_key: Optional[str] = None,
        tenant: str = "default",
        topic: str = "job.default",
    ):
        self.cordum_url = cordum_url.rstrip("/")
        self.api_key = api_key
        self.tenant = tenant
        self.topic = topic

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _build_request(
        self, tool_name: str, risk_tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        return {
            "topic": self.topic,
            "tenant": self.tenant,
            "meta": {
                "capability": tool_name,
                "risk_tags": risk_tags or [],
            },
        }

    def _check_decision(self, tool_name: str, result: Dict[str, Any]) -> None:
        decision = result.get("decision", "")
        reason = result.get("reason", "no reason provided")
        if decision == DECISION_DENY:
            raise PermissionError(
                f"Tool '{tool_name}' denied by Cordum policy: {reason}"
            )
        if decision == DECISION_REQUIRE_HUMAN:
            raise PermissionError(
                f"Tool '{tool_name}' requires human approval: "
                f"ref={result.get('approval_ref')}, reason={reason}"
            )

    def _evaluate(self, tool_name: str) -> None:
        """Synchronously evaluate a tool call against the policy gateway."""
        try:
            response = httpx.post(
                f"{self.cordum_url}/api/v1/policy/evaluate",
                json=self._build_request(tool_name),
                headers=self._headers(),
                timeout=10.0,
            )
            self._check_decision(tool_name, response.json())
        except httpx.RequestError as exc:
            logger.warning("Cordum governance check failed: %s", exc)

    async def _evaluate_async(self, tool_name: str) -> None:
        """Async version of evaluate."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.cordum_url}/api/v1/policy/evaluate",
                    json=self._build_request(tool_name),
                    headers=self._headers(),
                    timeout=10.0,
                )
                self._check_decision(tool_name, response.json())
        except httpx.RequestError as exc:
            logger.warning("Cordum governance check failed: %s", exc)

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown")
        self._evaluate(tool_name)

    async def on_tool_start_async(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown")
        await self._evaluate_async(tool_name)


def govern(
    agent: Any,
    cordum_url: str = "http://localhost:8081",
    api_key: Optional[str] = None,
    tenant: str = "default",
    topic: str = "job.default",
) -> Any:
    """Wrap a LangChain agent with Cordum governance.

    Tool calls are evaluated against the Cordum policy gateway
    before execution. Denied or approval-required actions raise
    a PermissionError with the policy reason.
    """
    try:
        from langchain_core.runnables import Runnable
    except ImportError as exc:
        raise RuntimeError("langchain-core is required for Cordum governance") from exc

    callback = CordumGovernanceCallback(
        cordum_url=cordum_url,
        api_key=api_key,
        tenant=tenant,
        topic=topic,
    )
    
    if isinstance(agent, Runnable):
        return agent.with_config({"callbacks": [callback]})
    
    existing = list(getattr(agent, "callbacks", None) or [])
    agent.callbacks = existing + [callback]
    return agent