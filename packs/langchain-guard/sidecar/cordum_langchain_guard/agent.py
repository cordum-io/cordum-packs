"""CordumAgent — the main entry point for governing LangChain agents.

Pattern A: Per-agent wrapping with granular control.

    from cordum_langchain_guard import CordumAgent

    cordum = CordumAgent("http://localhost:8081", api_key="...")
    safe_tools = cordum.govern(tools, risk_tags=["write"])
    agent = create_react_agent(llm, safe_tools)
"""

from __future__ import annotations

from typing import Any, Optional

from .adapter import govern_tools
from .gateway import AsyncGatewayClient, GatewayClient
from .worker import InProcessWorker, ToolRegistry


class CordumAgent:
    """Govern LangChain agents through the Cordum control plane.

    Tool calls become real CAP jobs — policy-evaluated, scheduled,
    worker-executed, and audited. Cordum owns the execution.
    """

    def __init__(
        self,
        gateway_url: str = "http://localhost:8081",
        api_key: str = "",
        tenant_id: str = "default",
        timeout: float = 20.0,
        poll_interval: float = 0.75,
        poll_timeout: float = 60.0,
    ):
        self._gateway = GatewayClient(
            gateway_url=gateway_url,
            api_key=api_key,
            tenant_id=tenant_id,
            timeout=timeout,
            poll_interval=poll_interval,
            poll_timeout=poll_timeout,
        )
        self._async_gateway = AsyncGatewayClient(
            gateway_url=gateway_url,
            api_key=api_key,
            tenant_id=tenant_id,
            timeout=timeout,
            poll_interval=poll_interval,
            poll_timeout=poll_timeout,
        )
        self._gateway_url = gateway_url
        self._api_key = api_key
        self._tenant_id = tenant_id
        self._registry = ToolRegistry()
        self._worker: Optional[InProcessWorker] = None

    def govern(
        self,
        tools: list[Any],
        *,
        risk_tags: list[str] | None = None,
        topic: str = "job.langchain-guard.tool",
        labels: dict[str, str] | None = None,
        start_worker: bool = True,
    ) -> list[Any]:
        """Wrap LangChain tools so their calls become CAP jobs.

        Args:
            tools: List of LangChain BaseTool instances.
            risk_tags: Default risk tags for all tools. Override per-tool by
                       setting tool.metadata["risk_tags"].
            topic: CAP topic for tool execution jobs.
            labels: Extra labels attached to every job.
            start_worker: If True, start an in-process worker to handle
                         tool execution. Set False for remote worker setups.

        Returns:
            New list of governed tools (originals are not modified).
        """
        # Register originals so the worker can execute them
        self._registry.register_many(tools)

        if start_worker and self._worker is None:
            self._worker = InProcessWorker(
                registry=self._registry,
                gateway_url=self._gateway_url,
                api_key=self._api_key,
                tenant_id=self._tenant_id,
            )
            self._worker.start()

        return govern_tools(
            tools,
            self._gateway,
            self._async_gateway,
            risk_tags=risk_tags,
            topic=topic,
            labels=labels,
        )

    def close(self) -> None:
        """Clean up resources."""
        if self._worker:
            self._worker.stop()
        self._gateway.close()

    def __enter__(self) -> CordumAgent:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
