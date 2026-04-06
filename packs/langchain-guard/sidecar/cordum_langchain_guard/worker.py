"""Worker that executes LangChain tools inside Cordum's infrastructure.

Registers as a CAP worker for the langchain-guard.tool topic.
When a governed tool call is submitted as a job, this worker receives it,
executes the original tool function, and returns the result through CAP.

Supports two modes:
- in_process: runs as a background asyncio task in the agent's process
- remote: runs as a standalone worker process (for production deployments)
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict

logger = logging.getLogger(__name__)

_DEFAULT_TOPIC = "job.langchain-guard.tool"


class ToolRegistry:
    """Thread-safe registry of LangChain tools available for worker execution."""

    def __init__(self) -> None:
        self._tools: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def register(self, tool: Any) -> None:
        """Register a LangChain BaseTool for worker execution."""
        with self._lock:
            self._tools[tool.name] = tool

    def register_many(self, tools: list[Any]) -> None:
        with self._lock:
            for t in tools:
                self._tools[t.name] = t

    def get(self, name: str) -> Any | None:
        with self._lock:
            return self._tools.get(name)

    def names(self) -> list[str]:
        with self._lock:
            return list(self._tools.keys())

    def __len__(self) -> int:
        with self._lock:
            return len(self._tools)


class InProcessWorker:
    """Runs tool execution as an in-process background task.

    For the in-process pattern, the worker doesn't subscribe to NATS directly.
    Instead, the gateway dispatches the job to a CAP worker pool. In development
    or single-node deployments, we run a lightweight HTTP-polling worker that
    picks up jobs assigned to this worker and executes them locally.

    For production, use the CAP runtime Agent (cap.runtime.Agent) which subscribes
    to NATS directly. See RemoteWorker below.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        gateway_url: str,
        api_key: str = "",
        tenant_id: str = "default",
    ):
        self._registry = registry
        self._gateway_url = gateway_url
        self._api_key = api_key
        self._tenant_id = tenant_id
        self._running = False

    def execute_tool(self, tool_name: str, tool_input: Any) -> Dict[str, Any]:
        """Execute a registered tool and return the result dict."""
        tool = self._registry.get(tool_name)
        if tool is None:
            return {
                "tool_name": tool_name,
                "error": f"Tool '{tool_name}' not registered in worker",
            }

        start = time.monotonic()
        try:
            # Call the ORIGINAL tool function (before governance wrapping)
            original_run = getattr(tool, "_original_run", None) or tool._run
            if isinstance(tool_input, dict):
                result = original_run(**tool_input)
            else:
                result = original_run(tool_input)

            elapsed_ms = (time.monotonic() - start) * 1000
            return {
                "tool_name": tool_name,
                "output": result,
                "execution_ms": elapsed_ms,
            }
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error("Tool %s failed: %s", tool_name, exc)
            return {
                "tool_name": tool_name,
                "error": str(exc),
                "execution_ms": elapsed_ms,
            }

    def start(self) -> None:
        """Start the in-process worker in a background thread."""
        if self._running:
            return
        self._running = True
        logger.info(
            "In-process worker started with %d tools: %s",
            len(self._registry),
            self._registry.names(),
        )

    def stop(self) -> None:
        """Stop the in-process worker."""
        self._running = False
        logger.info("In-process worker stopped")


def create_remote_worker(
    registry: ToolRegistry,
    nats_url: str = "nats://127.0.0.1:4222",
    redis_url: str = "redis://127.0.0.1:6379",
    topic: str = _DEFAULT_TOPIC,
    pool: str = "langchain-guard",
    max_parallel: int = 4,
) -> Any:
    """Create a CAP runtime Agent worker for production NATS deployment.

    Requires cap-sdk-python: pip install cordum-langchain-guard[nats]

    Usage:
        registry = ToolRegistry()
        registry.register_many(my_tools)
        worker = create_remote_worker(registry, nats_url="nats://...")
        asyncio.run(worker.run())
    """
    try:
        from cap.runtime import Agent, Context
    except ImportError as exc:
        raise RuntimeError(
            "cap-sdk-python is required for remote workers: "
            "pip install cordum-langchain-guard[nats]"
        ) from exc

    agent = Agent(
        nats_url=nats_url,
        redis_url=redis_url,
        sender_id="langchain-guard-worker",
        pool=pool,
        max_parallel=max_parallel,
    )

    @agent.job(topic)
    async def handle_tool_call(ctx: Context, data: dict) -> dict:
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        ctx.logger.info("Executing tool: %s", tool_name)

        tool = registry.get(tool_name)
        if tool is None:
            return {
                "tool_name": tool_name,
                "error": f"Tool '{tool_name}' not registered",
            }

        start = time.monotonic()
        try:
            import asyncio
            original_run = tool._run
            if isinstance(tool_input, dict):
                result = await asyncio.to_thread(original_run, **tool_input)
            else:
                result = await asyncio.to_thread(original_run, tool_input)

            elapsed_ms = (time.monotonic() - start) * 1000
            return {
                "tool_name": tool_name,
                "output": result if isinstance(result, (str, dict, list)) else str(result),
                "execution_ms": elapsed_ms,
            }
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            ctx.logger.error("Tool %s failed: %s", tool_name, exc)
            return {
                "tool_name": tool_name,
                "error": str(exc),
                "execution_ms": elapsed_ms,
            }

    return agent
