"""Global hook for zero-change LangChain governance adoption.

Pattern B: Patch LangChain globally so ALL tool calls go through CAP.

    from cordum_langchain_guard import patch_langchain

    patch_langchain(
        gateway_url="http://localhost:8081",
        api_key="...",
    )

    # All agents — zero changes. Every tool call goes through CAP.
    agent = create_react_agent(llm, tools)  # unchanged
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

_patched = False
_original_run = None
_original_arun = None


def patch_langchain(
    gateway_url: str = "http://localhost:8081",
    api_key: str = "",
    tenant_id: str = "default",
    default_risk_tags: list[str] | None = None,
    topic: str = "job.langchain-guard.tool",
    poll_timeout: float = 60.0,
) -> None:
    """Monkey-patch LangChain's BaseTool so ALL tool calls go through CAP.

    This is the zero-change adoption path. Call once at app startup and every
    LangChain tool call across all agents will be submitted as a CAP job,
    policy-evaluated, and worker-executed through Cordum.

    To undo, call unpatch_langchain().
    """
    global _patched, _original_run, _original_arun

    if _patched:
        logger.warning("LangChain is already patched for Cordum governance")
        return

    try:
        from langchain_core.tools import BaseTool
    except ImportError as exc:
        raise RuntimeError(
            "langchain-core is required: pip install cordum-langchain-guard[langchain]"
        ) from exc

    from .gateway import (
        ApprovalRequiredError,
        AsyncGatewayClient,
        GatewayClient,
        GatewayError,
    )

    gateway = GatewayClient(
        gateway_url=gateway_url,
        api_key=api_key,
        tenant_id=tenant_id,
        poll_timeout=poll_timeout,
    )
    async_gateway = AsyncGatewayClient(
        gateway_url=gateway_url,
        api_key=api_key,
        tenant_id=tenant_id,
        poll_timeout=poll_timeout,
    )

    risk_tags = default_risk_tags or []

    _original_run = BaseTool._run
    _original_arun = BaseTool._arun

    def patched_run(self: Any, tool_input: Any, **kwargs: Any) -> str:
        from .adapter import _handle_result, _serialize_input

        tool_name = self.name
        context = {
            "tool_name": tool_name,
            "tool_input": _serialize_input(tool_input),
        }
        labels = {"langchain.tool": tool_name}
        if self.description:
            labels["langchain.description"] = self.description[:200]

        try:
            result = gateway.submit_and_wait(
                topic=topic,
                prompt=f"LangChain tool call: {tool_name}",
                context=context,
                capability=tool_name,
                risk_tags=risk_tags,
                labels=labels,
            )
            return _handle_result(result, tool_name)
        except ApprovalRequiredError as exc:
            return (
                f"[AWAITING APPROVAL] {tool_name}: {exc.reason} "
                f"(job_id={exc.job_id}). "
                f"A human must approve this action in the Cordum dashboard."
            )
        except GatewayError as exc:
            from langchain_core.tools import ToolException

            raise ToolException(f"[GATEWAY ERROR] {tool_name}: {exc}") from exc

    async def patched_arun(self: Any, tool_input: Any, **kwargs: Any) -> str:
        from .adapter import _handle_result, _serialize_input

        tool_name = self.name
        context = {
            "tool_name": tool_name,
            "tool_input": _serialize_input(tool_input),
        }
        labels = {"langchain.tool": tool_name}
        if self.description:
            labels["langchain.description"] = self.description[:200]

        try:
            result = await async_gateway.submit_and_wait(
                topic=topic,
                prompt=f"LangChain tool call: {tool_name}",
                context=context,
                capability=tool_name,
                risk_tags=risk_tags,
                labels=labels,
            )
            return _handle_result(result, tool_name)
        except ApprovalRequiredError as exc:
            return (
                f"[AWAITING APPROVAL] {tool_name}: {exc.reason} "
                f"(job_id={exc.job_id}). "
                f"A human must approve this action in the Cordum dashboard."
            )
        except GatewayError as exc:
            from langchain_core.tools import ToolException

            raise ToolException(f"[GATEWAY ERROR] {tool_name}: {exc}") from exc

    BaseTool._run = patched_run
    BaseTool._arun = patched_arun
    _patched = True
    logger.info("LangChain patched for Cordum governance (topic=%s)", topic)


def unpatch_langchain() -> None:
    """Undo the global LangChain patch."""
    global _patched, _original_run, _original_arun

    if not _patched:
        return

    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        return

    if _original_run is not None:
        BaseTool._run = _original_run
    if _original_arun is not None:
        BaseTool._arun = _original_arun

    _patched = False
    _original_run = None
    _original_arun = None
    logger.info("LangChain Cordum governance patch removed")
