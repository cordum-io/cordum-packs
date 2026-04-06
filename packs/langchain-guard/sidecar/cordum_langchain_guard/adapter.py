"""LangChain tool adapter — wraps BaseTool so tool calls become CAP jobs."""

from __future__ import annotations

import json
import logging
from copy import deepcopy
from typing import Any, Optional

from .gateway import (
    ApprovalRequiredError,
    AsyncGatewayClient,
    GatewayClient,
    GatewayError,
    JobResult,
)

logger = logging.getLogger(__name__)

_DEFAULT_TOPIC = "job.langchain-guard.tool"


def _serialize_input(tool_input: Any) -> Any:
    """Ensure tool input is JSON-serializable."""
    if isinstance(tool_input, str):
        return tool_input
    if isinstance(tool_input, dict):
        return tool_input
    try:
        return json.loads(json.dumps(tool_input, default=str))
    except (TypeError, ValueError):
        return str(tool_input)


def _result_to_string(result: JobResult) -> str:
    """Convert a job result to a string for LangChain."""
    if result.result is None:
        return ""
    if isinstance(result.result, str):
        return result.result
    return json.dumps(result.result, default=str)


def handle_job_result(result: JobResult, tool_name: str) -> str:
    """Process a terminal job result into a LangChain-compatible response.

    Module-level so it can be used by both govern_tool() and patch_langchain().
    """
    try:
        from langchain_core.tools import ToolException
    except ImportError:
        ToolException = PermissionError  # fallback

    if result.is_succeeded:
        return _result_to_string(result)

    if result.is_denied:
        raise ToolException(
            f"[BLOCKED] {tool_name}: {result.safety_reason or 'denied by policy'}"
        )

    if result.is_approval_required:
        ref = result.approval_ref
        reason = result.safety_reason or "requires human approval"
        return (
            f"[AWAITING APPROVAL] {tool_name}: {reason} "
            f"(ref={ref}, job_id={result.job_id}). "
            f"A human must approve this action in the Cordum dashboard "
            f"before it will execute."
        )

    if result.is_failed:
        raise ToolException(
            f"[FAILED] {tool_name}: {result.error_message or result.state}"
        )

    raise ToolException(f"[UNEXPECTED] {tool_name}: state={result.state}")


def govern_tool(
    tool: Any,
    gateway: GatewayClient,
    async_gateway: Optional[AsyncGatewayClient] = None,
    *,
    risk_tags: list[str] | None = None,
    topic: str = _DEFAULT_TOPIC,
    labels: dict[str, str] | None = None,
) -> Any:
    """Wrap a single LangChain BaseTool so its calls become CAP jobs.

    When the tool is invoked:
    - Input is serialized and submitted as a CAP job
    - Safety Kernel evaluates policy (ALLOW/DENY/THROTTLE/REQUIRE_APPROVAL)
    - If allowed, a worker executes the tool inside Cordum's infrastructure
    - Result flows back to the LangChain agent

    Approval handling: REQUIRE_APPROVAL returns immediately to the LLM with a
    message like "[AWAITING APPROVAL] tool_name: reason (ref=xxx)". This lets
    the agent continue doing other work instead of blocking indefinitely.

    DENY raises ToolException so LangChain surfaces the denial to the LLM.
    """
    try:
        from langchain_core.tools import BaseTool, ToolException
    except ImportError as exc:
        raise RuntimeError(
            "langchain-core is required: pip install cordum-langchain-guard[langchain]"
        ) from exc

    if not isinstance(tool, BaseTool):
        raise TypeError(f"Expected BaseTool, got {type(tool).__name__}")

    wrapped = deepcopy(tool)

    tool_risk_tags = risk_tags or []
    tool_labels = dict(labels or {})
    tool_labels["langchain.tool"] = tool.name
    if tool.description:
        tool_labels["langchain.description"] = tool.description[:200]

    def governed_run(tool_input: Any, **kwargs: Any) -> str:
        tool_name = wrapped.name
        context = {
            "tool_name": tool_name,
            "tool_input": _serialize_input(tool_input),
        }
        try:
            result = gateway.submit_and_wait(
                topic=topic,
                prompt=f"LangChain tool call: {tool_name}",
                context=context,
                capability=tool_name,
                risk_tags=tool_risk_tags,
                labels=tool_labels,
            )
            return handle_job_result(result, tool_name)
        except ApprovalRequiredError as exc:
            return (
                f"[AWAITING APPROVAL] {tool_name}: {exc.reason} "
                f"(job_id={exc.job_id}). "
                f"A human must approve this action in the Cordum dashboard "
                f"before it will execute."
            )
        except GatewayError as exc:
            raise ToolException(f"[GATEWAY ERROR] {tool_name}: {exc}") from exc

    async def governed_arun(tool_input: Any, **kwargs: Any) -> str:
        gw = async_gateway
        if gw is None:
            import asyncio
            return await asyncio.to_thread(governed_run, tool_input, **kwargs)

        tool_name = wrapped.name
        context = {
            "tool_name": tool_name,
            "tool_input": _serialize_input(tool_input),
        }
        try:
            result = await gw.submit_and_wait(
                topic=topic,
                prompt=f"LangChain tool call: {tool_name}",
                context=context,
                capability=tool_name,
                risk_tags=tool_risk_tags,
                labels=tool_labels,
            )
            return handle_job_result(result, tool_name)
        except ApprovalRequiredError as exc:
            return (
                f"[AWAITING APPROVAL] {tool_name}: {exc.reason} "
                f"(job_id={exc.job_id}). "
                f"A human must approve this action in the Cordum dashboard "
                f"before it will execute."
            )
        except GatewayError as exc:
            raise ToolException(f"[GATEWAY ERROR] {tool_name}: {exc}") from exc

    wrapped._run = governed_run
    wrapped._arun = governed_arun
    wrapped.handle_tool_error = True
    return wrapped


def govern_tools(
    tools: list[Any],
    gateway: GatewayClient,
    async_gateway: Optional[AsyncGatewayClient] = None,
    *,
    risk_tags: list[str] | None = None,
    topic: str = _DEFAULT_TOPIC,
    labels: dict[str, str] | None = None,
) -> list[Any]:
    """Wrap multiple LangChain tools. Returns a new list of governed tools."""
    return [
        govern_tool(
            t,
            gateway,
            async_gateway,
            risk_tags=risk_tags,
            topic=topic,
            labels=labels,
        )
        for t in tools
    ]
