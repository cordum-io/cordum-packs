"""AutoGen 0.4+ (AG2) adapter.

Builds ``autogen_core.tools.FunctionTool`` instances from MCP tool
definitions. Each tool's ``_call`` coroutine runs the blocking
``McpStdioClient.call_tool`` via ``asyncio.to_thread`` so the event loop
stays responsive, and wraps every exception through
``mcp_error_to_modern_exception`` so policy denials, invalid-arg errors,
and tool-side failures surface as proper Python exceptions AG2 can
render as ``ToolCallResultEvent``.

AG2 (autogen-core / autogen-agentchat) is an optional install — the
import is deferred until ``build_ag2_tools`` is called so importing this
module does not require the framework to be present.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Type

from .._pydantic_models import build_model
from ..mcp_client import McpStdioClient
from .errors import mcp_error_to_modern_exception

logger_module = logging.getLogger(__name__)


def _serialise_result(result: Any) -> str:
    """Turn an MCP call result into a string the LLM can consume.

    MCP tool results are ``{isError: bool, content: [...blocks...]}``.
    AG2 tools return strings; so we flatten the content list. Structured
    non-content payloads round-trip as JSON.
    """
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            parts: List[str] = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
                elif isinstance(block, dict):
                    parts.append(json.dumps(block, sort_keys=True, default=str))
                else:
                    parts.append(str(block))
            return "\n".join(p for p in parts if p) or ""
        try:
            return json.dumps(result, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return str(result)
    return str(result)


def _make_async_caller(
    client: McpStdioClient,
    tool_name: str,
    args_model: Optional[Type[Any]],
    logger: Optional[Any] = None,
) -> Callable[..., Any]:
    """Build the ``async def _call(**kwargs) -> str`` the FunctionTool wraps.

    ``args_model`` is stapled onto the callable by FunctionTool; we keep a
    reference so pydantic validation runs before the MCP round-trip. When
    the caller skipped the model (pydantic unavailable), the kwargs are
    passed through verbatim.

    ``logger`` is an optional
    :class:`cordum_agent_adapters.audit.CordumConversationLogger`. When
    supplied, every tool invocation is recorded via ``log_tool_invocation``
    regardless of success or failure, giving AG2 runs an audit trail
    even when the framework doesn't expose a stream-level hook. The
    logger contract is "never raises", so audit failures do not
    propagate into the tool-caller loop.
    """

    async def _call(**kwargs: Any) -> str:
        payload: Dict[str, Any] = kwargs
        if args_model is not None:
            try:
                instance = args_model(**kwargs)
                # Support pydantic v1 (.dict) and v2 (.model_dump).
                dump = getattr(instance, "model_dump", None) or getattr(instance, "dict", None)
                if dump is not None:
                    payload = dump()
            except Exception as exc:  # noqa: BLE001
                if logger is not None:
                    logger.log_tool_invocation(tool_name, payload, {"error": str(exc)})
                raise mcp_error_to_modern_exception(exc, tool_name=tool_name) from exc
        try:
            result = await asyncio.to_thread(client.call_tool, tool_name, payload)
        except BaseException as exc:  # noqa: BLE001 — translate + re-raise
            if logger is not None:
                logger.log_tool_invocation(tool_name, payload, {"error": str(exc)})
            raise mcp_error_to_modern_exception(exc, tool_name=tool_name) from exc
        if logger is not None:
            logger.log_tool_invocation(tool_name, payload, result)
        return _serialise_result(result)

    _call.__name__ = f"mcp_{tool_name}"
    _call.__qualname__ = _call.__name__
    return _call


def build_ag2_tools(
    client: McpStdioClient,
    tools: Optional[List[Dict[str, Any]]] = None,
    logger: Optional[Any] = None,
) -> List[Any]:
    """Build AG2 tool instances for every MCP tool.

    Each MCP tool becomes a :class:`autogen_core.tools.BaseTool`
    subclass whose args schema is derived from the MCP ``inputSchema``
    via :func:`_pydantic_models.build_model`. BaseTool is used instead
    of FunctionTool because MCP tools carry a JSON-Schema argument
    contract that we want AG2 to enforce BEFORE invoking the handler —
    FunctionTool builds its schema from the Python function's
    signature, which for dynamic ``**kwargs`` wrappers produces a
    useless single ``kwargs`` field. BaseTool with an explicit
    args_type preserves the MCP contract.

    Parameters
    ----------
    client:
        Live ``McpStdioClient``. The adapter does NOT take ownership of
        the client — the caller is responsible for ``close()``.
    tools:
        Optional pre-fetched tool listing. When ``None``, the adapter
        calls ``client.list_tools()`` itself.
    logger:
        Optional :class:`cordum_agent_adapters.audit.CordumConversationLogger`.
        When supplied every tool invocation lands on
        ``log_tool_invocation`` so the AG2 run has conversation-audit
        coverage at the tool boundary.

    Returns
    -------
    list[BaseTool]
        One entry per MCP tool. Pass directly into
        ``AssistantAgent(tools=...)``.

    Raises
    ------
    ImportError
        When ``autogen-core`` is not installed.
    """
    try:
        from autogen_core import CancellationToken  # type: ignore[import-not-found]
        from autogen_core.tools import BaseTool  # type: ignore[import-not-found]
        from pydantic import BaseModel, ConfigDict, create_model  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - exercised via importorskip in tests
        raise ImportError(
            "autogen-core is required for build_ag2_tools; install with "
            "`pip install cordum-adapters[autogen]`"
        ) from exc

    defs = tools if tools is not None else client.list_tools()
    out: List[Any] = []
    for tool in defs:
        name = str(tool.get("name") or "").strip()
        if not name:
            logger_module.debug("skipping nameless tool def: %r", tool)
            continue
        description = str(tool.get("description") or name)
        input_schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}

        args_model = build_model(name, input_schema) if isinstance(input_schema, dict) else None
        if args_model is None:
            # Ensure BaseTool has SOME args_type so the framework's
            # validation doesn't blow up on an empty schema. Use a
            # permissive pydantic model that admits any field.
            args_model = create_model(
                f"{name}_PermissiveArgs",
                __config__=ConfigDict(extra="allow"),
            )
        strict = input_schema.get("additionalProperties") is False if isinstance(input_schema, dict) else False

        tool_cls = _make_base_tool_class(
            BaseTool, CancellationToken, client, name, description, args_model, strict, logger
        )
        out.append(tool_cls())
    return out


def _make_base_tool_class(
    base_tool_cls: Any,
    cancellation_token_cls: Any,
    client: McpStdioClient,
    name: str,
    description: str,
    args_model: Type[Any],
    strict: bool,
    logger: Optional[Any],
) -> Any:
    """Synthesize a BaseTool subclass bound to a specific MCP tool.

    Capturing the closure state (client, name, logger) at class-build
    time keeps the :meth:`run` body simple and means a fresh instance
    per tool does not leak the closure across tools.
    """

    class _CordumMcpTool(base_tool_cls):  # type: ignore[misc, valid-type]
        def __init__(self) -> None:
            super().__init__(
                args_type=args_model,
                return_type=str,
                name=name,
                description=description,
                strict=strict,
            )

        async def run(self, args: Any, cancellation_token: Any) -> str:  # type: ignore[override]
            # args is a pydantic model instance; serialise to a plain
            # dict so the MCP stdio transport can re-JSON it. Support
            # v1 (.dict) + v2 (.model_dump).
            dump = getattr(args, "model_dump", None) or getattr(args, "dict", None)
            payload: Dict[str, Any] = dump() if dump is not None else (dict(args.__dict__) if hasattr(args, "__dict__") else {})
            try:
                result = await asyncio.to_thread(client.call_tool, name, payload)
            except BaseException as exc:  # noqa: BLE001
                if logger is not None:
                    logger.log_tool_invocation(name, payload, {"error": str(exc)})
                raise mcp_error_to_modern_exception(exc, tool_name=name) from exc
            if logger is not None:
                logger.log_tool_invocation(name, payload, result)
            return _serialise_result(result)

    _CordumMcpTool.__name__ = f"Cordum_{name.replace('.', '_').replace('-', '_')}Tool"
    _CordumMcpTool.__qualname__ = _CordumMcpTool.__name__
    _ = cancellation_token_cls  # reserved for future cancel-aware path
    return _CordumMcpTool


__all__ = [
    "build_ag2_tools",
]
