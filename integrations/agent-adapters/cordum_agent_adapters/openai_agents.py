"""Cordum adapter for the OpenAI Agents SDK (``openai-agents``).

Supported version: ``openai-agents>=0.1`` (import path ``from agents import ...``).

The adapter bridges Cordum's governed MCP surface into the Agents SDK's
native tool-calling loop:

- :func:`build_openai_agent_tools` converts MCP tool definitions into
  :class:`agents.FunctionTool` instances with strict JSON-Schema and an
  async ``on_invoke_tool`` callback that proxies through
  :class:`cordum_agent_adapters.mcp_client.McpStdioClient`.
- :func:`run_governed` wraps :func:`agents.Runner.run_streamed` so the
  Cordum conversation logger sees every turn.
- :func:`register_cordum_mcp` attaches the Cordum tools to an existing
  :class:`agents.Agent` instance.

Policy denials (JSON-RPC ``-32099``) from the gateway NEVER raise out
of the tool callback — doing so aborts the Runner loop. Instead the
denial becomes a string return value prefixed ``[POLICY DENIED]`` so
the LLM reads it in the next turn and can choose a different action.

Example::

    from agents import Agent, Runner
    from cordum_agent_adapters.mcp_client import McpStdioClient
    from cordum_agent_adapters.openai_agents import (
        build_openai_agent_tools, register_cordum_mcp, run_governed,
    )

    client = McpStdioClient(["cordum-mcp-bridge"])
    with client:
        tools = build_openai_agent_tools(client)
        agent = Agent(name="ops", instructions="You operate Cordum.", tools=tools)
        result = await run_governed(agent, "list my jobs", client=client)
        async for ev in result.stream_events():
            ...
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import uuid
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

from ._schema import normalise_strict_schema
from .errors import (
    AdapterError,
    AdapterToolCallError,
    mcp_error_to_openai_agents_message,
)
from .mcp_client import McpError, McpRpcError, McpStdioClient, McpToolError

_logger = logging.getLogger(__name__)

# Exported for tooling/tests; populated lazily so the module imports
# without the optional openai-agents extra.
__all__ = [
    "build_openai_agent_tools",
    "build_openai_agent_tools_sync",
    "register_cordum_mcp",
    "run_governed",
    "tee_events",
]


# _normalise_strict_schema previously lived here; it now ships from the
# shared `_schema` module so every adapter (CrewAI, AutoGen, OpenAI
# Agents, LangChain) shares one schema-normalisation contract. The
# private alias preserves any in-tree call sites the next refactor
# might introduce.
_normalise_strict_schema = normalise_strict_schema


def _flatten_content_blocks(result: Any) -> str:
    """Serialise an MCP call_tool result into a short LLM-ready string.

    MCP returns ``{content: [{type: text, text: ...}, ...]}``. The LLM
    sees the concatenated text of every ``text`` block; non-text
    blocks are represented as their JSON form so the model still has
    a hint of what happened. Raw dict inputs (from tests) fall back
    to ``json.dumps`` for safety.
    """
    if result is None:
        return ""
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            parts: List[str] = []
            for block in content:
                if not isinstance(block, dict):
                    parts.append(json.dumps(block, default=str))
                    continue
                if block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
                else:
                    parts.append(json.dumps(block, default=str))
            return "".join(parts)
        return json.dumps(result, default=str)
    return str(result)


def _build_on_invoke_tool(
    client: McpStdioClient,
    tool_name: str,
    *,
    result_transform: Optional[Callable[[Any], Any]] = None,
    logger: Optional[Any] = None,
) -> Callable[[Any, str], Any]:
    """Construct the async ``on_invoke_tool`` callback for one MCP tool.

    The callback NEVER raises — an unhandled exception in the Agents
    Runner loop aborts the run. Errors are translated via
    :func:`mcp_error_to_openai_agents_message` into a string return
    value so the LLM sees the failure on its next turn.
    """

    async def _on_invoke_tool(ctx: Any, args_json: str) -> str:  # noqa: ARG001
        try:
            args = json.loads(args_json) if args_json else {}
        except json.JSONDecodeError as exc:
            msg = f"[TOOL ARG ERROR] malformed JSON: {exc}"
            if logger is not None and hasattr(logger, "log_tool_invocation"):
                try:
                    logger.log_tool_invocation(tool_name, args_json, msg)
                except Exception:  # noqa: BLE001
                    _logger.debug("conversation logger failed", exc_info=True)
            return msg
        try:
            result = await asyncio.to_thread(client.call_tool, tool_name, args)
        except (McpError, McpRpcError, McpToolError, AdapterError) as exc:
            msg = mcp_error_to_openai_agents_message(exc)
            if logger is not None and hasattr(logger, "log_tool_invocation"):
                try:
                    logger.log_tool_invocation(tool_name, args, msg)
                except Exception:  # noqa: BLE001
                    _logger.debug("conversation logger failed", exc_info=True)
            return msg
        except Exception as exc:  # noqa: BLE001
            # Wrap truly-unexpected errors. Still return a string so
            # the Runner continues; the wrapped exception is stored
            # in the adapter error for downstream debugging.
            wrapped = AdapterToolCallError(
                f"internal error invoking {tool_name}",
                tool_name=tool_name,
                tool_args=args,
                cause=exc,
            )
            msg = mcp_error_to_openai_agents_message(wrapped)
            if logger is not None and hasattr(logger, "log_tool_invocation"):
                try:
                    logger.log_tool_invocation(tool_name, args, msg)
                except Exception:  # noqa: BLE001
                    _logger.debug("conversation logger failed", exc_info=True)
            return msg
        payload: Any = result
        if result_transform is not None:
            try:
                payload = result_transform(result)
            except Exception as exc:  # noqa: BLE001
                _logger.warning("result_transform raised; using raw result", exc_info=exc)
                payload = result
        text = _flatten_content_blocks(payload)
        if logger is not None and hasattr(logger, "log_tool_invocation"):
            try:
                logger.log_tool_invocation(tool_name, args, payload)
            except Exception:  # noqa: BLE001
                _logger.debug("conversation logger failed", exc_info=True)
        return text

    return _on_invoke_tool


def build_openai_agent_tools(
    client: McpStdioClient,
    tools: Optional[List[Dict[str, Any]]] = None,
    *,
    result_transform: Optional[Callable[[Any], Any]] = None,
    strict: bool = True,
    logger: Optional[Any] = None,
) -> List[Any]:
    """Produce :class:`agents.FunctionTool` instances from MCP tools.

    ``tools`` may be an explicit list (skipping a round trip to the
    MCP server) or ``None`` (the default) in which case the client's
    ``list_tools`` is called. ``strict`` controls whether the
    generated JSON-Schema is normalised for the SDK's strict mode;
    disable it only when an upstream tool advertises a loose schema
    the LLM cannot satisfy.
    """
    try:
        from agents import FunctionTool
    except ImportError as exc:  # pragma: no cover - exercised via importorskip
        raise ImportError(
            "openai-agents is not installed — `pip install "
            "cordum-adapters[openai-agents]` to use this adapter"
        ) from exc

    tool_defs = tools if tools is not None else client.list_tools()
    function_tools: List[Any] = []
    for tool_def in tool_defs:
        name = str(tool_def.get("name", "")).strip()
        if not name:
            continue
        description = str(tool_def.get("description", "") or "")
        raw_schema = tool_def.get("inputSchema") or {}
        params_schema = normalise_strict_schema(raw_schema) if strict else dict(raw_schema)
        kwargs: Dict[str, Any] = {
            "name": name,
            "description": description,
            "params_json_schema": params_schema,
            "on_invoke_tool": _build_on_invoke_tool(
                client,
                name,
                result_transform=result_transform,
                logger=logger,
            ),
        }
        # The SDK accepts ``strict_json_schema`` on newer builds; feed
        # it opportunistically so callers that set strict=False get the
        # looser validator. Older versions ignore unknown kwargs.
        try:
            function_tools.append(FunctionTool(strict_json_schema=strict, **kwargs))
        except TypeError:
            function_tools.append(FunctionTool(**kwargs))
    return function_tools


def build_openai_agent_tools_sync(
    client: McpStdioClient,
    tools: Optional[List[Dict[str, Any]]] = None,
    **kwargs: Any,
) -> List[Any]:
    """Sync shim for callers that aren't already running under asyncio.

    The heavy lifting inside ``build_openai_agent_tools`` is sync —
    the only async code is the per-call ``on_invoke_tool`` callback.
    This shim exists so imports from sync contexts stay natural.
    """
    return build_openai_agent_tools(client, tools, **kwargs)


async def run_governed(
    agent: Any,
    input_: Any,
    *,
    client: McpStdioClient,  # noqa: ARG001  # retained for symmetry / future wiring
    logger: Optional[Any] = None,
    run_config: Optional[Any] = None,
) -> Any:
    """Start an Agents Runner streamed run with Cordum session metadata.

    Returns the SDK's ``RunResultStreaming``. Callers typically iterate
    it directly or via :func:`tee_events` when they want turn-by-turn
    notifications to the conversation logger.
    """
    try:
        from agents import RunConfig, Runner
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "openai-agents is not installed — `pip install "
            "cordum-adapters[openai-agents]` to use run_governed"
        ) from exc
    if run_config is None:
        session_id = getattr(logger, "session_id", None) or uuid.uuid4().hex
        run_config = RunConfig(trace_metadata={"cordum_session_id": session_id})
    elif getattr(run_config, "trace_metadata", None) is None:
        session_id = getattr(logger, "session_id", None) or uuid.uuid4().hex
        try:
            run_config.trace_metadata = {"cordum_session_id": session_id}
        except Exception:  # noqa: BLE001 - SDK versions differ
            pass
    return Runner.run_streamed(agent, input_, run_config=run_config)


async def tee_events(streaming_result: Any, logger: Optional[Any] = None) -> AsyncIterator[Any]:
    """Yield every event from the Runner stream, tee-ing tool calls.

    Callers :code:`async for ev in tee_events(result, logger):` to
    consume events as usual; whenever the event describes a tool call
    or tool-call output, :meth:`logger.log_turn` is invoked with a
    flat dict. Missing / non-logger inputs are tolerated.
    """
    async for ev in streaming_result.stream_events():
        try:
            if logger is not None and hasattr(logger, "log_turn"):
                _maybe_log_turn(ev, logger)
        except Exception:  # noqa: BLE001
            _logger.debug("tee_events logger failure", exc_info=True)
        yield ev


def _maybe_log_turn(ev: Any, logger: Any) -> None:
    """Best-effort translation of a stream event to a Cordum turn dict."""
    item = getattr(ev, "item", None)
    if item is None:
        return
    item_type = getattr(item, "type", "")
    if item_type not in {"tool_call_item", "tool_call_output_item"}:
        return
    turn: Dict[str, Any] = {
        "kind": item_type,
        "name": getattr(item, "name", None),
    }
    for attr in ("arguments", "output", "call_id", "tool_call_id"):
        value = getattr(item, attr, None)
        if value is not None:
            turn[attr] = value
    logger.log_turn(turn)


def register_cordum_mcp(
    agent: Any,
    client: McpStdioClient,
    *,
    tools: Optional[List[Dict[str, Any]]] = None,
    logger: Optional[Any] = None,
    strict: bool = True,
) -> Any:
    """Return a copy of ``agent`` with the Cordum MCP tools attached.

    Two MCP sources of truth on one Agent is a footgun — if
    ``agent.mcp_servers`` is already non-empty, we raise
    :class:`ValueError` so the caller explicitly chooses one path.
    """
    mcp_servers = getattr(agent, "mcp_servers", None) or ()
    if mcp_servers:
        raise ValueError(
            "register_cordum_mcp: agent.mcp_servers is non-empty — two MCP "
            "sources of truth (SDK MCPServer + Cordum bridge) is a footgun. "
            "Remove the native mcp_servers or pass the Cordum client to only "
            "one path."
        )
    cordum_tools = build_openai_agent_tools(
        client, tools, strict=strict, logger=logger
    )
    existing_tools = list(getattr(agent, "tools", None) or ())
    merged = existing_tools + cordum_tools
    if dataclasses.is_dataclass(agent) and not isinstance(agent, type):
        return dataclasses.replace(agent, tools=merged)
    clone = getattr(agent, "clone", None)
    if callable(clone):
        return clone(tools=merged)
    # Fall back to direct mutation — acceptable for test doubles and
    # SDK versions that don't ship a clone method yet.
    agent.tools = merged
    return agent
