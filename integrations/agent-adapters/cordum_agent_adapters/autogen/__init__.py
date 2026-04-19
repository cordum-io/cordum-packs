"""Cordum AutoGen adapter.

Supports two generations of the framework:

* **Classic** — ``pyautogen~=0.2``. ``build_autogen_tools`` returns the
  legacy ``(functions, function_map)`` tuple so existing callers keep
  working; ``register_cordum_tools(agent, client, api='classic')`` wires
  the function map straight into ``ConversableAgent.register_function``.
* **Modern (AG2)** — ``autogen-core>=0.4`` + ``autogen-agentchat>=0.4``.
  ``build_ag2_tools`` returns ``FunctionTool`` instances the caller
  passes into ``AssistantAgent(tools=...)``; ``register_cordum_tools(...,
  api='modern')`` stapes the tools on directly when the agent exposes
  a mutable ``.tools`` sequence.

``register_cordum_tools(agent, client, api='auto')`` picks the correct
path via duck-typing and returns a :class:`CordumAutoGenBinding` dataclass
so callers can introspect the wired tools / function map / logger.

The two framework extras are mutually exclusive in a single interpreter
(different openai pins); see ``pyproject.toml``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional

from ..mcp_client import McpStdioClient
from .audit import CordumConversationLogger
from .classic import build_autogen_openai_tools, build_autogen_tools

# Modern tools live in a separate module so importing this package does
# NOT require autogen-core. ``register_cordum_tools`` lazy-imports them.


Api = Literal["auto", "classic", "modern"]


@dataclass
class CordumAutoGenBinding:
    """Return value of :func:`register_cordum_tools`.

    Exactly one of ``function_map`` / ``tools`` is populated depending
    on the API path taken. ``logger`` is whatever the caller supplied
    (never auto-constructed — the caller owns lifecycle).
    """

    api: str
    tools: List[Any] = field(default_factory=list)
    function_map: Dict[str, Callable[..., Any]] = field(default_factory=dict)
    logger: Optional[CordumConversationLogger] = None


def _detect_api(agent: Any) -> str:
    """Duck-type the agent to classic vs modern.

    Classic ``ConversableAgent`` exposes ``register_function``; modern
    ``AssistantAgent`` exposes ``tools`` as a list (even if empty) or
    ``on_messages_stream``. Fall back to ``classic`` so pre-existing
    integrations keep working on the legacy API.
    """
    if hasattr(agent, "on_messages_stream") or hasattr(agent, "_model_client"):
        return "modern"
    if hasattr(agent, "register_function"):
        return "classic"
    if hasattr(agent, "tools"):
        return "modern"
    return "classic"


def _register_classic(
    agent: Any,
    client: McpStdioClient,
    tools: Optional[List[Dict[str, Any]]],
    logger: Optional[CordumConversationLogger],
) -> CordumAutoGenBinding:
    functions, function_map = build_autogen_tools(client, tools=tools)
    register_function = getattr(agent, "register_function", None)
    if register_function is None:
        raise TypeError(
            "classic AutoGen agent is missing register_function; "
            "pass a ConversableAgent or use api='modern'"
        )
    register_function(function_map)

    # Optional reply hook → logger. register_reply is the 0.2 API; skip
    # when it isn't there (some stripped-down subclasses omit it).
    if logger is not None:
        register_reply = getattr(agent, "register_reply", None)
        if callable(register_reply):
            def _cordum_reply_hook(recipient: Any, messages: Any, sender: Any, config: Any):  # noqa: ANN401
                try:
                    last = messages[-1] if messages else {}
                    logger.log_turn({
                        "kind": "message",
                        "sender": getattr(sender, "name", str(sender)),
                        "recipient": getattr(recipient, "name", str(recipient)),
                        "content": last.get("content") if isinstance(last, dict) else str(last),
                    })
                except Exception:  # noqa: BLE001 — never let audit kill a turn
                    pass
                return False, None

            try:
                from autogen import Agent  # type: ignore[import-not-found]
                register_reply([Agent, None], _cordum_reply_hook)
            except Exception:  # noqa: BLE001 — best-effort hook only
                try:
                    register_reply(None, _cordum_reply_hook)
                except Exception:  # noqa: BLE001
                    pass

    return CordumAutoGenBinding(
        api="classic",
        function_map=function_map,
        logger=logger,
    )


def _register_modern(
    agent: Any,
    client: McpStdioClient,
    tools: Optional[List[Dict[str, Any]]],
    logger: Optional[CordumConversationLogger],
) -> CordumAutoGenBinding:
    from .modern import build_ag2_tools  # lazy: only if autogen-core is installed

    # Passing `logger` into build_ag2_tools makes each tool invocation
    # land on the audit tool at call time — so a real AG2 run that
    # dispatches tool calls (AssistantAgent, RoundRobinGroupChat, etc.)
    # gets conversation tracking at the tool boundary without a
    # stream-observer dance.
    built = build_ag2_tools(client, tools=tools, logger=logger)
    existing = getattr(agent, "tools", None)
    if isinstance(existing, list):
        # Extend in place so the agent's tool loop sees the new entries.
        existing.extend(built)
    else:
        # Some AG2 builds freeze tools at construction; set the attr if
        # the agent allows it, otherwise the caller is expected to pass
        # the returned list into the constructor themselves.
        try:
            setattr(agent, "tools", list(built))
        except (AttributeError, TypeError):
            pass

    # Wrap on_messages_stream so pure-LLM turns (no tool call) also
    # land in the audit trail. AG2's AssistantAgent / BaseChatAgent
    # expose this async generator; we decorate it to forward the same
    # events after teeing each TextMessage / ToolCallSummaryMessage into
    # logger.log_turn. Best-effort only — a framework that doesn't
    # carry the method is left untouched.
    if logger is not None:
        _attach_stream_logger(agent, logger)

    return CordumAutoGenBinding(
        api="modern",
        tools=built,
        logger=logger,
    )


def _attach_stream_logger(agent: Any, logger: CordumConversationLogger) -> None:
    """Wrap ``agent.on_messages_stream`` to tee each event into the logger.

    The wrapped generator forwards every item from the original and
    additionally invokes ``logger.log_turn`` for message-shaped events
    (anything with a ``content`` attribute or dict key). Errors inside
    the logger are swallowed so audit failure never breaks the stream.
    """
    original = getattr(agent, "on_messages_stream", None)
    if not callable(original):
        return

    async def _wrapped(messages, cancellation_token=None):  # type: ignore[no-untyped-def]
        async for event in original(messages, cancellation_token):
            try:
                turn = _event_to_turn(event)
                if turn:
                    logger.log_turn(turn)
            except Exception:  # noqa: BLE001 — audit must not break the loop
                pass
            yield event

    try:
        setattr(agent, "on_messages_stream", _wrapped)
    except (AttributeError, TypeError):
        # Agent class is frozen (dataclass(frozen=True), slots, etc.).
        # The tool-call-boundary logger wired via build_ag2_tools still
        # runs, so we keep partial coverage.
        pass


def _event_to_turn(event: Any) -> Optional[Dict[str, Any]]:
    """Best-effort projection of an AG2 stream event into a turn dict.

    AG2 0.4+ emits dataclass-like events with ``source``, ``content``,
    and sometimes ``type`` attributes. We read attributes defensively
    so a schema change in autogen-agentchat doesn't crash the wrapper.
    """
    if event is None:
        return None
    source = getattr(event, "source", None)
    content = getattr(event, "content", None)
    if source is None and content is None:
        return None
    return {
        "kind": "message",
        "sender": str(source) if source is not None else "",
        "content": content if isinstance(content, (str, dict, list)) else str(content),
        "event_type": type(event).__name__,
    }


def register_cordum_tools(
    agent: Any,
    client: McpStdioClient,
    *,
    tools: Optional[List[Dict[str, Any]]] = None,
    logger: Optional[CordumConversationLogger] = None,
    api: Api = "auto",
) -> CordumAutoGenBinding:
    """Wire Cordum MCP tools onto an AutoGen agent.

    Parameters
    ----------
    agent:
        Either a classic ``ConversableAgent`` (pyautogen 0.2) or a modern
        ``AssistantAgent`` (autogen-agentchat 0.4+).
    client:
        Live ``McpStdioClient`` pointed at ``cordum-mcp-bridge``.
    tools:
        Optional pre-fetched tool list; when ``None`` the adapter calls
        ``client.list_tools()`` itself.
    logger:
        Optional :class:`CordumConversationLogger`; when supplied,
        classic agents get a reply hook that logs each turn. Modern
        agents are expected to feed the logger from their own message
        stream (see :mod:`tutorials/autogen.md`).
    api:
        ``'auto'`` (default), ``'classic'``, or ``'modern'``.
    """
    chosen = api if api != "auto" else _detect_api(agent)
    if chosen == "classic":
        return _register_classic(agent, client, tools, logger)
    if chosen == "modern":
        return _register_modern(agent, client, tools, logger)
    raise ValueError(f"unknown api: {api!r}")


__all__ = [
    "CordumAutoGenBinding",
    "CordumConversationLogger",
    "build_autogen_openai_tools",
    "build_autogen_tools",
    "register_cordum_tools",
]
