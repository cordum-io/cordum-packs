"""CrewAI adapter: turn MCP tool descriptors into CrewAI ``BaseTool`` subclasses.

The public surface is :func:`build_crewai_tools` (per-tool factory) and the
convenience helper :func:`build_crew` added in step-7 which wires a full
``Crew`` from a declarative agents/tasks config.

Design notes:

* MCP calls go through :func:`retry_call` / :func:`retry_call_async` so a
  transient NATS/gateway hiccup doesn't kill a whole Crew run.
* Every tool-call failure is wrapped in :class:`AdapterToolCallError` with
  the arguments redacted so logs don't leak secrets.
* ``args_schema`` uses pydantic models built by the shared helpers in
  ``_pydantic_models`` so every adapter honours arrays/enums/nested/nullable
  /formats the same way.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Type

from .errors import AdapterSchemaError, AdapterToolCallError
from .mcp_client import McpStdioClient
from .retry import RetryPolicy, retry_call, retry_call_async

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CrewAI BaseTool discovery
# ---------------------------------------------------------------------------


def _load_base_tool() -> Any:
    """Load the CrewAI BaseTool class, trying crewai_tools first, then crewai."""
    try:
        from crewai_tools import BaseTool
        return BaseTool
    except ImportError:
        logger.info("crewai_tools.BaseTool not available, trying crewai.tools")
    try:
        from crewai.tools import BaseTool
        return BaseTool
    except ImportError as exc:
        raise RuntimeError(
            "CrewAI is not installed. Run `pip install cordum-adapters[crewai]` "
            "to pull in the optional dependency."
        ) from exc


# ---------------------------------------------------------------------------
# Argument coercion + redaction
# ---------------------------------------------------------------------------


def _coerce_kwargs(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    if kwargs:
        return kwargs
    if not args:
        return {}
    if len(args) == 1:
        raw = args[0]
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                return {"input": raw}
        return {"input": raw}
    return {"args": list(args)}


# Key-level redaction: word-boundary match so ``api_version`` stays
# visible while ``api_key`` / ``apiKey`` / ``x-api-key`` are scrubbed.
# Pattern tested against adversarial inputs in tests/test_crewai.py.
_REDACT_KEY_RE = re.compile(
    r"(?i)(?:^|[_\-\.])"
    r"(password|passwd|secret|token|api[_\-]?key|authorization|auth)"
    r"(?:$|[_\-\.])"
)
_REDACTED_PLACEHOLDER = "***REDACTED***"


def _redact_args(args: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy of ``args`` with secret-ish values masked.

    Matches on the KEY (word-bounded), not the value, so the check is
    cheap and predictable. Nested dicts are walked one level deep —
    deeper nesting gets a best-effort recursion.
    """
    redacted: Dict[str, Any] = {}
    for key, value in args.items():
        if isinstance(key, str) and _is_sensitive_key(key):
            redacted[key] = _REDACTED_PLACEHOLDER
        elif isinstance(value, dict):
            redacted[key] = _redact_args(value)
        else:
            redacted[key] = value
    return redacted


def _is_sensitive_key(key: str) -> bool:
    # Normalise for the word-boundary check: wrap with dots so both
    # "password" at BOL/EOL and "x-api-key" in the middle match.
    probe = "." + key + "."
    return bool(_REDACT_KEY_RE.search(probe))


# ---------------------------------------------------------------------------
# Legacy schema helpers — kept for backward compatibility.
# New code should import from ``_pydantic_models`` directly.
# ---------------------------------------------------------------------------


def _schema_type(schema: Dict[str, Any]) -> Any:
    from ._pydantic_models import schema_to_type
    return schema_to_type(schema)


def _pydantic_model_from_schema(name: str, schema: Dict[str, Any]) -> Optional[Type[Any]]:
    from ._pydantic_models import build_model
    return build_model(name, schema)


# ---------------------------------------------------------------------------
# Tool factory
# ---------------------------------------------------------------------------


def build_crewai_tools(
    client: McpStdioClient,
    tools: Optional[List[Dict[str, Any]]] = None,
    result_transform: Optional[Callable[[Dict[str, Any]], Any]] = None,
    *,
    retry_policy: Optional[RetryPolicy] = None,
    async_mode: bool = False,
    logger: Optional[logging.Logger] = None,
) -> List[Any]:
    """Build CrewAI tool instances from MCP tool definitions.

    Args:
      client: Live :class:`McpStdioClient` the generated tools will call.
      tools: Explicit tool list (dicts matching the MCP ``tools/list``
        response shape). When ``None`` the client is queried.
      result_transform: Optional post-processor applied to every
        successful tool result before returning.
      retry_policy: When set, each tool invocation is wrapped in
        :func:`retry_call` (sync) or :func:`retry_call_async` (async).
      async_mode: When ``True`` the generated tool class defines an
        ``_arun`` coroutine for CrewAI's async agents. A ``_run`` is
        still provided so synchronous flows keep working.
      logger: Optional logger; falls back to this module's logger when
        not supplied. Used by structured success/failure logs.

    The returned tool classes set ``__module__`` to
    ``cordum_agent_adapters.crewai`` so tracebacks and IDE navigation
    point at a stable location regardless of the dynamic class name.
    """
    base_tool = _load_base_tool()
    log = logger if logger is not None else globals()["logger"]
    tool_defs = tools or client.list_tools()
    built_tools: List[Any] = []

    for tool in tool_defs:
        name = tool.get("name", "")
        description = tool.get("description", "")
        input_schema = tool.get("inputSchema") or {"type": "object", "properties": {}}
        args_schema = _pydantic_model_from_schema(name, input_schema)

        sync_runner = _make_sync_runner(
            client=client,
            tool_name=name,
            retry_policy=retry_policy,
            result_transform=result_transform,
            log=log,
        )
        # Annotate the pydantic-v2 overridden fields so CrewAI BaseTool
        # (which now uses pydantic v2) doesn't reject the dynamic class
        # with "field defined on a base class was overridden by a
        # non-annotated attribute". Falls back silently under v1.
        annotations: Dict[str, Any] = {
            "name": str,
            "description": str,
        }
        attrs: Dict[str, Any] = {
            "__annotations__": annotations,
            "name": name,
            "description": description,
            "_run": sync_runner,
            "__doc__": description or f"Cordum-governed MCP tool: {name}",
            "__module__": "cordum_agent_adapters.crewai",
        }
        if async_mode:
            attrs["_arun"] = _make_async_runner(
                client=client,
                tool_name=name,
                retry_policy=retry_policy,
                result_transform=result_transform,
                log=log,
            )
        if args_schema is not None:
            annotations["args_schema"] = type
            attrs["args_schema"] = args_schema

        safe_class = re.sub(r"[^a-zA-Z0-9_]", "_", name or "CordumTool")
        tool_class = type(f"{safe_class}Tool", (base_tool,), attrs)
        built_tools.append(tool_class())

    return built_tools


def _make_sync_runner(
    *,
    client: McpStdioClient,
    tool_name: str,
    retry_policy: Optional[RetryPolicy],
    result_transform: Optional[Callable[[Dict[str, Any]], Any]],
    log: logging.Logger,
) -> Callable[..., Any]:
    """Return the ``_run`` implementation for one CrewAI tool."""
    def _run(self: Any, *args: Any, **kwargs: Any) -> Any:
        payload = _coerce_kwargs(args, kwargs)
        redacted = _redact_args(payload)
        started = time.monotonic()
        try:
            if retry_policy is not None:
                result = retry_call(
                    client.call_tool,
                    retry_policy,
                    tool_name,
                    payload,
                    tool_name=tool_name,
                )
            else:
                result = client.call_tool(tool_name, payload)
        except Exception as exc:  # noqa: BLE001 — wrap and re-raise with context
            elapsed_ms = int((time.monotonic() - started) * 1000)
            log.warning(
                "mcp tool call failed",
                extra={
                    "tool": tool_name,
                    "tool_args": redacted,
                    "elapsed_ms": elapsed_ms,
                    "error_class": type(exc).__name__,
                },
            )
            raise AdapterToolCallError(
                f"tool {tool_name!r} call failed",
                tool_name=tool_name,
                tool_args=redacted,
                cause=exc,
                elapsed_ms=elapsed_ms,
            ) from exc
        elapsed_ms = int((time.monotonic() - started) * 1000)
        log.info(
            "mcp tool call ok",
            extra={
                "tool": tool_name,
                "elapsed_ms": elapsed_ms,
            },
        )
        if result_transform:
            return result_transform(result)
        return result

    return _run


def _make_async_runner(
    *,
    client: McpStdioClient,
    tool_name: str,
    retry_policy: Optional[RetryPolicy],
    result_transform: Optional[Callable[[Dict[str, Any]], Any]],
    log: logging.Logger,
) -> Callable[..., Any]:
    """Return the ``_arun`` coroutine implementation."""
    async def _arun(self: Any, *args: Any, **kwargs: Any) -> Any:
        payload = _coerce_kwargs(args, kwargs)
        redacted = _redact_args(payload)
        started = time.monotonic()
        try:
            if retry_policy is not None:
                async def factory() -> Any:
                    return await client.call_tool_async(tool_name, payload)

                result = await retry_call_async(factory, retry_policy, tool_name=tool_name)
            else:
                result = await client.call_tool_async(tool_name, payload)
        except Exception as exc:  # noqa: BLE001
            elapsed_ms = int((time.monotonic() - started) * 1000)
            log.warning(
                "mcp tool call (async) failed",
                extra={
                    "tool": tool_name,
                    "tool_args": redacted,
                    "elapsed_ms": elapsed_ms,
                    "error_class": type(exc).__name__,
                },
            )
            raise AdapterToolCallError(
                f"tool {tool_name!r} call failed",
                tool_name=tool_name,
                tool_args=redacted,
                cause=exc,
                elapsed_ms=elapsed_ms,
            ) from exc
        elapsed_ms = int((time.monotonic() - started) * 1000)
        log.info(
            "mcp tool call (async) ok",
            extra={"tool": tool_name, "elapsed_ms": elapsed_ms},
        )
        if result_transform:
            return result_transform(result)
        return result

    return _arun


# ---------------------------------------------------------------------------
# Crew convenience helper
# ---------------------------------------------------------------------------


def _load_crewai() -> Any:
    """Return the ``crewai`` module or raise a clear ImportError.

    The message points operators straight at the optional extra so they
    don't have to dig through tracebacks to learn the install incantation.
    """
    try:
        import crewai
        return crewai
    except ImportError as exc:
        raise ImportError(
            "CrewAI is not installed. Install via "
            "`pip install cordum-adapters[crewai]`."
        ) from exc


def _require_field(config: Mapping[str, Any], field: str, context: str) -> Any:
    """Pull a required field from a config dict, raising AdapterSchemaError on miss."""
    if field not in config:
        raise AdapterSchemaError(
            f"{context} missing required field {field!r}",
            offending_key=field,
        )
    return config[field]


def build_crew(
    client: McpStdioClient,
    agents_config: List[Mapping[str, Any]],
    tasks_config: List[Mapping[str, Any]],
    *,
    retry_policy: Optional[RetryPolicy] = None,
    async_mode: bool = False,
    tools: Optional[List[Dict[str, Any]]] = None,
    result_transform: Optional[Callable[[Dict[str, Any]], Any]] = None,
) -> Any:
    """Build a fully-wired :class:`crewai.Crew` from declarative configs.

    ``agents_config`` entries expect keys ``role``, ``goal``, ``backstory``
    (all required). An optional ``allowed_tool_names`` list subsets the
    global tool pool for that agent — handy when one sub-agent shouldn't
    see destructive tools even though they're registered on the Crew.

    ``tasks_config`` entries expect ``description`` and ``expected_output``
    (both required) plus optional ``agent`` (role string, resolves to the
    Agent built above) and ``context`` (list of prior task descriptions).

    Config validation errors are raised as :class:`AdapterSchemaError` with
    ``offending_key`` pointing at the missing entry. Upstream callers can
    surface this to dashboards without parsing exception strings.

    Returns a :class:`crewai.Crew` instance that the caller kicks off via
    ``crew.kickoff()``. Process defaults to ``crewai.Process.sequential``;
    callers can set a custom process via ``crew.process = ...`` before
    kicking off.
    """
    crewai = _load_crewai()

    all_tools = build_crewai_tools(
        client,
        tools=tools,
        result_transform=result_transform,
        retry_policy=retry_policy,
        async_mode=async_mode,
    )
    tools_by_name: Dict[str, Any] = {t.name: t for t in all_tools}

    agents_by_role: Dict[str, Any] = {}
    for idx, cfg in enumerate(agents_config):
        if not isinstance(cfg, Mapping):
            raise AdapterSchemaError(
                f"agents_config[{idx}] must be a mapping, got {type(cfg).__name__}",
                offending_key=f"agents_config[{idx}]",
            )
        role = _require_field(cfg, "role", f"agents_config[{idx}]")
        goal = _require_field(cfg, "goal", f"agents_config[{idx}]")
        backstory = _require_field(cfg, "backstory", f"agents_config[{idx}]")
        allowed_names = cfg.get("allowed_tool_names")
        if allowed_names is None:
            agent_tools = list(all_tools)
        else:
            agent_tools = [tools_by_name[n] for n in allowed_names if n in tools_by_name]
            missing = [n for n in allowed_names if n not in tools_by_name]
            if missing:
                raise AdapterSchemaError(
                    f"agent {role!r}: allowed_tool_names references unknown tools: {missing!r}",
                    offending_key="allowed_tool_names",
                )
        agent_kwargs: Dict[str, Any] = {
            "role": role,
            "goal": goal,
            "backstory": backstory,
            "tools": agent_tools,
        }
        # Forward any non-reserved keys so callers can pass
        # llm=, verbose=, allow_delegation= etc.
        for key, value in cfg.items():
            if key not in ("role", "goal", "backstory", "allowed_tool_names", "tools"):
                agent_kwargs[key] = value
        agents_by_role[role] = crewai.Agent(**agent_kwargs)

    tasks: List[Any] = []
    for idx, cfg in enumerate(tasks_config):
        if not isinstance(cfg, Mapping):
            raise AdapterSchemaError(
                f"tasks_config[{idx}] must be a mapping, got {type(cfg).__name__}",
                offending_key=f"tasks_config[{idx}]",
            )
        description = _require_field(cfg, "description", f"tasks_config[{idx}]")
        expected = _require_field(cfg, "expected_output", f"tasks_config[{idx}]")
        task_kwargs: Dict[str, Any] = {
            "description": description,
            "expected_output": expected,
        }
        agent_role = cfg.get("agent")
        if agent_role is not None:
            if agent_role not in agents_by_role:
                raise AdapterSchemaError(
                    f"tasks_config[{idx}].agent {agent_role!r} not defined in agents_config",
                    offending_key="agent",
                )
            task_kwargs["agent"] = agents_by_role[agent_role]
        for key, value in cfg.items():
            if key not in ("description", "expected_output", "agent"):
                task_kwargs[key] = value
        tasks.append(crewai.Task(**task_kwargs))

    return crewai.Crew(agents=list(agents_by_role.values()), tasks=tasks)
