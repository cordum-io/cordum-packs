from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence


try:  # pragma: no cover - optional dependency
    from langchain_core.tools import BaseTool as LangChainBaseTool
except ImportError:  # pragma: no cover - optional dependency
    class LangChainBaseTool:  # type: ignore[no-redef]
        name: str = ""
        description: str = ""
        args_schema: Any = None

        def __init__(self, **kwargs: Any) -> None:
            for key, value in kwargs.items():
                setattr(self, key, value)


def _load_crewai_base_tool():
    try:  # pragma: no cover - optional dependency
        from crewai_tools import BaseTool

        return BaseTool
    except ImportError:
        pass
    try:  # pragma: no cover - optional dependency
        from crewai.tools import BaseTool

        return BaseTool
    except ImportError:  # pragma: no cover - optional dependency
        class FallbackCrewAITool:
            name: str = ""
            description: str = ""
            args_schema: Any = None

            def __init__(self, **kwargs: Any) -> None:
                for key, value in kwargs.items():
                    setattr(self, key, value)

        return FallbackCrewAITool


CrewAIBaseTool = _load_crewai_base_tool()


class GovernanceError(RuntimeError):
    """Base error raised for governance callback failures."""


class GovernanceDeniedError(GovernanceError):
    """Raised when Cordum denies a tool call."""


class GovernanceTimeoutError(GovernanceError):
    """Raised when the governance callback does not respond in time."""


@dataclass(slots=True)
class GovernanceResponse:
    approved: bool
    result: Any = None
    error: str = ""
    job_id: str = ""
    trace_id: str = ""
    status: str = ""


class GovernedTool:
    """Framework-agnostic governance helper."""

    def __init__(
        self,
        *,
        tool_name: str,
        callback_url: str,
        timeout_seconds: float = 30.0,
        trace_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.tool_name = tool_name.strip()
        if not self.tool_name:
            raise ValueError("tool_name is required")
        self.callback_url = _tool_call_url(callback_url)
        self.timeout_seconds = timeout_seconds
        self.trace_id_factory = trace_id_factory or (lambda: uuid.uuid4().hex)

    def invoke(self, arguments: Mapping[str, Any] | None = None, *, trace_id: str | None = None) -> Any:
        payload = {
            "tool_name": self.tool_name,
            "arguments": dict(arguments or {}),
            "trace_id": trace_id or self.trace_id_factory(),
        }
        response = self._post(payload)
        if response.approved:
            return response.result
        message = response.error or f"tool call denied with status {response.status or 'unknown'}"
        raise GovernanceDeniedError(message)

    def __call__(self, arguments: Mapping[str, Any] | None = None, *, trace_id: str | None = None) -> Any:
        return self.invoke(arguments, trace_id=trace_id)

    def _post(self, payload: Mapping[str, Any]) -> GovernanceResponse:
        request = urllib.request.Request(
            self.callback_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:  # #nosec B310 - callback_url is sidecar-local config.
                data = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise GovernanceError(f"governance callback failed with HTTP {exc.code}: {body}") from exc
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            raise GovernanceTimeoutError(f"governance callback timed out: {exc}") from exc

        try:
            decoded = json.loads(data)
        except json.JSONDecodeError as exc:
            raise GovernanceError(f"governance callback returned invalid JSON: {data}") from exc

        if not isinstance(decoded, Mapping):
            raise GovernanceError("governance callback returned a non-object payload")

        return GovernanceResponse(
            approved=bool(decoded.get("approved")),
            result=decoded.get("result"),
            error=str(decoded.get("error") or ""),
            job_id=str(decoded.get("job_id") or ""),
            trace_id=str(decoded.get("trace_id") or ""),
            status=str(decoded.get("status") or ""),
        )


class GovernedToolClient:
    """Adapter-compatible tool client that records governed CrewAI tool calls."""

    def __init__(
        self,
        *,
        callback_url: str,
        tools: Sequence[Mapping[str, Any]] | None = None,
        request_defaults: Mapping[str, Any] | None = None,
        trace_id_factory: Callable[[], str] | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.callback_url = callback_url
        self.tools = [dict(tool) for tool in (tools or [])]
        self.request_defaults = dict(request_defaults or {})
        self.trace_id_factory = trace_id_factory or (lambda: uuid.uuid4().hex)
        self.timeout_seconds = timeout_seconds
        self.records: list[dict[str, Any]] = []

    def list_tools(self) -> list[dict[str, Any]]:
        return [dict(tool) for tool in self.tools]

    def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None) -> Any:
        tool = GovernedTool(
            tool_name=name,
            callback_url=self.callback_url,
            timeout_seconds=self.timeout_seconds,
            trace_id_factory=self.trace_id_factory,
        )
        trace_id = self.trace_id_factory()
        payload = {
            **_clean_mapping(self.request_defaults),
            "tool_name": name,
            "arguments": dict(arguments or {}),
            "trace_id": trace_id,
        }
        response = tool._post(payload)
        record = {
            "tool_name": name,
            "arguments": dict(arguments or {}),
            "trace_id": response.trace_id or trace_id,
            "job_id": response.job_id,
            "status": response.status or ("succeeded" if response.approved else "denied"),
        }
        request_defaults = _clean_mapping(self.request_defaults)
        if request_defaults:
            record["request_defaults"] = request_defaults
        if not response.approved and response.error:
            record["error"] = response.error
        self.records.append(record)
        if response.approved:
            return response.result
        message = response.error or f"tool call denied with status {response.status or 'unknown'}"
        raise GovernanceDeniedError(message)


class ProgressReporter:
    """Posts execution progress updates back to the Go callback server."""

    def __init__(self, *, callback_url: str, job_id: str, trace_id: str = "", timeout_seconds: float = 10.0) -> None:
        self.callback_url = _progress_url(callback_url)
        self.job_id = job_id.strip()
        self.trace_id = trace_id.strip()
        self.timeout_seconds = timeout_seconds
        if not self.job_id:
            raise ValueError("job_id is required")

    def emit(
        self,
        *,
        percent: int,
        message: str,
        active_agent: str = "",
        completed_tasks: int = 0,
        total_tasks: int = 0,
        step_id: str = "",
    ) -> None:
        payload = {
            "job_id": self.job_id,
            "trace_id": self.trace_id,
            "step_id": step_id,
            "percent": max(0, min(100, int(percent))),
            "message": message,
            "active_agent": active_agent,
            "completed_tasks": completed_tasks,
            "total_tasks": total_tasks,
        }
        request = urllib.request.Request(
            self.callback_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds):  # #nosec B310 - callback_url is sidecar-local config.
                return
        except urllib.error.HTTPError as exc:  # pragma: no cover - network integration
            body = exc.read().decode("utf-8", errors="replace")
            raise GovernanceError(f"progress callback failed with HTTP {exc.code}: {body}") from exc
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:  # pragma: no cover - network integration
            raise GovernanceTimeoutError(f"progress callback timed out: {exc}") from exc


class GovernedLangChainTool(LangChainBaseTool):
    """LangChain BaseTool wrapper that routes execution through Cordum governance."""

    name: str
    description: str = ""
    args_schema: Any = None
    callback_url: str
    tool_name: str
    timeout_seconds: float = 30.0
    trace_id_factory: Callable[[], str] | None = None

    def __init__(
        self,
        *,
        name: str,
        callback_url: str,
        description: str = "",
        tool_name: str | None = None,
        args_schema: Any = None,
        timeout_seconds: float = 30.0,
        trace_id_factory: Callable[[], str] | None = None,
    ) -> None:
        super().__init__(
            name=name,
            description=description,
            callback_url=callback_url,
            tool_name=tool_name or name,
            args_schema=args_schema,
            timeout_seconds=timeout_seconds,
            trace_id_factory=trace_id_factory,
        )

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        tool = GovernedTool(
            tool_name=self.tool_name,
            callback_url=self.callback_url,
            timeout_seconds=self.timeout_seconds,
            trace_id_factory=self.trace_id_factory,
        )
        return tool.invoke(_coerce_arguments(args, kwargs))

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)


class GovernedCrewAITool(CrewAIBaseTool):
    """CrewAI BaseTool wrapper that routes execution through Cordum governance."""

    name: str = ""
    description: str = ""
    args_schema: Any = None
    callback_url: str = ""
    tool_name: str = ""
    timeout_seconds: float = 30.0
    trace_id_factory: Callable[[], str] | None = None

    def __init__(
        self,
        *,
        name: str,
        callback_url: str,
        description: str = "",
        tool_name: str | None = None,
        args_schema: Any = None,
        timeout_seconds: float = 30.0,
        trace_id_factory: Callable[[], str] | None = None,
    ) -> None:
        super().__init__(
            name=name,
            description=description,
            args_schema=args_schema,
            callback_url=callback_url,
            tool_name=tool_name or name,
            timeout_seconds=timeout_seconds,
            trace_id_factory=trace_id_factory,
        )

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        tool = GovernedTool(
            tool_name=self.tool_name,
            callback_url=self.callback_url,
            timeout_seconds=self.timeout_seconds,
            trace_id_factory=self.trace_id_factory,
        )
        return tool.invoke(_coerce_arguments(args, kwargs))


class GovernedAutoGenFunction:
    """Callable wrapper for AutoGen function maps."""

    def __init__(
        self,
        *,
        name: str,
        callback_url: str,
        description: str = "",
        parameter_schema: Mapping[str, Any] | None = None,
        timeout_seconds: float = 30.0,
        trace_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self.parameter_schema = dict(parameter_schema or {})
        self._tool = GovernedTool(
            tool_name=name,
            callback_url=callback_url,
            timeout_seconds=timeout_seconds,
            trace_id_factory=trace_id_factory,
        )

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._tool.invoke(_coerce_arguments(args, kwargs))

    def openai_function(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameter_schema or {"type": "object", "properties": {}},
        }


def _coerce_arguments(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> dict[str, Any]:
    if kwargs:
        return dict(kwargs)
    if not args:
        return {}
    if len(args) == 1:
        raw = args[0]
        if isinstance(raw, Mapping):
            return dict(raw)
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, Mapping):
                    return dict(parsed)
            except json.JSONDecodeError:
                return {"input": raw}
        return {"input": raw}
    return {"args": list(args)}


def _clean_mapping(values: Mapping[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if not str(key).strip():
            continue
        if value in (None, "", [], {}):
            continue
        cleaned[str(key)] = value
    return cleaned


def _tool_call_url(callback_url: str) -> str:
    stripped = callback_url.strip()
    if not stripped:
        raise ValueError("callback_url is required")
    parsed = urllib.parse.urlparse(stripped)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("callback_url must be an absolute URL")
    if parsed.path.endswith("/tool-call"):
        return stripped
    path = parsed.path.rstrip("/") + "/tool-call"
    return urllib.parse.urlunparse(parsed._replace(path=path))


def _progress_url(callback_url: str) -> str:
    stripped = callback_url.strip()
    if not stripped:
        raise ValueError("callback_url is required")
    parsed = urllib.parse.urlparse(stripped)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("callback_url must be an absolute URL")
    if parsed.path.endswith("/progress"):
        return stripped
    path = parsed.path.rstrip("/") + "/progress"
    return urllib.parse.urlunparse(parsed._replace(path=path))


__all__ = [
    "GovernanceDeniedError",
    "GovernanceError",
    "GovernanceResponse",
    "GovernanceTimeoutError",
    "GovernedAutoGenFunction",
    "GovernedCrewAITool",
    "GovernedLangChainTool",
    "GovernedToolClient",
    "GovernedTool",
    "ProgressReporter",
]
