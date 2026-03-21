from __future__ import annotations

import json
import logging
import os
import pathlib
import sys
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Sequence

from .governance import GovernedToolClient, ProgressReporter

try:
    from cordum_agent_adapters.crewai import build_crewai_tools
except ImportError:
    repo_root = pathlib.Path(__file__).resolve().parents[4]
    adapters_path = repo_root / "integrations" / "agent-adapters"
    if adapters_path.exists():
        sys.path.insert(0, str(adapters_path))
    from cordum_agent_adapters.crewai import build_crewai_tools


RuntimeLoader = Callable[[], SimpleNamespace]
ToolBuilder = Callable[..., list[Any]]

logger = logging.getLogger("cordum.sidecar.crewai")


@dataclass(slots=True)
class CrewAIExecutor:
    runtime_loader: RuntimeLoader | None = None
    tool_builder: ToolBuilder = build_crewai_tools

    def execute(
        self,
        *,
        action: str,
        config: dict[str, Any],
        payload: Any,
        callback_url: str,
    ) -> dict[str, Any]:
        runtime = (self.runtime_loader or load_crewai_runtime)()
        reporter = ProgressReporter(
            callback_url=callback_url,
            job_id=str(config.get("job_id", "")).strip(),
            trace_id=str(config.get("trace_id", "")).strip(),
        )

        if action == "crew.run":
            return self._run_crew(runtime, config=config, payload=payload, reporter=reporter, callback_url=callback_url)
        if action == "task.execute":
            return self._run_task(runtime, config=config, payload=payload, reporter=reporter, callback_url=callback_url)
        raise ValueError(f"unsupported action: {action}")

    def _run_crew(
        self,
        runtime: SimpleNamespace,
        *,
        config: Mapping[str, Any],
        payload: Any,
        reporter: ProgressReporter,
        callback_url: str,
    ) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ValueError("crew payload must be an object")
        crew_config = payload.get("crew_config")
        if not isinstance(crew_config, Mapping):
            raise ValueError("crew_config is required")

        agent_configs = self._require_list(crew_config.get("agents"), "crew_config.agents")
        task_configs = self._require_list(crew_config.get("tasks"), "crew_config.tasks")
        kickoff_inputs = normalize_inputs(payload.get("input"))
        total_tasks = len(task_configs)
        request_defaults = governance_request_defaults(config)
        _emit_progress(reporter, percent=2, message="starting crew execution", completed_tasks=0, total_tasks=total_tasks)

        tool_clients: list[GovernedToolClient] = []
        agents_by_role: dict[str, Any] = {}
        agents: list[Any] = []
        for agent_cfg in agent_configs:
            if not isinstance(agent_cfg, Mapping):
                raise ValueError("agent configuration must be an object")
            role = str(agent_cfg.get("role", "")).strip()
            goal = str(agent_cfg.get("goal", "")).strip()
            if not role or not goal:
                raise ValueError("agent role and goal are required")

            tools, governed_client = self._build_tools(
                tool_defs=agent_cfg.get("tools"),
                callback_url=callback_url,
                trace_id=str(config.get("trace_id", "")).strip(),
                request_defaults=request_defaults,
            )
            tool_clients.append(governed_client)
            llm = build_llm(runtime, agent_cfg.get("llm_config"))

            agent_kwargs = {
                "role": role,
                "goal": goal,
                "backstory": str(agent_cfg.get("backstory", "")),
                "tools": tools,
                "allow_delegation": bool(agent_cfg.get("allow_delegation", False)),
                "verbose": bool(agent_cfg.get("verbose", False)),
                "step_callback": self._step_callback(reporter, role, total_tasks),
            }
            if llm is not None:
                agent_kwargs["llm"] = llm

            agent = runtime.Agent(**agent_kwargs)
            agents.append(agent)
            agents_by_role[role] = agent

        task_records: list[tuple[Any, Mapping[str, Any]]] = []
        tasks: list[Any] = []
        for task_cfg in task_configs:
            if not isinstance(task_cfg, Mapping):
                raise ValueError("task configuration must be an object")
            role = str(task_cfg.get("agent_role", "")).strip()
            if role not in agents_by_role:
                raise ValueError(f"unknown task agent_role: {role}")

            description = render_text(str(task_cfg.get("description", "")), kickoff_inputs)
            if not description:
                raise ValueError("task description is required")
            expected_output = render_text(str(task_cfg.get("expected_output", "")), kickoff_inputs)
            description = append_context(description, task_cfg.get("context"))

            task_kwargs = {
                "description": description,
                "agent": agents_by_role[role],
                "expected_output": expected_output,
                "async_execution": bool(task_cfg.get("async_execution", False)),
            }
            filtered_tools = self._filter_task_tools(getattr(agents_by_role[role], "tools", []), task_cfg.get("tools"))
            if filtered_tools:
                task_kwargs["tools"] = filtered_tools
            task = runtime.Task(**task_kwargs)
            tasks.append(task)
            task_records.append((task, task_cfg))

        crew_kwargs: dict[str, Any] = {
            "agents": agents,
            "tasks": tasks,
            "process": resolve_process(runtime, crew_config.get("process")),
            "task_callback": self._task_callback(reporter, total_tasks),
        }
        manager_llm = build_llm(runtime, crew_config.get("manager_llm_config"))
        if manager_llm is not None and str(crew_config.get("process", "sequential")).strip().lower() == "hierarchical":
            crew_kwargs["manager_llm"] = manager_llm
        if int(config.get("max_rpm", 0) or 0) > 0:
            crew_kwargs["max_rpm"] = int(config.get("max_rpm", 0))

        crew = runtime.Crew(**crew_kwargs)
        result = crew.kickoff(inputs=kickoff_inputs)
        _emit_progress(
            reporter,
            percent=100,
            message="crew execution complete",
            completed_tasks=total_tasks,
            total_tasks=total_tasks,
        )

        task_outputs = collect_task_outputs(result, tasks)
        tool_calls = flatten_tool_calls(tool_clients)
        tokens_used = extract_tokens_used(result)

        return {
            "crew_output": serialize_value(getattr(result, "output", result)),
            "task_outputs": task_outputs,
            "tool_calls": tool_calls,
            "tokens_used": tokens_used,
            "result": serialize_value(result),
        }

    def _run_task(
        self,
        runtime: SimpleNamespace,
        *,
        config: Mapping[str, Any],
        payload: Any,
        reporter: ProgressReporter,
        callback_url: str,
    ) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ValueError("task payload must be an object")
        task_config = payload.get("task_config")
        if not isinstance(task_config, Mapping):
            raise ValueError("task_config is required")

        agent_config = task_config.get("agent_config")
        if not isinstance(agent_config, Mapping):
            raise ValueError("task_config.agent_config is required")

        inputs = normalize_inputs(payload.get("input"))
        context_items = payload.get("context")
        request_defaults = governance_request_defaults(config)
        _emit_progress(reporter, percent=5, message="starting task execution", completed_tasks=0, total_tasks=1)

        tool_defs = task_config.get("tools")
        if tool_defs in (None, [], ()):
            tool_defs = agent_config.get("tools")
        tools, governed_client = self._build_tools(
            tool_defs=tool_defs,
            callback_url=callback_url,
            trace_id=str(config.get("trace_id", "")).strip(),
            request_defaults=request_defaults,
        )
        llm = build_llm(runtime, agent_config.get("llm_config"))
        agent_kwargs = {
            "role": str(agent_config.get("role", "")).strip(),
            "goal": str(agent_config.get("goal", "")).strip(),
            "backstory": str(agent_config.get("backstory", "")),
            "tools": tools,
            "allow_delegation": bool(agent_config.get("allow_delegation", False)),
            "step_callback": self._step_callback(reporter, str(agent_config.get("role", "")).strip(), 1),
        }
        if llm is not None:
            agent_kwargs["llm"] = llm
        if not agent_kwargs["role"] or not agent_kwargs["goal"]:
            raise ValueError("task_config.agent_config.role and goal are required")
        agent = runtime.Agent(**agent_kwargs)

        description = render_text(str(task_config.get("description", "")), inputs)
        if not description:
            raise ValueError("task_config.description is required")
        description = append_context(description, context_items)
        expected_output = render_text(str(task_config.get("expected_output", "")), inputs)
        task = runtime.Task(
            description=description,
            expected_output=expected_output,
            agent=agent,
            tools=tools,
        )
        crew = runtime.Crew(
            agents=[agent],
            tasks=[task],
            process=resolve_process(runtime, "sequential"),
            task_callback=self._task_callback(reporter, 1),
        )
        result = crew.kickoff(inputs=inputs)
        _emit_progress(reporter, percent=100, message="task execution complete", completed_tasks=1, total_tasks=1)

        task_outputs = collect_task_outputs(result, [task])
        return {
            "crew_output": serialize_value(getattr(result, "output", result)),
            "task_outputs": task_outputs,
            "tool_calls": governed_client.records,
            "tokens_used": extract_tokens_used(result),
            "result": serialize_value(result),
        }

    def _build_tools(
        self,
        *,
        tool_defs: Any,
        callback_url: str,
        trace_id: str,
        request_defaults: Mapping[str, Any],
    ) -> tuple[list[Any], GovernedToolClient]:
        normalized_defs = normalize_tool_definitions(tool_defs)
        governed_client = GovernedToolClient(
            callback_url=callback_url,
            tools=normalized_defs,
            request_defaults=request_defaults,
            trace_id_factory=trace_id_factory(trace_id),
        )
        if not normalized_defs:
            return [], governed_client
        return self.tool_builder(governed_client, tools=normalized_defs), governed_client

    def _task_callback(self, reporter: ProgressReporter, total_tasks: int) -> Callable[..., None]:
        completed = {"count": 0}

        def _callback(*args: Any, **kwargs: Any) -> None:
            del args, kwargs
            completed["count"] += 1
            percent = 10 + int((completed["count"] / max(total_tasks, 1)) * 85)
            _emit_progress(
                reporter,
                percent=percent,
                message="task completed",
                completed_tasks=completed["count"],
                total_tasks=total_tasks,
            )

        return _callback

    def _step_callback(self, reporter: ProgressReporter, role: str, total_tasks: int) -> Callable[..., None]:
        def _callback(*args: Any, **kwargs: Any) -> None:
            del args, kwargs
            _emit_progress(
                reporter,
                percent=15,
                message="agent step executing",
                active_agent=role,
                completed_tasks=0,
                total_tasks=total_tasks,
            )

        return _callback

    @staticmethod
    def _require_list(value: Any, field: str) -> list[Any]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise ValueError(f"{field} must be an array")
        values = list(value)
        if not values:
            raise ValueError(f"{field} must not be empty")
        return values

    @staticmethod
    def _filter_task_tools(agent_tools: Any, requested_names: Any) -> list[Any]:
        if not requested_names:
            return [tool for tool in ensure_sequence(agent_tools)]
        requested = {str(name).strip() for name in ensure_sequence(requested_names) if str(name).strip()}
        return [tool for tool in ensure_sequence(agent_tools) if str(getattr(tool, "name", "")).strip() in requested]


def load_crewai_runtime() -> SimpleNamespace:
    try:
        from crewai import Agent, Crew, Process, Task
    except ImportError as exc:  # pragma: no cover - integration dependency
        raise RuntimeError("crewai is required for the CrewAI sidecar") from exc

    try:  # pragma: no cover - optional dependency
        from crewai import LLM
    except ImportError:
        LLM = None

    return SimpleNamespace(Agent=Agent, Crew=Crew, Process=Process, Task=Task, LLM=LLM)


def build_llm(runtime: SimpleNamespace, config: Any) -> Any:
    if not isinstance(config, Mapping):
        return None
    model = str(config.get("model", "")).strip()
    if not model:
        return None
    provider = str(config.get("provider", "")).strip()
    if provider and "/" not in model:
        model = f"{provider}/{model}"

    llm_class = getattr(runtime, "LLM", None)
    if llm_class is None:
        return model

    kwargs: dict[str, Any] = {"model": model}
    if config.get("temperature") is not None:
        kwargs["temperature"] = config.get("temperature")
    if config.get("base_url"):
        kwargs["base_url"] = config.get("base_url")
    if config.get("max_tokens"):
        kwargs["max_tokens"] = config.get("max_tokens")
    api_key_env = str(config.get("api_key_env", "")).strip()
    if api_key_env:
        api_key = os.getenv(api_key_env, "").strip()
        if api_key:
            kwargs["api_key"] = api_key
    try:
        return llm_class(**kwargs)
    except Exception:  # pragma: no cover - runtime-dependent fallback
        return model


def resolve_process(runtime: SimpleNamespace, process_value: Any) -> Any:
    process_name = str(process_value or "sequential").strip().lower()
    process = getattr(runtime, "Process", None)
    if process is None:
        return process_name
    return getattr(process, process_name, getattr(process, "sequential", process_name))


def normalize_inputs(payload: Any) -> dict[str, Any]:
    if isinstance(payload, Mapping):
        return dict(payload)
    if payload is None:
        return {}
    return {"input": payload}


def render_text(template: str, values: Mapping[str, Any]) -> str:
    template = template.strip()
    if not template:
        return ""

    class SafeDict(dict[str, Any]):
        def __missing__(self, key: str) -> str:
            return "{" + key + "}"

    try:
        return template.format_map(SafeDict(values))
    except Exception:
        return template


def append_context(description: str, context_items: Any) -> str:
    parts = [description.strip()]
    normalized = [serialize_value(item) for item in ensure_sequence(context_items)]
    normalized = [item for item in normalized if item not in ("", None, [], {})]
    if normalized:
        parts.append("Context:")
        parts.extend(json.dumps(item, ensure_ascii=False) if not isinstance(item, str) else item for item in normalized)
    return "\n".join(part for part in parts if part)


def collect_task_outputs(result: Any, fallback_tasks: Sequence[Any]) -> list[Any]:
    task_items = getattr(result, "tasks_output", None)
    if task_items is None:
        task_items = getattr(result, "task_outputs", None)
    if task_items is None:
        task_items = getattr(result, "tasks", None)
    if task_items is None:
        task_items = fallback_tasks
    outputs: list[Any] = []
    for task in ensure_sequence(task_items):
        output = getattr(task, "output", task)
        outputs.append(serialize_value(output))
    return outputs


def extract_tokens_used(result: Any) -> dict[str, int]:
    for attr in ("usage_metrics", "token_usage", "tokens_used", "usage"):
        value = getattr(result, attr, None)
        normalized = serialize_value(value)
        if isinstance(normalized, Mapping):
            output: dict[str, int] = {}
            for key, raw in normalized.items():
                if isinstance(raw, (int, float)):
                    output[str(key)] = int(raw)
            if output:
                return output
    return {}


def flatten_tool_calls(clients: Sequence[GovernedToolClient]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for client in clients:
        calls.extend(client.records)
    return calls


def serialize_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): serialize_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [serialize_value(item) for item in value]
    if hasattr(value, "model_dump") and callable(value.model_dump):
        return serialize_value(value.model_dump())
    if hasattr(value, "dict") and callable(value.dict):
        return serialize_value(value.dict())
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return serialize_value(value.to_dict())
    if hasattr(value, "__dict__"):
        return serialize_value(vars(value))
    return str(value)


def ensure_sequence(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return [value]


def trace_id_factory(trace_id: str) -> Callable[[], str]:
    trace_id = trace_id.strip()
    if trace_id:
        counter = {"value": 0}

        def _factory() -> str:
            counter["value"] += 1
            return f"{trace_id}-{counter['value']}"

        return _factory
    return lambda: os.urandom(8).hex()


def _emit_progress(reporter: ProgressReporter, **payload: Any) -> None:
    try:
        reporter.emit(**payload)
    except Exception as exc:  # pragma: no cover - defensive logging around telemetry path
        logger.warning("failed to emit CrewAI progress update: %s", exc)


def governance_request_defaults(config: Mapping[str, Any]) -> dict[str, Any]:
    defaults = {
        "topic": str(config.get("tool_topic") or "job.crewai.toolcall").strip(),
        "pack_id": str(config.get("pack_id") or "crewai").strip(),
        "tenant_id": str(config.get("tenant_id") or "").strip(),
        "principal_id": str(config.get("principal_id") or "").strip(),
        "actor_id": str(config.get("actor_id") or "").strip(),
        "actor_type": str(config.get("actor_type") or "").strip(),
    }
    return {key: value for key, value in defaults.items() if value}


def normalize_tool_definitions(tool_defs: Any) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in ensure_sequence(tool_defs):
        if not isinstance(item, Mapping):
            continue
        tool = dict(item)
        input_schema = tool.get("inputSchema")
        if input_schema is None and "input_schema" in tool:
            input_schema = tool.get("input_schema")
        if input_schema is not None:
            tool["inputSchema"] = input_schema
        if str(tool.get("name", "")).strip():
            normalized.append(tool)
    return normalized
