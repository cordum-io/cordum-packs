from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch


_sidecar_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_integrations = os.path.normpath(os.path.join(_sidecar_root, "..", "..", "..", "integrations"))
for _path in (
    os.path.join(_integrations, "agent-adapters"),
    _sidecar_root,
):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import cordum_crewai_sidecar.executor as executor_module
from cordum_crewai_sidecar.executor import CrewAIExecutor


class FakeProgressReporter:
    instances: list["FakeProgressReporter"] = []

    def __init__(self, *, callback_url: str, job_id: str, trace_id: str = "", timeout_seconds: float = 10.0) -> None:
        self.callback_url = callback_url
        self.job_id = job_id
        self.trace_id = trace_id
        self.timeout_seconds = timeout_seconds
        self.emissions: list[dict[str, object]] = []
        self.__class__.instances.append(self)

    def emit(self, **payload: object) -> None:
        self.emissions.append(dict(payload))


class FakeGovernedToolClient:
    def __init__(
        self,
        *,
        callback_url: str,
        tools=None,
        request_defaults=None,
        trace_id_factory=None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.callback_url = callback_url
        self.tools = [dict(tool) for tool in (tools or [])]
        self.request_defaults = dict(request_defaults or {})
        self.trace_id_factory = trace_id_factory or (lambda: "trace-generated")
        self.timeout_seconds = timeout_seconds
        self.records: list[dict[str, object]] = []

    def list_tools(self) -> list[dict[str, object]]:
        return [dict(tool) for tool in self.tools]

    def call_tool(self, name: str, arguments=None) -> dict[str, object]:
        payload = dict(arguments or {})
        record = {
            "tool_name": name,
            "arguments": payload,
            "trace_id": self.trace_id_factory(),
            "status": "succeeded",
            "request_defaults": dict(self.request_defaults),
        }
        self.records.append(record)
        return {
            "tool_name": name,
            "arguments": payload,
            "request_defaults": dict(self.request_defaults),
        }


class FakeTool:
    def __init__(self, name: str, client: FakeGovernedToolClient) -> None:
        self.name = name
        self._client = client

    def _run(self, **kwargs: object) -> dict[str, object]:
        return self._client.call_tool(self.name, kwargs)


class FakeAgent:
    def __init__(self, **kwargs: object) -> None:
        self.role = kwargs["role"]
        self.goal = kwargs["goal"]
        self.backstory = kwargs.get("backstory", "")
        self.tools = list(kwargs.get("tools", []))
        self.allow_delegation = kwargs.get("allow_delegation", False)
        self.verbose = kwargs.get("verbose", False)
        self.step_callback = kwargs.get("step_callback")
        self.llm = kwargs.get("llm")


class FakeTask:
    def __init__(self, **kwargs: object) -> None:
        self.description = kwargs["description"]
        self.expected_output = kwargs.get("expected_output", "")
        self.agent = kwargs["agent"]
        self.tools = list(kwargs.get("tools", getattr(self.agent, "tools", [])))
        self.async_execution = kwargs.get("async_execution", False)
        self.output = None


class FakeCrew:
    last_init: dict[str, object] | None = None

    def __init__(self, **kwargs: object) -> None:
        self.__class__.last_init = dict(kwargs)
        self.agents = list(kwargs["agents"])
        self.tasks = list(kwargs["tasks"])
        self.process = kwargs["process"]
        self.task_callback = kwargs.get("task_callback")
        self.manager_llm = kwargs.get("manager_llm")
        self.max_rpm = kwargs.get("max_rpm")

    def kickoff(self, inputs: dict[str, object]) -> SimpleNamespace:
        for task in self.tasks:
            if callable(getattr(task.agent, "step_callback", None)):
                task.agent.step_callback(task=task)

            tool_results = []
            tool_input = inputs.get("query") or inputs.get("topic") or inputs.get("input") or ""
            for tool in task.tools or getattr(task.agent, "tools", []):
                tool_results.append(tool._run(query=tool_input))

            task.output = {
                "description": task.description,
                "expected_output": task.expected_output,
                "tool_results": tool_results,
            }
            if callable(self.task_callback):
                self.task_callback(task=task)

        return SimpleNamespace(
            output="crew complete" if len(self.tasks) > 1 else "task complete",
            tasks=self.tasks,
            usage_metrics={"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
        )


class FakeLLM:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = dict(kwargs)


def fake_runtime_loader() -> SimpleNamespace:
    return SimpleNamespace(
        Agent=FakeAgent,
        Crew=FakeCrew,
        Task=FakeTask,
        Process=SimpleNamespace(sequential="sequential", hierarchical="hierarchical"),
        LLM=FakeLLM,
    )


def fake_tool_builder(client: FakeGovernedToolClient, tools):
    fake_tool_builder.calls.append([dict(tool) for tool in tools])
    return [FakeTool(str(tool["name"]), client) for tool in tools]


fake_tool_builder.calls = []


class CrewAIExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeProgressReporter.instances.clear()
        FakeCrew.last_init = None
        fake_tool_builder.calls.clear()

    def test_unsupported_action_raises(self) -> None:
        executor = CrewAIExecutor(runtime_loader=fake_runtime_loader, tool_builder=fake_tool_builder)

        with self.assertRaises(ValueError) as ctx:
            executor.execute(
                action="crewai.unknown",
                config={"job_id": "job-1"},
                payload={},
                callback_url="http://127.0.0.1:9999",
            )

        self.assertIn("unsupported action", str(ctx.exception))

    def test_crew_run_reports_progress_and_governs_tools(self) -> None:
        executor = CrewAIExecutor(runtime_loader=fake_runtime_loader, tool_builder=fake_tool_builder)
        payload = {
            "crew_config": {
                "agents": [
                    {
                        "role": "Researcher",
                        "goal": "Find facts",
                        "tools": [
                            {
                                "name": "search",
                                "description": "Search for facts",
                                "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}},
                            }
                        ],
                    },
                    {
                        "role": "Writer",
                        "goal": "Write summary",
                    },
                ],
                "tasks": [
                    {"description": "Research {query}", "agent_role": "Researcher"},
                    {"description": "Write summary for {query}", "agent_role": "Writer"},
                ],
                "process": "hierarchical",
                "manager_llm_config": {"provider": "openai", "model": "gpt-4o-mini"},
            },
            "input": {"query": "Cordum"},
        }

        with (
            patch.object(executor_module, "ProgressReporter", FakeProgressReporter),
            patch.object(executor_module, "GovernedToolClient", FakeGovernedToolClient),
        ):
            result = executor.execute(
                action="crew.run",
                config={
                    "job_id": "job-crew",
                    "trace_id": "trace-crew",
                    "tenant_id": "tenant-123",
                    "principal_id": "principal-123",
                    "actor_id": "actor-123",
                    "actor_type": "human",
                    "tool_topic": "job.crewai.toolcall",
                    "pack_id": "crewai",
                    "max_rpm": 42,
                },
                payload=payload,
                callback_url="http://127.0.0.1:9999",
            )

        self.assertEqual("crew complete", result["crew_output"])
        self.assertEqual(2, len(result["task_outputs"]))
        self.assertEqual(1, len(result["tool_calls"]))
        self.assertEqual(12, result["tokens_used"]["total_tokens"])
        self.assertEqual("tenant-123", result["tool_calls"][0]["request_defaults"]["tenant_id"])
        self.assertEqual("job.crewai.toolcall", result["tool_calls"][0]["request_defaults"]["topic"])
        self.assertEqual(42, FakeCrew.last_init["max_rpm"])
        self.assertIsNotNone(FakeCrew.last_init["manager_llm"])
        self.assertEqual("object", fake_tool_builder.calls[0][0]["inputSchema"]["type"])

        emissions = FakeProgressReporter.instances[0].emissions
        self.assertEqual(2, emissions[0]["percent"])
        self.assertEqual(100, emissions[-1]["percent"])
        self.assertTrue(any(item.get("active_agent") == "Researcher" for item in emissions))

    def test_task_execute_uses_agent_tool_fallback_and_context(self) -> None:
        executor = CrewAIExecutor(runtime_loader=fake_runtime_loader, tool_builder=fake_tool_builder)
        payload = {
            "task_config": {
                "description": "Summarize {topic}",
                "expected_output": "A concise summary",
                "agent_config": {
                    "role": "Writer",
                    "goal": "Summarize findings",
                    "tools": [
                        {
                            "name": "search",
                            "description": "Search for context",
                            "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}},
                        }
                    ],
                },
            },
            "input": {"topic": "CrewAI governance"},
            "context": ["Prior note"],
        }

        with (
            patch.object(executor_module, "ProgressReporter", FakeProgressReporter),
            patch.object(executor_module, "GovernedToolClient", FakeGovernedToolClient),
        ):
            result = executor.execute(
                action="task.execute",
                config={
                    "job_id": "job-task",
                    "trace_id": "trace-task",
                    "tenant_id": "tenant-task",
                    "tool_topic": "job.crewai.toolcall",
                },
                payload=payload,
                callback_url="http://127.0.0.1:9999",
            )

        self.assertEqual("task complete", result["crew_output"])
        self.assertEqual(1, len(result["task_outputs"]))
        self.assertIn("Context:", result["task_outputs"][0]["description"])
        self.assertIn("Prior note", result["task_outputs"][0]["description"])
        self.assertEqual("search", result["tool_calls"][0]["tool_name"])
        self.assertEqual("tenant-task", result["tool_calls"][0]["request_defaults"]["tenant_id"])


if __name__ == "__main__":
    unittest.main()
