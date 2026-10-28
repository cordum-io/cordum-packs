"""Real LangGraph + native LangChain tools; fake only the Cordum transport.

The separate live test validates the control plane. These tests validate graph
checkpoint behavior without network services or a model provider.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import httpx
import pytest

pytest.importorskip("langgraph")
from cordum_agent_adapters.mcp_client import McpToolError
from langchain_core.tools import BaseTool
from langgraph.types import Command


@pytest.fixture
def demo():
    path = Path(__file__).parents[1] / "examples" / "langgraph_governance.py"
    assert path.is_file(), "The checkpointed LangGraph demo has not been implemented"
    spec = importlib.util.spec_from_file_location("langgraph_governance_demo", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Transport:
    """Small stand-in matching the real bridge's APPROVAL_REQUIRED envelope."""

    def __init__(self, decision):
        self.decision = decision
        self.calls = []
        self.executions = []
        self.reads = []
        self.job = {"id": "job-original", "state": "APPROVAL_REQUIRED"}

    def list_tools(self):
        return [{"name": "cordum.workflow.run", "description": "Start a run.",
                 "inputSchema": {"type": "object", "properties": {
                     "workflow_id": {"type": "string"}, "input": {"type": "object"}},
                     "required": ["workflow_id"]}}]

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if self.decision != "SUCCEEDED":
            raise McpToolError("tool call failed", {"isError": True, "content": [{
                "type": "text", "text": json.dumps({"job_id": "job-original",
                                                       "state": self.decision})}]})
        self.executions.append(arguments)
        return {"content": [{"type": "text", "text": json.dumps({
            "job_id": "job-original", "tool": name, "output": {"run_id": "run-safe"}})}]}

    def get_job(self, job_id):
        self.reads.append(job_id)
        return self.job


def request():
    return {"tool": "cordum.workflow.run", "arguments": {
        "workflow_id": "noop", "input": {"message": "hello"}}}


def test_allow_uses_native_tool(demo):
    transport = Transport("SUCCEEDED")
    app, tools = demo.build_graph(transport, transport.get_job)
    assert all(isinstance(tool, BaseTool) for tool in tools)
    result = app.invoke(request(), {"configurable": {"thread_id": "allow"}})
    assert result["status"] == "succeeded"
    assert result["result"] == {"job_id": "job-original", "tool": "cordum.workflow.run",
                                "output": {"run_id": "run-safe"}}
    assert len(transport.executions) == 1


def test_deny_never_executes(demo):
    transport = Transport("DENIED")
    app, _ = demo.build_graph(transport, transport.get_job)
    result = app.invoke(request(), {"configurable": {"thread_id": "deny"}})
    assert result["status"] == "denied"
    assert transport.executions == []
    assert "__interrupt__" not in result


def test_approval_resumes_original_job_without_resubmission(demo):
    transport = Transport("APPROVAL_REQUIRED")
    app, _ = demo.build_graph(transport, transport.get_job)
    config = {"configurable": {"thread_id": "approval"}}
    waiting = app.invoke(request(), config)
    assert waiting["__interrupt__"][0].value["job_id"] == "job-original"
    assert transport.executions == []
    # An independent operator approves in Cordum; the graph only reads state.
    transport.job = {"id": "job-original", "state": "SUCCEEDED", "result": {
        "job_id": "job-original", "tool": "cordum.workflow.run", "output": {"run_id": "run-safe"}}}
    result = app.invoke(Command(resume=waiting["__interrupt__"][0].value), config)
    assert result["status"] == "succeeded"
    assert result["result"] == {"job_id": "job-original", "tool": "cordum.workflow.run",
                                "output": {"run_id": "run-safe"}}
    assert len(transport.calls) == 1
    assert transport.reads == ["job-original"]


def test_resume_is_not_approval_authority(demo):
    transport = Transport("APPROVAL_REQUIRED")
    app, _ = demo.build_graph(transport, transport.get_job)
    config = {"configurable": {"thread_id": "unapproved"}}
    waiting = app.invoke(request(), config)
    result = app.invoke(Command(resume=waiting["__interrupt__"][0].value), config)
    assert result["status"] == "approval_required"
    assert result["__interrupt__"]
    assert len(transport.calls) == 1
    assert transport.executions == []


@pytest.mark.parametrize("mutation", ["arguments", "tool", "job_id", "state"])
def test_changed_inputs_are_rejected_by_application(demo, mutation):
    transport = Transport("APPROVAL_REQUIRED")
    app, _ = demo.build_graph(transport, transport.get_job)
    config = {"configurable": {"thread_id": "changed"}}
    waiting = app.invoke(request(), config)
    resume = dict(waiting["__interrupt__"][0].value)
    if mutation == "arguments":
        resume["arguments"] = {"workflow_id": "changed"}
    elif mutation == "state":
        app.update_state(config, {"arguments": {"workflow_id": "changed"}})
    else:
        resume[mutation] = "changed"
    result = app.invoke(Command(resume=resume), config)
    assert result["status"] == "rejected_input"
    assert len(transport.calls) == 1
    assert transport.reads == []


def test_unknown_tool_fails_closed(demo):
    transport = Transport("SUCCEEDED")
    app, _ = demo.build_graph(transport, transport.get_job)
    with pytest.raises(ValueError, match="Unknown tool"):
        app.invoke({"tool": "unknown", "arguments": {}}, {"configurable": {"thread_id": "unknown"}})
    assert transport.calls == []


def test_observer_waits_through_retrying(demo, monkeypatch):
    states = iter(["RETRYING", "SUCCEEDED"])
    requests = []

    def handle(request):
        requests.append(request.url.path)
        return httpx.Response(200, json={"id": "job-original", "state": next(states)})

    monkeypatch.setattr(demo.time, "sleep", lambda _: None)
    with httpx.Client(base_url="http://fixture.invalid", transport=httpx.MockTransport(handle)) as gateway:
        job = demo.read_job(gateway, "job-original")
    assert job["state"] == "SUCCEEDED"
    assert requests == ["/api/v1/jobs/job-original", "/api/v1/jobs/job-original"]
