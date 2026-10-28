"""Real CrewAI tool interface; only the Cordum transport is simulated here."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("crewai")
from crewai.tools import BaseTool

from cordum_agent_adapters.crewai import build_crewai_tools
from cordum_agent_adapters.errors import AdapterToolCallError
from cordum_agent_adapters.mcp_client import McpToolError


@pytest.fixture
def crewai_demo():
    path = Path(__file__).parents[1] / "examples" / "crewai_governance.py"
    assert path.is_file(), "The CrewAI governance example has not been implemented"
    spec = importlib.util.spec_from_file_location("crewai_governance_demo", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Transport:
    def __init__(self, state="SUCCEEDED"):
        self.state, self.calls = state, []

    def list_tools(self):
        return [{"name": "cordum.workflow.run", "description": "Harmless local workflow.",
                 "inputSchema": {"type": "object", "properties": {
                     "workflow_id": {"type": "string"}}, "required": ["workflow_id"]}}]

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        payload = {"job_id": "original-job", "state": self.state}
        if self.state == "SUCCEEDED":
            payload["output"] = {"run_id": "safe-run"}
        result = {"content": [{"type": "text", "text": json.dumps(payload)}]}
        if self.state != "SUCCEEDED":
            result["isError"] = True
            raise McpToolError("governance outcome", result)
        return result


def test_allow_runs_real_native_tool(crewai_demo):
    transport = Transport()
    tool = build_crewai_tools(transport)[0]
    assert isinstance(tool, BaseTool)
    outcome = crewai_demo.invoke_tool(tool, {"workflow_id": "local"})
    assert outcome["status"] == "succeeded"
    assert outcome["result"]["output"] == {"run_id": "safe-run"}
    assert transport.calls == [("cordum.workflow.run", {"workflow_id": "local"})]


@pytest.mark.parametrize("state,status", [("DENIED", "denied"), ("APPROVAL_REQUIRED", "approval_required")])
def test_decodes_wrapped_governance_outcomes(crewai_demo, state, status):
    transport = Transport(state)
    outcome = crewai_demo.invoke_tool(build_crewai_tools(transport)[0], {"workflow_id": "local"})
    assert outcome["status"] == status
    assert outcome["job_id"] == "original-job"
    assert len(transport.calls) == 1


def test_observe_requires_original_job_and_never_submits(crewai_demo):
    transport = Transport("APPROVAL_REQUIRED")
    pending = crewai_demo.invoke_tool(build_crewai_tools(transport)[0], {"workflow_id": "local"})
    reads = []
    def reader(job_id):
        reads.append(job_id)
        return {"id": job_id, "state": "SUCCEEDED", "result": {"output": {"run_id": "safe-run"}}}
    outcome = crewai_demo.observe_original(pending, reader)
    assert outcome["status"] == "succeeded"
    assert outcome["job_id"] == "original-job"
    assert reads == ["original-job"]
    assert len(transport.calls) == 1
    with pytest.raises(ValueError, match="different job"):
        crewai_demo.observe_original(pending, lambda _: {"id": "other", "state": "SUCCEEDED"})


def test_observation_does_not_approve(crewai_demo):
    pending = {"status": "approval_required", "job_id": "original-job"}
    outcome = crewai_demo.observe_original(pending, lambda job: {"id": job, "state": "APPROVAL_REQUIRED"})
    assert outcome["status"] == "approval_required"
    assert outcome["job_id"] == "original-job"


def test_keyword_arguments_use_crewai_validation(crewai_demo):
    transport = Transport()
    with pytest.raises(ValueError, match="arguments validation failed"):
        crewai_demo.invoke_tool(build_crewai_tools(transport)[0], {})
    assert transport.calls == []


def test_unrecognized_failure_is_not_a_governance_outcome(crewai_demo):
    transport = Transport("FAILED")
    with pytest.raises(AdapterToolCallError):
        crewai_demo.invoke_tool(build_crewai_tools(transport)[0], {"workflow_id": "local"})

