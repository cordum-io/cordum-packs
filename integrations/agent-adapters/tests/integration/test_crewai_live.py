"""Native CrewAI tools -> PR418 MCP bridge -> real disposable current Core.

Opt in with CORDUM_ADAPTERS_E2E=1, CORDUM_CREWAI_FIXTURE=<runtime.json>,
CORDUM_MCP_BRIDGE=<executable>. No model, cloud, or external tools are used.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

import pytest

pytest.importorskip("crewai")
httpx = pytest.importorskip("httpx")
redis = pytest.importorskip("redis")
from crewai.tools import BaseTool

from cordum_agent_adapters.crewai import build_crewai_tools
from cordum_agent_adapters.mcp_client import McpStdioClient
from test_crewai_demo import crewai_demo as crewai_demo  # noqa: PLC0414

pytestmark = pytest.mark.integration


class FixtureConfig(dict):
    def __repr__(self):
        return "<disposable fixture configuration: credentials redacted>"


@pytest.fixture
def live_crewai(crewai_demo):
    runtime, bridge = os.environ.get("CORDUM_CREWAI_FIXTURE"), os.environ.get("CORDUM_MCP_BRIDGE")
    if not runtime or not bridge:
        pytest.skip("Start the disposable fixture and set its paths")
    cfg = FixtureConfig(json.loads(Path(runtime).read_text(encoding="utf-8")))
    for endpoint in ("gateway_url", "nats_url", "redis_url"):
        assert urlparse(cfg[endpoint]).hostname == "127.0.0.1", "Use the disposable loopback fixture"
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("CORDUM_", "NATS_", "REDIS_"))}
    env.update(CORDUM_GATEWAY_URL=cfg["gateway_url"], CORDUM_API_KEY=cfg["requester_api_key"],
               CORDUM_TENANT_ID=cfg["tenant_id"], CORDUM_NATS_URL=cfg["nats_url"],
               CORDUM_REDIS_URL=cfg["redis_url"], CORDUM_MCP_POLL_INTERVAL="50ms",
               CORDUM_ENV="development", CORDUM_CAP_PROFILE="compat", CORDUM_MCP_ALLOW_UNSIGNED="true")
    headers = {"X-API-Key": cfg["requester_api_key"], "X-Tenant-ID": cfg["tenant_id"]}
    with (httpx.Client(base_url=cfg["gateway_url"], headers=headers, timeout=10, trust_env=False) as gateway,
          McpStdioClient([bridge], env=env, timeout=45) as client):
        tools = {tool.name: tool for tool in build_crewai_tools(client)}
        assert all(isinstance(tool, BaseTool) for tool in tools.values())
        yield cfg, client, tools, gateway, crewai_demo


def job_states(cfg, job_id):
    with redis.Redis.from_url(cfg["redis_url"], decode_responses=True,
                             socket_connect_timeout=5, socket_timeout=5) as store:
        rows = store.lrange(f"job:events:{job_id}", 0, -1)
    return [json.loads(row)["state"] if row.startswith("{") else row.split("|", 1)[1] for row in rows]


def test_real_crewai_allow(live_crewai):
    cfg, _, tools, gateway, demo = live_crewai
    result = demo.invoke_tool(tools["cordum.workflow.run"], {
        "workflow_id": cfg["workflow_id"], "input": {"name": "CrewAI"}})
    assert result["status"] == "succeeded"
    payload = result["result"].get("result", result["result"])
    run_id = payload["output"]["run_id"]
    run = gateway.get(f"/api/v1/workflow-runs/{run_id}")
    run.raise_for_status()
    assert run.json()["steps"]["echo"]["output"] == {"greeting": "Hello CrewAI"}
    assert run.json()["status"] == "succeeded"
    print("CrewAI ALLOW: real native BaseTool; harmless transform returned Hello CrewAI")


def test_real_crewai_deny_prevents_dispatch(live_crewai):
    cfg, _, tools, gateway, demo = live_crewai
    result = demo.invoke_tool(tools["cordum.workflow.cancel"], {
        "workflow_id": cfg["workflow_id"], "run_id": cfg["source_run_id"]})
    assert result["status"] == "denied"
    response = gateway.get(f"/api/v1/jobs/{result['job_id']}")
    response.raise_for_status()
    job = response.json()
    assert job["state"] == "DENIED"
    assert job["safety_rule_id"] == "langgraph-demo-deny-cancel"
    assert job["attempts"] == 0
    assert job["result"]["status"] == "JOB_STATUS_DENIED"
    assert "output" not in job["result"]
    states = job_states(cfg, result["job_id"])
    assert "DENIED" in states
    assert not set(states) & {"SCHEDULED", "DISPATCHED", "RUNNING", "SUCCEEDED"}
    print(f"CrewAI DENY: job={result['job_id']} attempts=0 states={states}")


def test_real_crewai_approval_observes_same_job(live_crewai, mocker):
    cfg, client, tools, gateway, demo = live_crewai
    calls = mocker.spy(client, "call_tool")
    pending = demo.invoke_tool(tools["cordum.workflow.rerun"], {
        "run_id": cfg["source_run_id"], "from_step": "echo"})
    assert pending["status"] == "approval_required"
    job_id = pending["job_id"]
    before = gateway.get(f"/api/v1/jobs/{job_id}").json()
    assert before["state"] == "APPROVAL_REQUIRED"
    assert not before.get("result")
    states = job_states(cfg, job_id)
    assert "APPROVAL_REQUIRED" in states
    assert not set(states) & {"SCHEDULED", "DISPATCHED", "RUNNING", "SUCCEEDED"}
    still_pending = demo.observe_original(pending, lambda job: demo.read_job(gateway, job))
    assert still_pending["status"] == "approval_required"
    self_approval = gateway.post(f"/api/v1/approvals/{job_id}/approve", json={"reason": "self"})
    assert self_approval.status_code == 403
    approval = gateway.post(f"/api/v1/approvals/{job_id}/approve",
                            json={"reason": "Harmless local CrewAI demonstration"},
                            headers={"X-API-Key": cfg["approver_api_key"]})
    assert approval.status_code == 200
    result = demo.observe_original(pending, lambda job: demo.read_job(gateway, job))
    assert result["status"] == "succeeded"
    assert result["job_id"] == job_id
    assert result["result"]["output"]["run_id"]
    assert calls.call_count == 1
    print(f"CrewAI APPROVAL: job={job_id} self_approval=403 tool_calls=1 states={job_states(cfg, job_id)}")
