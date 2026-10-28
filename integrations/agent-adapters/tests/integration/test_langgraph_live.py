"""Real graph -> native tool -> stdio bridge -> real Cordum local stack.

Opt in with CORDUM_ADAPTERS_E2E=1, CORDUM_LANGGRAPH_FIXTURE=<runtime.json>,
CORDUM_MCP_BRIDGE=<built executable>. No cloud or model calls are made.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pytest

pytest.importorskip("langgraph")
redis = pytest.importorskip("redis")
from cordum_agent_adapters.mcp_client import McpStdioClient
from langgraph.types import Command
from test_langgraph_demo import demo as demo  # noqa: PLC0414 -- pytest fixture re-export

pytestmark = pytest.mark.integration


class FixtureConfig(dict):
    def __repr__(self):
        return "<disposable fixture configuration: credentials redacted>"


@pytest.fixture
def live(demo):
    runtime = os.environ.get("CORDUM_LANGGRAPH_FIXTURE")
    bridge = os.environ.get("CORDUM_MCP_BRIDGE")
    if not runtime or not bridge:
        pytest.skip("Start the disposable LangGraph fixture and set its paths")
    cfg = FixtureConfig(json.loads(Path(runtime).read_text(encoding="utf-8")))
    for endpoint in ("gateway_url", "nats_url", "redis_url"):
        assert urlparse(cfg[endpoint]).hostname == "127.0.0.1", "Use the disposable loopback fixture"
    env = {key: val for key, val in os.environ.items() if not key.startswith(("CORDUM_", "NATS_", "REDIS_"))}
    env.update(CORDUM_GATEWAY_URL=cfg["gateway_url"], CORDUM_API_KEY=cfg["requester_api_key"],
               CORDUM_TENANT_ID=cfg["tenant_id"], CORDUM_NATS_URL=cfg["nats_url"],
               CORDUM_REDIS_URL=cfg["redis_url"], CORDUM_MCP_POLL_INTERVAL="50ms",
               CORDUM_ENV="development", CORDUM_CAP_PROFILE="compat", CORDUM_MCP_ALLOW_UNSIGNED="true")
    headers = {"X-API-Key": cfg["requester_api_key"], "X-Tenant-ID": cfg["tenant_id"]}
    with (httpx.Client(base_url=cfg["gateway_url"], headers=headers, timeout=10, trust_env=False) as gateway,
          McpStdioClient([bridge], env=env, timeout=45) as client):
        yield cfg, client, gateway, demo


def approve(cfg, gateway, job_id):
    response = gateway.post(f"/api/v1/approvals/{job_id}/approve", json={"reason": "Harmless local tutorial fixture"},
                            headers={"X-API-Key": cfg["approver_api_key"]})
    assert response.status_code == 200, response.text


def job_states(cfg, job_id):
    """Inspect real scheduler/store transitions, including the absence of dispatch."""
    with redis.Redis.from_url(cfg["redis_url"], decode_responses=True,
                             socket_connect_timeout=5, socket_timeout=5) as store:
        records = store.lrange(f"job:events:{job_id}", 0, -1)
    return [json.loads(row)["state"] if row.startswith("{") else row.split("|", 1)[1] for row in records]


def test_real_allow(live):
    cfg, client, gateway, demo = live
    app, tools = demo.build_graph(client, lambda job: demo.read_job(gateway, job))
    assert {tool.name for tool in tools} >= {"cordum.workflow.run", "cordum.workflow.rerun"}
    result = app.invoke({"tool": "cordum.workflow.run", "arguments": {
        "workflow_id": cfg["workflow_id"], "input": {"name": "langgraph"}}},
        {"configurable": {"thread_id": "live-allow"}})
    assert result["status"] == "succeeded"
    payload = result["result"]
    if "result" in payload:
        payload = payload["result"]
    run_id = payload["output"]["run_id"]
    run = gateway.get(f"/api/v1/workflow-runs/{run_id}")
    run.raise_for_status()
    assert run.json()["status"] == "succeeded"
    assert run.json()["steps"]["echo"]["output"] == {"greeting": "Hello langgraph"}


def test_real_deny_prevents_dispatch(live):
    cfg, client, gateway, demo = live
    app, _ = demo.build_graph(client, lambda job: demo.read_job(gateway, job))
    result = app.invoke({"tool": "cordum.workflow.cancel", "arguments": {
        "workflow_id": cfg["workflow_id"], "run_id": cfg["source_run_id"]}},
        {"configurable": {"thread_id": "live-deny"}})
    assert result["status"] == "denied"
    job_id = result["result"]["job_id"]
    response = gateway.get(f"/api/v1/jobs/{job_id}")
    response.raise_for_status()
    job = response.json()
    assert job["state"] == "DENIED"
    assert job["safety_decision"].lower() == "deny"
    assert job["safety_rule_id"] == "langgraph-demo-deny-cancel"
    # Core persists a synthetic denial result; it is not a tool execution.
    assert job["result"]["status"] == "JOB_STATUS_DENIED"
    assert "output" not in job["result"]
    assert job["attempts"] == 0
    states = job_states(cfg, job_id)
    assert "DENIED" in states
    assert not set(states) & {"SCHEDULED", "DISPATCHED", "RUNNING", "SUCCEEDED"}


def test_real_operator_approval_then_same_job_resume(live, mocker):
    cfg, client, gateway, demo = live
    calls = mocker.spy(client, "call_tool")
    app, _ = demo.build_graph(client, lambda job: demo.read_job(gateway, job))
    config = {"configurable": {"thread_id": "live-approval"}}
    waiting = app.invoke({"tool": "cordum.workflow.rerun", "arguments": {
        "run_id": cfg["source_run_id"], "from_step": "echo"}}, config)
    pending = waiting["__interrupt__"][0].value
    before = gateway.get(f"/api/v1/jobs/{pending['job_id']}").json()
    assert before["state"] == "APPROVAL_REQUIRED"
    assert not before.get("result")
    states = job_states(cfg, pending["job_id"])
    assert "APPROVAL_REQUIRED" in states
    assert not set(states) & {"SCHEDULED", "DISPATCHED", "RUNNING", "SUCCEEDED"}
    # A graph resume cannot approve anything.
    still_waiting = app.invoke(Command(resume=pending), config)
    assert still_waiting["__interrupt__"]
    # Self-approval is rejected by the real gateway.
    refused = gateway.post(f"/api/v1/approvals/{pending['job_id']}/approve", json={"reason": "self"})
    assert refused.status_code == 403
    approve(cfg, gateway, pending["job_id"])
    result = app.invoke(Command(resume=pending), config)
    assert result["status"] == "succeeded"
    assert result["job_id"] == pending["job_id"]
    original = gateway.get(f"/api/v1/jobs/{pending['job_id']}").json()
    assert original["state"] == "SUCCEEDED"
    assert original["result"]["output"]["run_id"]
    assert calls.call_count == 1
    assert "SUCCEEDED" in job_states(cfg, pending["job_id"])


def test_real_changed_resume_arguments_rejected_by_application(live, mocker):
    cfg, client, gateway, demo = live
    calls = mocker.spy(client, "call_tool")
    app, _ = demo.build_graph(client, lambda job: demo.read_job(gateway, job))
    config = {"configurable": {"thread_id": "live-changed"}}
    waiting = app.invoke({"tool": "cordum.workflow.rerun", "arguments": {
        "run_id": cfg["source_run_id"], "from_step": "echo"}}, config)
    pending = waiting["__interrupt__"][0].value
    approve(cfg, gateway, pending["job_id"])
    # Cordum executes the stored original request; edits cannot become a new call.
    changed = copy.deepcopy(pending)
    changed["arguments"]["run_id"] = "different-input"
    result = app.invoke(Command(resume=changed), config)
    assert result["status"] == "rejected_input"
    assert result["job_id"] == pending["job_id"]
    original = demo.read_job(gateway, pending["job_id"])
    assert original["state"] == "SUCCEEDED"
    assert calls.call_count == 1
