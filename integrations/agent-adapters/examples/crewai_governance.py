"""Run a real CrewAI tool once, then observe its original Cordum job.

No model provider is used. A separate Cordum operator owns approval.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from typing import Any, Callable
from urllib.parse import quote

import httpx

from cordum_agent_adapters.crewai import build_crewai_tools
from cordum_agent_adapters.errors import AdapterToolCallError
from cordum_agent_adapters.mcp_client import McpStdioClient, McpToolError


def _payload(result: dict[str, Any]) -> dict[str, Any]:
    content = result.get("content", [])
    if len(content) != 1 or content[0].get("type") != "text":
        raise ValueError("Expected one bridge JSON text result")
    value = json.loads(content[0]["text"])
    if not isinstance(value, dict):
        raise ValueError("Expected a bridge JSON object")
    return value


def invoke_tool(tool: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    """Call the native BaseTool with validated keyword args, without retries."""
    try:
        result = _payload(tool.run(**arguments))
    except AdapterToolCallError as exc:
        # CrewAI's adapter preserves the MCP exception as its structured cause.
        # Transport errors and unexpected envelopes remain failures.
        if not isinstance(exc.cause, McpToolError):
            raise
        result = _payload(exc.cause.result)
        state = result.get("state")
        if state not in {"DENIED", "APPROVAL_REQUIRED"} or not result.get("job_id"):
            raise
        return {"status": "denied" if state == "DENIED" else "approval_required",
                "job_id": result["job_id"], "result": result}
    return {"status": "succeeded", "job_id": result.get("job_id"), "result": result}


def observe_original(pending: dict[str, Any], get_job: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    """Read the stored job; this function cannot approve or resubmit a tool."""
    if pending.get("status") != "approval_required" or not pending.get("job_id"):
        raise ValueError("Expected an outstanding approval job")
    job_id = pending["job_id"]
    job = get_job(job_id)
    if job.get("id") != job_id:
        raise ValueError("Gateway returned a different job")
    state = job.get("state")
    if state not in {"APPROVAL_REQUIRED", "SUCCEEDED", "DENIED", "FAILED", "CANCELLED", "TIMEOUT", "OUTPUT_QUARANTINED"}:
        raise ValueError(f"Job has not reached an observable outcome: {state}")
    return {"status": state.lower(), "job_id": job_id, "result": job.get("result")}


def read_job(gateway: httpx.Client, job_id: str, timeout: float = 30) -> dict[str, Any]:
    """Wait boundedly through queued/running states, preserving the job ID."""
    deadline = time.monotonic() + timeout
    while True:
        response = gateway.get(f"/api/v1/jobs/{quote(job_id, safe='')}")
        response.raise_for_status()
        job = response.json()
        if job.get("state") not in {"PENDING", "SCHEDULED", "DISPATCHED", "RUNNING", "RETRYING"}:
            return job
        if time.monotonic() >= deadline:
            raise TimeoutError("Original job did not complete before observation timeout")
        time.sleep(0.1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge", required=True)
    parser.add_argument("--tool", default="cordum.workflow.run")
    parser.add_argument("--arguments", required=True, help="JSON object for the selected tool")
    args = parser.parse_args()
    url, key = os.environ.get("CORDUM_GATEWAY_URL"), os.environ.get("CORDUM_API_KEY")
    if not url or not key:
        parser.error("Set CORDUM_GATEWAY_URL and CORDUM_API_KEY for the disposable fixture")
    arguments = json.loads(args.arguments)
    if not isinstance(arguments, dict):
        parser.error("--arguments must be a JSON object")
    headers = {"X-API-Key": key, "X-Tenant-ID": os.environ.get("CORDUM_TENANT_ID", "default")}
    with (McpStdioClient([args.bridge], env=dict(os.environ), timeout=45) as client,
          httpx.Client(base_url=url, headers=headers, timeout=10, trust_env=False) as gateway):
        tools = {tool.name: tool for tool in build_crewai_tools(client)}
        if args.tool not in tools:
            parser.error(f"Unknown tool: {args.tool}")
        result = invoke_tool(tools[args.tool], arguments)
        print(json.dumps(result, indent=2))
        pending = result
        while result["status"] == "approval_required":
            input("A separate operator must approve/reject this job in Cordum. Press Enter to observe it: ")
            result = observe_original(pending, lambda job: read_job(gateway, job))
            print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
