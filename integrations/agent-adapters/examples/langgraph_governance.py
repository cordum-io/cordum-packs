"""Checkpoint a governed tool call and observe its original job after approval.

No model provider is needed. Approval belongs to a separate Cordum operator;
LangGraph's resume value is only an acknowledgement of the pending request.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import time
from typing import Any, Callable, TypedDict
from urllib.parse import quote

import httpx
from cordum_agent_adapters.langchain import build_langchain_tools
from cordum_agent_adapters.mcp_client import McpStdioClient, McpToolError
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt


class State(TypedDict, total=False):
    tool: str
    arguments: dict[str, Any]
    request_digest: str
    job_id: str
    status: str
    result: Any


def _digest(tool: str, arguments: dict[str, Any]) -> str:
    payload = json.dumps([tool, arguments], sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def _payload(result: dict[str, Any]) -> dict[str, Any]:
    """Decode the JSON text content emitted by the packs MCP bridge."""
    content = result.get("content", [])
    if len(content) != 1 or content[0].get("type") != "text":
        raise ValueError("Expected one bridge JSON text result")
    value = json.loads(content[0]["text"])
    if not isinstance(value, dict):
        raise TypeError("Expected a bridge JSON object")
    return value


def build_graph(client: McpStdioClient, get_job: Callable[[str], dict[str, Any]]):
    """Return a compiled graph and the existing adapter's native BaseTools.

    Submit is a separate completed node: interrupt replay cannot resubmit it.
    The request digest is a demo application check, not a Cordum approval token.
    Checkpoints and resume values must remain within the trusted application.
    """
    tools = build_langchain_tools(client)
    by_name = {tool.name: tool for tool in tools}

    def submit(state: State):
        name, arguments = state["tool"], state["arguments"]
        if name not in by_name:
            raise ValueError(f"Unknown tool: {name}")
        digest = _digest(name, arguments)
        try:
            result = _payload(by_name[name].invoke(arguments))
        except McpToolError as exc:
            result = _payload(exc.result)
            if result.get("state") == "DENIED":
                return {"status": "denied", "result": result, "request_digest": digest}
            if result.get("state") == "APPROVAL_REQUIRED" and result.get("job_id"):
                return {"status": "approval_required", "job_id": result["job_id"],
                        "request_digest": digest}
            raise
        return {"status": "succeeded", "result": result, "request_digest": digest}

    def await_operator(state: State):
        pending = {"job_id": state["job_id"], "tool": state["tool"], "arguments": state["arguments"]}
        acknowledged = interrupt(pending)
        if (acknowledged != pending
                or _digest(state["tool"], state["arguments"]) != state["request_digest"]):
            return {"status": "rejected_input", "result": "Pending request changed; no new call submitted."}
        job = get_job(state["job_id"])
        if job.get("id") != state["job_id"]:
            raise ValueError("Gateway returned a different job")
        status = job.get("state")
        if status == "SUCCEEDED":
            return {"status": "succeeded", "result": job.get("result")}
        if status == "APPROVAL_REQUIRED":
            return {"status": "approval_required"}
        if status in {"DENIED", "FAILED", "CANCELLED", "TIMEOUT", "OUTPUT_QUARANTINED"}:
            return {"status": status.lower(), "result": job}
        raise ValueError(f"Job has not reached an observable outcome: {status}")

    def route(state: State):
        return "await_operator" if state["status"] == "approval_required" else END

    graph = StateGraph(State)
    graph.add_node("submit", submit)
    graph.add_node("await_operator", await_operator)
    graph.add_edge(START, "submit")
    graph.add_conditional_edges("submit", route)
    graph.add_conditional_edges("await_operator", route)
    return graph.compile(checkpointer=InMemorySaver()), tools


def read_job(gateway: httpx.Client, job_id: str, timeout: float = 30) -> dict[str, Any]:
    """Wait boundedly for completion, or return an outstanding approval gate."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge", required=True, help="Path to cordum-mcp-bridge executable")
    parser.add_argument("--gateway-url", default=os.environ.get("CORDUM_GATEWAY_URL"))
    parser.add_argument("--tool", default="cordum.workflow.run")
    parser.add_argument("--arguments", required=True, help="JSON object for the selected tool")
    parser.add_argument("--ca-file", help="CA for the Python observer; see bridge TLS limitation in tutorial")
    args = parser.parse_args()
    if not args.gateway_url or not os.environ.get("CORDUM_API_KEY"):
        parser.error("Set CORDUM_GATEWAY_URL and CORDUM_API_KEY for the disposable fixture")
    tls = ssl.create_default_context(cafile=args.ca_file) if args.ca_file else True
    env = dict(os.environ, CORDUM_GATEWAY_URL=args.gateway_url)
    headers = {"X-API-Key": env["CORDUM_API_KEY"], "X-Tenant-ID": env.get("CORDUM_TENANT_ID", "default")}
    with McpStdioClient([args.bridge], env=env, timeout=45) as client, httpx.Client(
        base_url=args.gateway_url, headers=headers, verify=tls, timeout=10, trust_env=False
    ) as gateway:
        app, _ = build_graph(client, lambda job_id: read_job(gateway, job_id))
        config = {"configurable": {"thread_id": "local-governance-demo"}}
        result = app.invoke({"tool": args.tool, "arguments": json.loads(args.arguments)}, config)
        while result.get("__interrupt__"):
            pending = result["__interrupt__"][0].value
            print(json.dumps(pending, indent=2))
            input("Approve or reject this job as a separate Cordum operator, then press Enter to observe it: ")
            result = app.invoke(Command(resume=pending), config)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
