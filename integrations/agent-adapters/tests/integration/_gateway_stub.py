"""Minimal MCP-over-stdio gateway stub for integration tests.

Spawns as a subprocess that McpStdioClient connects to. Reads JSON-RPC
requests on stdin, writes responses on stdout — the same wire protocol a
real Cordum MCP bridge speaks.

Policy enforcement is intentionally simple: ``get_weather`` is denied
unless the caller has set ``CORDUM_APPROVAL=yes`` in the subprocess env.
This lets the E2E test exercise (a) successful governed calls, (b)
policy-denied calls, and (c) approval-then-retry without a full live
gateway.

Run standalone with::

    python -m tests.integration._gateway_stub

to debug the wire shape.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

# Fixture tools exposed by this stub. Keep shapes minimal — the adapter
# doesn't care about descriptions beyond echoing them into args_schema.
TOOLS: List[Dict[str, Any]] = [
    {
        "name": "list_repos",
        "description": "List repositories in the configured organisation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "org": {"type": "string", "description": "GitHub org slug"},
            },
        },
    },
    {
        "name": "get_weather",
        "description": "Fetch current weather for a location (policy-gated).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "location": {"type": "string"},
            },
            "required": ["location"],
        },
    },
    {
        # Mirrors the real cordum-mcp-bridge audit tool. The stub
        # records every payload into a process-local ring so the
        # integration test can assert that conversation turns landed
        # in the audit trail.
        "name": "cordum.audit.log_turn",
        "description": "Record a conversation turn in the Cordum audit trail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "turn": {"type": "object", "additionalProperties": True},
                "truncated": {"type": "boolean"},
            },
            "required": ["session_id", "turn"],
        },
    },
    {
        # Test-only tool: returns the stub's recorded turn buffer so the
        # E2E test can assert the agent landed the expected events. Not
        # present on the real bridge.
        "name": "_test_audit_dump",
        "description": "Return the stub's recorded audit turns (test only).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        # Test-only tool: returns the stub's safety-kernel decision log.
        # Each governed tool call records {tool, args, decision, reason}
        # here so the E2E can assert Cordum actually evaluated the call
        # (not just that the adapter formatted the denial text).
        "name": "_test_governance_dump",
        "description": "Return the stub's safety-kernel decision log (test only).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


# In-memory record of every cordum.audit.log_turn payload the stub
# received. The subprocess keeps this across the JSON-RPC loop's
# lifetime, which is the single test run; the test inspects via the
# _test_audit_dump tool.
_AUDIT_TURNS: List[Dict[str, Any]] = []

# Safety-kernel decision log — one entry per governed tool call. The
# stub acts as the safety kernel in-process: evaluates the policy
# (simple env-driven allow/deny), records the decision here, and
# returns the appropriate MCP content. Tests assert against this log
# to prove governance ran, not just that the denial *string* was
# produced by the adapter.
_GOVERNANCE_LOG: List[Dict[str, Any]] = []


def _record_decision(tool: str, args: Dict[str, Any], decision: str, reason: str) -> None:
    _GOVERNANCE_LOG.append(
        {
            "tool": tool,
            "args": args,
            "decision": decision,
            "reason": reason,
        }
    )


def _write(obj: Dict[str, Any]) -> None:
    line = json.dumps(obj, separators=(",", ":")) + "\n"
    sys.stdout.write(line)
    sys.stdout.flush()


def _rpc_ok(request_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _rpc_err(request_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


def _is_approved() -> bool:
    return os.environ.get("CORDUM_APPROVAL", "").lower() in ("yes", "true", "1")


def _handle_initialize(request_id: Any, _params: Dict[str, Any]) -> Dict[str, Any]:
    return _rpc_ok(
        request_id,
        {
            "protocolVersion": "2025-11-25",
            "serverInfo": {"name": "cordum-gateway-stub", "version": "0.0.1"},
            "capabilities": {"tools": {}},
        },
    )


def _handle_list_tools(request_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    # Cursor pagination: we return everything in one page.
    _ = params  # unused; reserved for pagination hook
    return _rpc_ok(request_id, {"tools": TOOLS})


def _handle_call_tool(request_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    name = params.get("name", "")
    args = params.get("arguments") or {}
    if name == "list_repos":
        org = args.get("org", "cordum")
        _record_decision(name, args, decision="allow", reason="tool on allow-list")
        return _rpc_ok(
            request_id,
            {
                "content": [{"type": "text", "text": f"repos for {org}: repo-a, repo-b"}],
                "isError": False,
            },
        )
    if name == "get_weather":
        if not _is_approved():
            _record_decision(
                name,
                args,
                decision="deny",
                reason="policy.approval_required",
            )
            # Return the real gateway's policy-deny convention: JSON-RPC
            # error with the reserved -32099 code. The adapter's
            # mcp_error_to_openai_agents_message maps this to the
            # [POLICY DENIED] sentinel prefix so the LLM can recognise
            # it on the next turn. An isError=true success body would
            # map to [TOOL ERROR] and lose the policy-deny classification.
            return _rpc_err(
                request_id,
                -32099,
                "policy denied: weather requires approval",
                {
                    "approval_id": "apr-test-weather",
                    "tool_name": "get_weather",
                    "reason": "policy.approval_required",
                    "tenant_id": "test-tenant",
                },
            )
        location = args.get("location", "unknown")
        _record_decision(name, args, decision="allow", reason="approval header present")
        return _rpc_ok(
            request_id,
            {
                "content": [{"type": "text", "text": f"weather at {location}: sunny"}],
                "isError": False,
            },
        )
    if name == "cordum.audit.log_turn":
        # Record the turn and return a bridge-shaped success envelope.
        # Real bridge does the same: body is a no-op because the
        # enclosing tools/call is already chained by the gateway.
        session_id = args.get("session_id", "")
        turn = args.get("turn") or {}
        if session_id and isinstance(turn, dict):
            _AUDIT_TURNS.append({"session_id": session_id, "turn": turn})
        return _rpc_ok(
            request_id,
            {
                "content": [{"type": "text", "text": "recorded"}],
                "isError": False,
            },
        )
    if name == "_test_audit_dump":
        # JSON-encode the recorded turns into a single text block so
        # the client sees the payload without needing a structured
        # content-block contract change.
        return _rpc_ok(
            request_id,
            {
                "content": [{"type": "text", "text": json.dumps(_AUDIT_TURNS)}],
                "isError": False,
            },
        )
    if name == "_test_governance_dump":
        return _rpc_ok(
            request_id,
            {
                "content": [{"type": "text", "text": json.dumps(_GOVERNANCE_LOG)}],
                "isError": False,
            },
        )
    return _rpc_err(request_id, -32601, f"unknown tool: {name}")


HANDLERS = {
    "initialize": _handle_initialize,
    "tools/list": _handle_list_tools,
    "tools/call": _handle_call_tool,
}


def _main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method", "")
        # Notifications (no id) are ignored; we just ack via silence.
        if "id" not in msg:
            continue
        handler = HANDLERS.get(method)
        if handler is None:
            _write(_rpc_err(msg["id"], -32601, f"method not found: {method}"))
            continue
        try:
            _write(handler(msg["id"], msg.get("params") or {}))
        except Exception as exc:  # noqa: BLE001
            _write(_rpc_err(msg["id"], -32603, f"stub error: {exc}"))


if __name__ == "__main__":
    _main()
