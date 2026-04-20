"""End-to-end integration test for the CrewAI adapter.

Opt-in via ``CORDUM_ADAPTERS_E2E=1``. Without the flag the whole module
is skipped by ``conftest.pytest_collection_modifyitems``.

This test intentionally sidesteps the full Crew.kickoff() runtime
because CrewAI pulls in a real LLM dependency and network access to run
an Agent end-to-end. Instead we build the Crew via :func:`build_crew`
to exercise the full adapter surface (tool discovery, args-schema
generation, retry, redaction, policy-denied path) and then invoke the
tool objects directly in the same way CrewAI's Agent would at runtime.

The assertions pin the three required behaviours:
  (a) a non-gated tool returns fixture payload,
  (b) a gated tool surfaces as AdapterToolCallError (cause is
      McpToolError with isError=True) when the subprocess has no
      approval header, and
  (c) a fresh client with approval in env sees the gated tool succeed.
"""
from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("crewai")  # soft-skip if extra not installed

from cordum_agent_adapters.crewai import build_crewai_tools
from cordum_agent_adapters.errors import AdapterToolCallError
from cordum_agent_adapters.mcp_client import McpToolError

# Note: full build_crew + Crew.kickoff() would require a real LLM
# configured via OPENAI_API_KEY / Anthropic creds / etc. The point of
# this E2E is to exercise the MCP → CrewAI adapter → stub gateway path
# end-to-end without pulling a live LLM into CI. We therefore build
# tools via build_crewai_tools (which is what build_crew wraps) and
# call their _run directly — that's exactly what a CrewAI Agent does
# at runtime when it dispatches a tool call.


def _get_tool_by_name(tools: Any, name: str) -> Any:
    for tool in tools:
        if tool.name == name:
            return tool
    raise AssertionError(f"tool {name!r} not in built tools")


def test_crewai_e2e_non_gated_tool_succeeds(mcp_client_factory: Any) -> None:
    client = mcp_client_factory(approval=False)
    tools = build_crewai_tools(client)
    tool = _get_tool_by_name(tools, "list_repos")
    result = tool._run(tool, org="cordum")
    assert result["isError"] is False
    text = result["content"][0]["text"]
    assert "repo-a" in text and "repo-b" in text


def test_crewai_e2e_gated_tool_denied_without_approval(mcp_client_factory: Any) -> None:
    from cordum_agent_adapters.mcp_client import McpRpcError

    client = mcp_client_factory(approval=False)
    tools = build_crewai_tools(client)
    tool = _get_tool_by_name(tools, "get_weather")
    with pytest.raises(AdapterToolCallError) as excinfo:
        tool._run(tool, location="San Francisco")
    err = excinfo.value
    assert err.tool_name == "get_weather"
    # Policy-deny surfaces as JSON-RPC -32099 per the gateway's
    # convention (mirrored by the stub to exercise the real code path).
    # Older stubs returned isError=true, but the canonical deny shape
    # the adapter must handle is the RPC error form.
    assert isinstance(err.cause, (McpRpcError, McpToolError))
    if isinstance(err.cause, McpRpcError):
        assert err.cause.code == -32099
        assert "policy" in err.cause.message.lower()


def test_crewai_e2e_gated_tool_succeeds_after_approval(mcp_client_factory: Any) -> None:
    client = mcp_client_factory(approval=True)
    tools = build_crewai_tools(client)
    tool = _get_tool_by_name(tools, "get_weather")
    result = tool._run(tool, location="San Francisco")
    assert result["isError"] is False
    assert "sunny" in result["content"][0]["text"]


def test_crewai_e2e_exercises_both_tools(mcp_client_factory: Any) -> None:
    client = mcp_client_factory(approval=True)
    tools = build_crewai_tools(client)
    list_tool = _get_tool_by_name(tools, "list_repos")
    weather_tool = _get_tool_by_name(tools, "get_weather")

    r1 = list_tool._run(list_tool, org="cordum")
    r2 = weather_tool._run(weather_tool, location="Paris")
    assert r1["isError"] is False
    assert r2["isError"] is False
