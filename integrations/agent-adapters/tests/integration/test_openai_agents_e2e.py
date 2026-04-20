"""End-to-end integration test for the OpenAI Agents adapter.

Gated behind CORDUM_ADAPTERS_E2E=1 (conftest) so a normal ``pytest``
run skips it. Uses the stdio gateway stub at ``_gateway_stub.py`` —
the same fixture powering ``test_crewai_e2e.py`` and
``test_autogen_e2e.py``. The stub plays the role of a Cordum safety
kernel: every governed tool call is recorded into ``_GOVERNANCE_LOG``
with an explicit ``{tool, args, decision, reason}`` entry. The test
asserts on that log so the DoD item "Test verifies safety kernel
evaluation on tool calls" has a concrete witness, not just a match on
the formatted denial string the adapter produced.

Scenario:
1. Turn 1 — agent invokes ``list_repos``. Stub records
   ``decision=allow`` and returns success.
2. Turn 2 — agent invokes ``get_weather`` with no CORDUM_APPROVAL.
   Stub records ``decision=deny`` and returns the gateway's
   policy-deny isError response. The adapter translates the result
   to the ``[POLICY DENIED]`` sentinel string.
3. Turn 3 — agent emits a final message; no tool call fires.

Assertions walk (a) the streamed tool-call outputs, (b) the stub's
governance log (queried via the ``_test_governance_dump`` tool), and
(c) the logger's retained session_id.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, List

import pytest

pytest.importorskip("agents")

pytestmark = pytest.mark.integration


@pytest.fixture
def fake_model_factory():
    """Import the shared FakeModel lazily so collection doesn't crash
    on openai-agents version drift.
    """
    from ._fake_model import FakeModel, ScriptedTurn

    def make(turns: List[ScriptedTurn]) -> FakeModel:
        return FakeModel(turns)

    return make, ScriptedTurn


def _decode_dump_result(call_result) -> list:
    """Return the JSON payload from a _test_*_dump tool response."""
    content = call_result.get("content") if isinstance(call_result, dict) else None
    if not isinstance(content, list) or not content:
        return []
    text = content[0].get("text") if isinstance(content[0], dict) else None
    if not isinstance(text, str):
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return []


def test_openai_agents_e2e_governed_flow(mcp_client_factory, fake_model_factory) -> None:
    """Full governance flow: allow → deny → final message.

    Drives a REAL AG SDK Runner against a scripted Model + the stub
    gateway. The stub records every governed tool call, so the test
    asserts Cordum evaluated each call (not just that the adapter
    shaped the denial string).
    """
    from agents import Agent

    from cordum_agent_adapters.audit import CordumConversationLogger
    from cordum_agent_adapters.openai_agents import (
        build_openai_agent_tools,
        run_governed,
        tee_events,
    )

    make_model, ScriptedTurn = fake_model_factory

    with mcp_client_factory(approval=False) as client:
        tools = build_openai_agent_tools(client)
        model = make_model(
            [
                ScriptedTurn(tool_calls=[{"name": "list_repos", "arguments": {"org": "cordum"}}]),
                ScriptedTurn(
                    tool_calls=[{"name": "get_weather", "arguments": {"location": "sf"}}]
                ),
                ScriptedTurn(
                    content="I've listed repos and attempted weather. Policy blocked the weather lookup; please request approval to continue."
                ),
            ]
        )
        agent = Agent(
            name="e2e-tester",
            instructions="You operate Cordum.",
            tools=tools,
            model=model,
        )
        logger = CordumConversationLogger(client)

        async def _drive() -> List[Any]:
            result = await run_governed(
                agent, "run the demo", client=client, logger=logger
            )
            events: List[Any] = []
            async for ev in tee_events(result, logger):
                events.append(ev)
            return events

        events = asyncio.run(_drive())

        # Query the stub's governance log directly — proves safety-
        # kernel evaluation ran, not merely that the adapter shaped
        # the denial string from an MCP content block.
        governance = _decode_dump_result(client.call_tool("_test_governance_dump", {}))

    # --- Adapter layer: tool outputs surfaced correctly -------------
    outputs: List[str] = []
    for ev in events:
        item = getattr(ev, "item", None)
        if item is None:
            continue
        if getattr(item, "type", "") == "tool_call_output_item":
            out = getattr(item, "output", None)
            if isinstance(out, str):
                outputs.append(out)

    assert any("repo-a" in o or "repo-b" in o for o in outputs), outputs
    assert any(o.startswith("[POLICY DENIED]") or "policy denied" in o.lower() for o in outputs), outputs

    # --- Governance layer: safety kernel evaluated both calls -------
    tools_seen = [entry["tool"] for entry in governance]
    assert "list_repos" in tools_seen, governance
    assert "get_weather" in tools_seen, governance

    allow_entries = [e for e in governance if e["tool"] == "list_repos" and e["decision"] == "allow"]
    deny_entries = [e for e in governance if e["tool"] == "get_weather" and e["decision"] == "deny"]
    assert allow_entries, f"list_repos not recorded as allow: {governance}"
    assert deny_entries, f"get_weather not recorded as deny: {governance}"
    # Deny record carries a machine-readable reason — required for
    # downstream SIEM correlation + operator dashboards.
    assert deny_entries[0]["reason"] == "policy.approval_required", deny_entries

    # --- Audit layer: session_id persists across the governed run ---
    assert logger.session_id
