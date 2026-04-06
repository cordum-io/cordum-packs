"""Tests for CordumAgent — the main entry point."""

import pytest
import respx
from httpx import Response

GATEWAY_URL = "http://localhost:8081"


def _make_mock_tool(tool_name="search"):
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        pytest.skip("langchain-core not installed")

    class MockTool(BaseTool):
        name: str = "mock"
        description: str = "mock"

        def _run(self, query: str) -> str:
            return f"result for {query}"

    return MockTool(name=tool_name, description=f"Mock {tool_name} tool")


@respx.mock
def test_cordum_agent_govern():
    from cordum_langchain_guard import CordumAgent

    agent = CordumAgent(GATEWAY_URL, api_key="test")
    tools = [_make_mock_tool(tool_name="search"), _make_mock_tool(tool_name="write")]
    governed = agent.govern(tools, risk_tags=["read"])

    assert len(governed) == 2
    assert governed[0].name == "search"
    assert governed[1].name == "write"

    agent.close()


@respx.mock
def test_cordum_agent_govern_and_call():
    from cordum_langchain_guard import CordumAgent

    respx.post(f"{GATEWAY_URL}/api/v1/jobs").mock(
        return_value=Response(200, json={"job_id": "j-1", "trace_id": "t-1"})
    )
    respx.get(f"{GATEWAY_URL}/api/v1/jobs/j-1").mock(
        return_value=Response(200, json={
            "id": "j-1",
            "state": "SUCCEEDED",
            "result": "found it",
        })
    )

    with CordumAgent(GATEWAY_URL, api_key="test", poll_interval=0.01) as agent:
        governed = agent.govern([_make_mock_tool()], risk_tags=["read"])
        result = governed[0]._run("test query")
        assert result == "found it"


@respx.mock
def test_cordum_agent_context_manager():
    from cordum_langchain_guard import CordumAgent

    with CordumAgent(GATEWAY_URL) as agent:
        tools = agent.govern([_make_mock_tool()], risk_tags=["read"])
        assert len(tools) == 1
