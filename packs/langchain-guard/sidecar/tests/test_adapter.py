"""Tests for the LangChain tool adapter."""

import pytest
import respx
from httpx import Response

from cordum_langchain_guard.gateway import GatewayClient


# Mock langchain_core before importing adapter
@pytest.fixture(autouse=True)
def mock_langchain():
    """Create mock LangChain classes for testing without langchain installed."""
    pass


def _make_mock_tool(tool_name="search", tool_desc="Search the web"):
    """Create a mock LangChain BaseTool."""
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        pytest.skip("langchain-core not installed")

    class MockTool(BaseTool):
        name: str = "mock"
        description: str = "mock"

        def _run(self, query: str) -> str:
            return f"result for {query}"

        async def _arun(self, query: str) -> str:
            return f"async result for {query}"

    return MockTool(name=tool_name, description=tool_desc)


GATEWAY_URL = "http://localhost:8081"


@respx.mock
def test_govern_tool_allow():
    from cordum_langchain_guard.adapter import govern_tool

    tool = _make_mock_tool()

    respx.post(f"{GATEWAY_URL}/api/v1/jobs").mock(
        return_value=Response(200, json={"job_id": "j-1", "trace_id": "t-1"})
    )
    respx.get(f"{GATEWAY_URL}/api/v1/jobs/j-1").mock(
        return_value=Response(200, json={
            "id": "j-1",
            "state": "SUCCEEDED",
            "result": "search results here",
        })
    )

    gw = GatewayClient(GATEWAY_URL, poll_interval=0.01)
    governed = govern_tool(tool, gw, risk_tags=["read"])

    result = governed._run("hello")
    assert result == "search results here"


@respx.mock
def test_govern_tool_denied():
    from cordum_langchain_guard.adapter import govern_tool

    try:
        from langchain_core.tools import ToolException
    except ImportError:
        pytest.skip("langchain-core not installed")

    tool = _make_mock_tool()

    respx.post(f"{GATEWAY_URL}/api/v1/jobs").mock(
        return_value=Response(200, json={"job_id": "j-2", "trace_id": "t-2"})
    )
    respx.get(f"{GATEWAY_URL}/api/v1/jobs/j-2").mock(
        return_value=Response(200, json={
            "id": "j-2",
            "state": "DENIED",
            "safety_reason": "destructive action blocked",
        })
    )

    gw = GatewayClient(GATEWAY_URL, poll_interval=0.01)
    governed = govern_tool(tool, gw, risk_tags=["destructive"])

    with pytest.raises(ToolException, match="BLOCKED"):
        governed._run("delete everything")


@respx.mock
def test_govern_tool_approval_required_immediate():
    """Test that APPROVAL_REQUIRED returns immediately to the LLM."""
    from cordum_langchain_guard.adapter import govern_tool

    tool = _make_mock_tool()

    respx.post(f"{GATEWAY_URL}/api/v1/jobs").mock(
        return_value=Response(200, json={
            "job_id": "j-3",
            "status": "approval_required",
            "reason": "write actions need approval",
        })
    )

    gw = GatewayClient(GATEWAY_URL, poll_interval=0.01)
    governed = govern_tool(tool, gw, risk_tags=["write"])

    result = governed._run("write something")
    assert "[AWAITING APPROVAL]" in result
    assert "j-3" in result


@respx.mock
def test_govern_tool_approval_required_via_poll():
    """Test APPROVAL_REQUIRED discovered during polling."""
    from cordum_langchain_guard.adapter import govern_tool

    tool = _make_mock_tool()

    respx.post(f"{GATEWAY_URL}/api/v1/jobs").mock(
        return_value=Response(200, json={"job_id": "j-4", "trace_id": "t-4"})
    )
    respx.get(f"{GATEWAY_URL}/api/v1/jobs/j-4").mock(
        return_value=Response(200, json={
            "id": "j-4",
            "state": "APPROVAL_REQUIRED",
            "approval_required": True,
            "approval_ref": "apr-123",
            "safety_reason": "requires human review",
        })
    )

    gw = GatewayClient(GATEWAY_URL, poll_interval=0.01)
    governed = govern_tool(tool, gw, risk_tags=["write"])

    result = governed._run("write something")
    assert "[AWAITING APPROVAL]" in result
    assert "apr-123" in result


@respx.mock
def test_govern_tool_failed():
    from cordum_langchain_guard.adapter import govern_tool

    try:
        from langchain_core.tools import ToolException
    except ImportError:
        pytest.skip("langchain-core not installed")

    tool = _make_mock_tool()

    respx.post(f"{GATEWAY_URL}/api/v1/jobs").mock(
        return_value=Response(200, json={"job_id": "j-5", "trace_id": "t-5"})
    )
    respx.get(f"{GATEWAY_URL}/api/v1/jobs/j-5").mock(
        return_value=Response(200, json={
            "id": "j-5",
            "state": "FAILED",
            "error_message": "worker crashed",
        })
    )

    gw = GatewayClient(GATEWAY_URL, poll_interval=0.01)
    governed = govern_tool(tool, gw)

    with pytest.raises(ToolException, match="FAILED"):
        governed._run("do something")


@respx.mock
def test_govern_tools_wraps_all():
    from cordum_langchain_guard.adapter import govern_tools

    tools = [_make_mock_tool(tool_name="tool1"), _make_mock_tool(tool_name="tool2")]

    gw = GatewayClient(GATEWAY_URL)
    governed = govern_tools(tools, gw, risk_tags=["read"])

    assert len(governed) == 2
    assert governed[0].name == "tool1"
    assert governed[1].name == "tool2"
