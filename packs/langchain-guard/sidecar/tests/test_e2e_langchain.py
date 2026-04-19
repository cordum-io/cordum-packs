"""End-to-end test: Real LangChain agent with Cordum governance.

Run with: pytest tests/test_e2e_langchain.py -v -s
Requires: Cordum running on https://127.0.0.1:8081 with langchain-guard pack installed
"""

import os
import httpx
import pytest
from langchain_core.tools import BaseTool, ToolException

GATEWAY_URL = os.environ.get("CORDUM_GATEWAY_URL", "https://127.0.0.1:8081")
API_KEY = os.environ.get(
    "CORDUM_API_KEY",
    "3f52861812d3584dcfa9b42dcd64fdefe7c00136865da8a6dba1438256a0dcfa",
)


def _gateway_reachable():
    try:
        r = httpx.get(
            f"{GATEWAY_URL}/api/v1/health",
            headers={"X-API-Key": API_KEY},
            verify=False,
            timeout=3,
        )
        return r.status_code == 200
    except Exception:
        return False


skipif_no_gateway = pytest.mark.skipif(
    not _gateway_reachable(),
    reason="Cordum gateway not reachable",
)


# --- Real LangChain tools ---

class SearchTool(BaseTool):
    name: str = "web_search"
    description: str = "Search the web for information"

    def _run(self, query: str) -> str:
        return f"Search results for '{query}': Python is a programming language created by Guido van Rossum."


class CalculatorTool(BaseTool):
    name: str = "calculator"
    description: str = "Perform math calculations"

    def _run(self, expression: str) -> str:
        try:
            result = eval(expression)  # safe in test context
            return f"Result: {result}"
        except Exception as e:
            return f"Error: {e}"


class FileWriteTool(BaseTool):
    name: str = "file_write"
    description: str = "Write content to a file"

    def _run(self, content: str) -> str:
        return f"Would write: {content}"


class DeleteDatabaseTool(BaseTool):
    name: str = "delete_database"
    description: str = "Delete the entire database"

    def _run(self, confirm: str) -> str:
        return "Database deleted"


# --- Tests ---

@skipif_no_gateway
def test_govern_read_tools():
    """Read-only tools should be accepted by Cordum (job submitted, enters PENDING)."""
    from cordum_langchain_guard import CordumAgent
    from cordum_langchain_guard.gateway import GatewayClient, GatewayError

    # Create agent with SSL verification disabled
    gw = GatewayClient.__new__(GatewayClient)
    gw._base_url = GATEWAY_URL
    gw._tenant_id = "default"
    gw._poll_interval = 0.5
    gw._poll_timeout = 10.0
    gw._client = httpx.Client(
        base_url=GATEWAY_URL,
        headers={"Content-Type": "application/json", "X-API-Key": API_KEY, "X-Tenant-ID": "default"},
        timeout=20.0,
        verify=False,
    )

    from cordum_langchain_guard.adapter import govern_tools
    tools = [SearchTool(), CalculatorTool()]
    governed = govern_tools(tools, gw, risk_tags=["read"])

    print(f"\n  Governed {len(governed)} read tools: {[t.name for t in governed]}")

    # Call the search tool - it will submit a job
    try:
        result = governed[0]._run("what is python")
        print(f"  Search result: {result}")
        # If we get here, a worker executed it (unlikely without one)
    except ToolException as e:
        err = str(e)
        print(f"  ToolException: {err}")
        # Expected: GATEWAY ERROR (timeout, no worker) - NOT BLOCKED
        assert "BLOCKED" not in err, f"Read tool should not be blocked: {err}"
        assert "GATEWAY ERROR" in err or "FAILED" in err

    gw.close()


@skipif_no_gateway
def test_govern_write_tools_approval():
    """Write tools should require approval (returns AWAITING APPROVAL to LLM)."""
    from cordum_langchain_guard.gateway import GatewayClient, ApprovalRequiredError, JobDeniedError

    gw = GatewayClient.__new__(GatewayClient)
    gw._base_url = GATEWAY_URL
    gw._tenant_id = "default"
    gw._poll_interval = 0.5
    gw._poll_timeout = 10.0
    gw._client = httpx.Client(
        base_url=GATEWAY_URL,
        headers={"Content-Type": "application/json", "X-API-Key": API_KEY, "X-Tenant-ID": "default"},
        timeout=20.0,
        verify=False,
    )

    from cordum_langchain_guard.adapter import govern_tools
    tools = [FileWriteTool()]
    governed = govern_tools(tools, gw, risk_tags=["write"])

    print(f"\n  Governed write tool: {governed[0].name}")

    result = governed[0]._run("hello world")
    print(f"  Result: {result}")
    # Should get AWAITING APPROVAL (not blocked, not executed)
    assert "[AWAITING APPROVAL]" in result, f"Expected approval message, got: {result}"
    print("  PASS: Write tool correctly returned AWAITING APPROVAL")

    gw.close()


@skipif_no_gateway
def test_govern_destructive_tools_denied():
    """Destructive tools should be blocked by policy."""
    from cordum_langchain_guard.gateway import GatewayClient

    gw = GatewayClient.__new__(GatewayClient)
    gw._base_url = GATEWAY_URL
    gw._tenant_id = "default"
    gw._poll_interval = 0.5
    gw._poll_timeout = 10.0
    gw._client = httpx.Client(
        base_url=GATEWAY_URL,
        headers={"Content-Type": "application/json", "X-API-Key": API_KEY, "X-Tenant-ID": "default"},
        timeout=20.0,
        verify=False,
    )

    from cordum_langchain_guard.adapter import govern_tools
    tools = [DeleteDatabaseTool()]
    governed = govern_tools(tools, gw, risk_tags=["destructive"])

    print(f"\n  Governed destructive tool: {governed[0].name}")

    with pytest.raises(ToolException) as exc_info:
        governed[0]._run("yes delete everything")

    err = str(exc_info.value)
    print(f"  ToolException: {err}")
    assert "BLOCKED" in err, f"Expected BLOCKED, got: {err}"
    print("  PASS: Destructive tool correctly BLOCKED")

    gw.close()


@skipif_no_gateway
def test_mixed_risk_agent():
    """An agent with mixed risk tools: read=allow, write=approve, destructive=deny."""
    from cordum_langchain_guard import CordumAgent
    from cordum_langchain_guard.gateway import GatewayClient, GatewayError, AsyncGatewayClient

    # Build a CordumAgent manually with SSL disabled
    agent = CordumAgent.__new__(CordumAgent)
    agent._gateway_url = GATEWAY_URL
    agent._api_key = API_KEY
    agent._tenant_id = "default"

    from cordum_langchain_guard.worker import ToolRegistry
    agent._registry = ToolRegistry()
    agent._worker = None

    headers = {"Content-Type": "application/json", "X-API-Key": API_KEY, "X-Tenant-ID": "default"}

    gw = GatewayClient.__new__(GatewayClient)
    gw._base_url = GATEWAY_URL
    gw._tenant_id = "default"
    gw._poll_interval = 0.5
    gw._poll_timeout = 10.0
    gw._client = httpx.Client(base_url=GATEWAY_URL, headers=headers, timeout=20.0, verify=False)
    agent._gateway = gw

    agw = AsyncGatewayClient.__new__(AsyncGatewayClient)
    agw._base_url = GATEWAY_URL
    agw._tenant_id = "default"
    agw._poll_interval = 0.5
    agw._poll_timeout = 10.0
    agw._client = httpx.AsyncClient(base_url=GATEWAY_URL, headers=headers, timeout=20.0, verify=False)
    agent._async_gateway = agw

    # Govern tools with different risk levels
    read_tools = agent.govern([SearchTool(), CalculatorTool()], risk_tags=["read"], start_worker=False)
    write_tools = agent.govern([FileWriteTool()], risk_tags=["write"], start_worker=False)
    destructive_tools = agent.govern([DeleteDatabaseTool()], risk_tags=["destructive"], start_worker=False)

    all_tools = read_tools + write_tools + destructive_tools
    print(f"\n  Agent has {len(all_tools)} tools:")
    for t in all_tools:
        print(f"    - {t.name}")

    # Test each risk level
    print("\n  Testing read tool (search)...")
    try:
        result = read_tools[0]._run("test")
        print(f"    Result: {result[:80]}")
    except ToolException as e:
        err = str(e)
        assert "BLOCKED" not in err, f"Read should not be blocked: {err}"
        print(f"    Expected timeout (no worker): {err[:80]}")

    print("\n  Testing write tool (file_write)...")
    result = write_tools[0]._run("test content")
    assert "[AWAITING APPROVAL]" in result
    print(f"    Result: {result[:80]}")

    print("\n  Testing destructive tool (delete_database)...")
    with pytest.raises(ToolException, match="BLOCKED"):
        destructive_tools[0]._run("confirm")
    print("    Correctly BLOCKED")

    print("\n  PASS: All three risk levels handled correctly")
    gw.close()


@skipif_no_gateway
def test_cordum_agent_govern_api():
    """Test the high-level CordumAgent.govern() API with real tools."""
    from cordum_langchain_guard import CordumAgent
    from cordum_langchain_guard.gateway import GatewayClient, AsyncGatewayClient

    # Manual construction with SSL disabled
    agent = CordumAgent.__new__(CordumAgent)
    agent._gateway_url = GATEWAY_URL
    agent._api_key = API_KEY
    agent._tenant_id = "default"

    from cordum_langchain_guard.worker import ToolRegistry
    agent._registry = ToolRegistry()
    agent._worker = None

    headers = {"Content-Type": "application/json", "X-API-Key": API_KEY, "X-Tenant-ID": "default"}

    gw = GatewayClient.__new__(GatewayClient)
    gw._base_url = GATEWAY_URL
    gw._tenant_id = "default"
    gw._poll_interval = 0.5
    gw._poll_timeout = 10.0
    gw._client = httpx.Client(base_url=GATEWAY_URL, headers=headers, timeout=20.0, verify=False)
    agent._gateway = gw

    agw = AsyncGatewayClient.__new__(AsyncGatewayClient)
    agw._base_url = GATEWAY_URL
    agw._tenant_id = "default"
    agw._poll_interval = 0.5
    agw._poll_timeout = 10.0
    agw._client = httpx.AsyncClient(base_url=GATEWAY_URL, headers=headers, timeout=20.0, verify=False)
    agent._async_gateway = agw

    tools = [SearchTool(), CalculatorTool(), FileWriteTool()]
    governed = agent.govern(tools, risk_tags=["read"], start_worker=False)

    print(f"\n  CordumAgent.govern() wrapped {len(governed)} tools")
    assert len(governed) == 3
    assert governed[0].name == "web_search"
    assert governed[1].name == "calculator"
    assert governed[2].name == "file_write"

    # Verify tools are actually governed (submit real job)
    try:
        governed[0]._run("test query")
    except ToolException as e:
        assert "BLOCKED" not in str(e)
        print(f"  Tool call went through governance pipeline (timeout expected): {str(e)[:60]}")

    print("  PASS: CordumAgent.govern() works with real Cordum")
    gw.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
