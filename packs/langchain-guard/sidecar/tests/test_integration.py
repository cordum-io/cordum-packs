"""Integration test — real Cordum gateway, real LangChain tools.

Run with: pytest tests/test_integration.py -v -s
Requires: Cordum running on https://127.0.0.1:8081
"""

import os
import pytest
from langchain_core.tools import BaseTool, ToolException

GATEWAY_URL = os.environ.get("CORDUM_GATEWAY_URL", "https://127.0.0.1:8081")
API_KEY = os.environ.get(
    "CORDUM_API_KEY",
    "3f52861812d3584dcfa9b42dcd64fdefe7c00136865da8a6dba1438256a0dcfa",
)


def _gateway_reachable():
    """Check if gateway is up."""
    try:
        import httpx
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


class EchoTool(BaseTool):
    name: str = "echo"
    description: str = "Echoes the input back"

    def _run(self, text: str) -> str:
        return f"Echo: {text}"


class DangerousTool(BaseTool):
    name: str = "delete_everything"
    description: str = "Deletes all data"

    def _run(self, confirm: str) -> str:
        return "Deleted everything"


# --- Test 1: Gateway client works with real Cordum ---

@skipif_no_gateway
def test_gateway_submit_real():
    """Submit a real job to the gateway and verify we get a job_id back."""
    import httpx

    # Need to disable SSL verification for self-signed certs
    from cordum_langchain_guard.gateway import GatewayClient, GatewayError

    # Create client with SSL verification disabled
    client = GatewayClient.__new__(GatewayClient)
    client._base_url = GATEWAY_URL
    client._tenant_id = "default"
    client._poll_interval = 0.5
    client._poll_timeout = 15.0

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
        "X-Tenant-ID": "default",
    }
    client._client = httpx.Client(
        base_url=GATEWAY_URL,
        headers=headers,
        timeout=20.0,
        verify=False,
    )

    try:
        job_id, trace_id = client.submit_job(
            topic="job.langchain-guard.tool",
            prompt="Integration test: echo tool",
            context={"tool_name": "echo", "tool_input": "hello world"},
            capability="echo",
            risk_tags=["read"],
        )
        print(f"\n  Submitted job: {job_id} (trace: {trace_id})")
        assert job_id, "Expected a job_id"
        assert len(job_id) > 0

        # Poll for result — with no worker running, job will stay PENDING
        # until poll_timeout. That's expected behavior.
        try:
            result = client.poll_until_terminal(job_id)
            print(f"  Job state: {result.state}")
            print(f"  Result: {result.result}")
            assert result.state in (
                "SUCCEEDED", "FAILED", "DENIED", "TIMEOUT",
                "APPROVAL_REQUIRED", "CANCELLED",
            ), f"Unexpected state: {result.state}"
        except GatewayError as e:
            # PENDING timeout is expected when no worker is running
            print(f"  Expected timeout (no worker): {e}")
            assert "PENDING" in str(e)

    finally:
        client.close()


# --- Test 2: CordumAgent.govern() with real gateway ---

@skipif_no_gateway
def test_cordum_agent_govern_real():
    """Wrap a tool with CordumAgent and call it against real Cordum."""
    import httpx
    from cordum_langchain_guard import CordumAgent
    from cordum_langchain_guard.gateway import GatewayClient, AsyncGatewayClient

    # Create agent with SSL verification disabled
    agent = CordumAgent.__new__(CordumAgent)
    agent._gateway_url = GATEWAY_URL
    agent._api_key = API_KEY
    agent._tenant_id = "default"
    agent._registry = __import__(
        "cordum_langchain_guard.worker", fromlist=["ToolRegistry"]
    ).ToolRegistry()
    agent._worker = None

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
        "X-Tenant-ID": "default",
    }

    gw = GatewayClient.__new__(GatewayClient)
    gw._base_url = GATEWAY_URL
    gw._tenant_id = "default"
    gw._poll_interval = 0.5
    gw._poll_timeout = 15.0
    gw._client = httpx.Client(
        base_url=GATEWAY_URL, headers=headers, timeout=20.0, verify=False,
    )
    agent._gateway = gw

    agw = AsyncGatewayClient.__new__(AsyncGatewayClient)
    agw._base_url = GATEWAY_URL
    agw._tenant_id = "default"
    agw._poll_interval = 0.5
    agw._poll_timeout = 15.0
    agw._client = httpx.AsyncClient(
        base_url=GATEWAY_URL, headers=headers, timeout=20.0, verify=False,
    )
    agent._async_gateway = agw

    try:
        echo = EchoTool()
        governed = agent.govern([echo], risk_tags=["read"], start_worker=False)

        assert len(governed) == 1
        assert governed[0].name == "echo"

        # Call the governed tool — this hits real Cordum
        print("\n  Calling governed echo tool...")
        try:
            result = governed[0]._run("hello from integration test")
            print(f"  Result: {result}")
        except ToolException as e:
            # FAILED or DENIED are expected (no worker running)
            print(f"  ToolException (expected): {e}")
            assert any(tag in str(e) for tag in ["BLOCKED", "FAILED", "GATEWAY ERROR"])

    finally:
        gw.close()


# --- Test 3: Verify DENY works with destructive risk tags ---

@skipif_no_gateway
def test_deny_with_destructive_tags():
    """Verify that destructive risk tags result in DENY from real Cordum."""
    import httpx
    from cordum_langchain_guard.gateway import GatewayClient, ApprovalRequiredError

    client = GatewayClient.__new__(GatewayClient)
    client._base_url = GATEWAY_URL
    client._tenant_id = "default"
    client._poll_interval = 0.5
    client._poll_timeout = 15.0

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
        "X-Tenant-ID": "default",
    }
    client._client = httpx.Client(
        base_url=GATEWAY_URL, headers=headers, timeout=20.0, verify=False,
    )

    try:
        from cordum_langchain_guard.gateway import JobDeniedError

        # Submit with destructive risk tag — should be denied by policy
        try:
            job_id, _ = client.submit_job(
                topic="job.langchain-guard.tool",
                prompt="Integration test: destructive",
                context={"tool_name": "delete_everything", "tool_input": "yes"},
                capability="delete_everything",
                risk_tags=["destructive"],
            )
            # If we get here, policy didn't block at submission
            print(f"\n  Submitted destructive job: {job_id}")
            result = client.poll_until_terminal(job_id)
            print(f"  State: {result.state}")
            assert result.is_denied, f"Expected DENIED, got {result.state}"
            print("  PASS: Destructive action correctly DENIED")

        except JobDeniedError as e:
            # Gateway denied at submission time (403) — this is correct!
            print(f"\n  PASS: Destructive action denied at submission: {e.reason}")

        except ApprovalRequiredError as e:
            print(f"\n  ApprovalRequired (unexpected for destructive): {e}")
            pytest.fail("Destructive should be DENIED, not REQUIRE_APPROVAL")

    finally:
        client.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
