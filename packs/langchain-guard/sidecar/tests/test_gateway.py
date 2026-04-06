"""Tests for the gateway HTTP client."""

import pytest
import respx
from httpx import Response

from cordum_langchain_guard.gateway import (
    ApprovalRequiredError,
    GatewayClient,
    GatewayError,
    JobResult,
)

GATEWAY_URL = "http://localhost:8081"


@respx.mock
def test_submit_job_success():
    route = respx.post(f"{GATEWAY_URL}/api/v1/jobs").mock(
        return_value=Response(200, json={"job_id": "j-1", "trace_id": "t-1"})
    )

    client = GatewayClient(GATEWAY_URL, api_key="test-key")
    job_id, trace_id = client.submit_job(
        topic="job.langchain-guard.tool",
        prompt="test",
        context={"tool_name": "search", "tool_input": "hello"},
        capability="search",
        risk_tags=["read"],
    )

    assert job_id == "j-1"
    assert trace_id == "t-1"
    assert route.called

    # Verify headers
    req = route.calls[0].request
    assert req.headers["X-API-Key"] == "test-key"
    assert req.headers["X-Tenant-ID"] == "default"


@respx.mock
def test_submit_job_approval_required():
    respx.post(f"{GATEWAY_URL}/api/v1/jobs").mock(
        return_value=Response(200, json={
            "job_id": "j-2",
            "status": "approval_required",
            "reason": "write action needs approval",
        })
    )

    client = GatewayClient(GATEWAY_URL)
    with pytest.raises(ApprovalRequiredError) as exc_info:
        client.submit_job(
            topic="job.langchain-guard.tool",
            prompt="test",
            capability="delete_file",
            risk_tags=["write"],
        )

    assert exc_info.value.job_id == "j-2"
    assert "approval" in exc_info.value.reason.lower()


@respx.mock
def test_get_job():
    respx.get(f"{GATEWAY_URL}/api/v1/jobs/j-3").mock(
        return_value=Response(200, json={
            "id": "j-3",
            "state": "SUCCEEDED",
            "result": {"output": "hello world"},
            "trace_id": "t-3",
        })
    )

    client = GatewayClient(GATEWAY_URL)
    result = client.get_job("j-3")

    assert result.job_id == "j-3"
    assert result.state == "SUCCEEDED"
    assert result.is_succeeded
    assert result.result == {"output": "hello world"}


@respx.mock
def test_get_job_denied():
    respx.get(f"{GATEWAY_URL}/api/v1/jobs/j-4").mock(
        return_value=Response(200, json={
            "id": "j-4",
            "state": "DENIED",
            "safety_reason": "destructive action blocked",
        })
    )

    client = GatewayClient(GATEWAY_URL)
    result = client.get_job("j-4")

    assert result.is_denied
    assert result.safety_reason == "destructive action blocked"


@respx.mock
def test_poll_until_terminal():
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            return Response(200, json={"id": "j-5", "state": "RUNNING"})
        return Response(200, json={
            "id": "j-5",
            "state": "SUCCEEDED",
            "result": "done",
        })

    respx.get(f"{GATEWAY_URL}/api/v1/jobs/j-5").mock(side_effect=side_effect)

    client = GatewayClient(GATEWAY_URL, poll_interval=0.01, poll_timeout=5.0)
    result = client.poll_until_terminal("j-5")

    assert result.is_succeeded
    assert result.result == "done"
    assert call_count == 3


@respx.mock
def test_poll_timeout():
    respx.get(f"{GATEWAY_URL}/api/v1/jobs/j-6").mock(
        return_value=Response(200, json={"id": "j-6", "state": "RUNNING"})
    )

    client = GatewayClient(GATEWAY_URL, poll_interval=0.01, poll_timeout=0.05)
    with pytest.raises(GatewayError, match="did not reach terminal state"):
        client.poll_until_terminal("j-6")


@respx.mock
def test_submit_and_wait():
    respx.post(f"{GATEWAY_URL}/api/v1/jobs").mock(
        return_value=Response(200, json={"job_id": "j-7", "trace_id": "t-7"})
    )
    respx.get(f"{GATEWAY_URL}/api/v1/jobs/j-7").mock(
        return_value=Response(200, json={
            "id": "j-7",
            "state": "SUCCEEDED",
            "result": {"output": "result"},
        })
    )

    client = GatewayClient(GATEWAY_URL, poll_interval=0.01)
    result = client.submit_and_wait(
        topic="job.langchain-guard.tool",
        prompt="test",
        capability="search",
    )

    assert result.is_succeeded
    assert result.result == {"output": "result"}


def test_job_result_states():
    assert JobResult("j", "SUCCEEDED").is_succeeded
    assert JobResult("j", "DENIED").is_denied
    assert JobResult("j", "FAILED").is_failed
    assert JobResult("j", "TIMEOUT").is_failed
    assert JobResult("j", "CANCELLED").is_failed
    assert JobResult("j", "APPROVAL_REQUIRED", approval_required=True).is_approval_required
