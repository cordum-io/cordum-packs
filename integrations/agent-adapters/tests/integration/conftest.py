"""pytest integration-test harness.

Hides these tests behind ``CORDUM_ADAPTERS_E2E=1`` so a normal ``pytest``
run stays fast. Separate fixtures configure a real subprocess-backed
MCP client pointed at the stub gateway.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from cordum_agent_adapters.mcp_client import McpStdioClient


E2E_FLAG = "CORDUM_ADAPTERS_E2E"


def pytest_collection_modifyitems(config: pytest.Config, items: list) -> None:
    """Skip every test in this package unless the E2E flag is set."""
    if os.environ.get(E2E_FLAG, "").lower() in ("1", "true", "yes"):
        return
    skip_marker = pytest.mark.skip(
        reason=f"set {E2E_FLAG}=1 to run integration tests"
    )
    for item in items:
        item.add_marker(skip_marker)


@pytest.fixture
def gateway_stub_command() -> list[str]:
    """Command that launches the stub MCP gateway subprocess."""
    stub_path = Path(__file__).parent / "_gateway_stub.py"
    return [sys.executable, str(stub_path)]


@pytest.fixture
def mcp_client_factory(gateway_stub_command: list[str]):
    """Factory for McpStdioClient bound to the stub gateway.

    Yields a callable ``make(approval=bool)`` that returns a fresh client
    with the subprocess env gated by ``CORDUM_APPROVAL``. Every client is
    closed on teardown so subprocesses are cleaned up even when a test
    raises.
    """
    opened: list[McpStdioClient] = []

    def make(*, approval: bool = False) -> McpStdioClient:
        env = os.environ.copy()
        if approval:
            env["CORDUM_APPROVAL"] = "yes"
        else:
            env.pop("CORDUM_APPROVAL", None)
        client = McpStdioClient(
            command=gateway_stub_command,
            env=env,
            timeout=10.0,
        )
        opened.append(client)
        return client

    yield make
    for c in opened:
        try:
            c.close()
        except Exception:  # noqa: BLE001
            pass
