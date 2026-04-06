"""Cordum LangChain Guard — full CAP integration for LangChain agents.

Tool calls become real CAP jobs — policy-evaluated, scheduled,
worker-executed, and audited through the Cordum control plane.

Two adoption patterns:

    # Pattern A: Per-agent wrapping (granular control)
    from cordum_langchain_guard import CordumAgent
    cordum = CordumAgent("http://localhost:8081", api_key="...")
    safe_tools = cordum.govern(tools, risk_tags=["write"])

    # Pattern B: Global hook (zero per-agent changes)
    from cordum_langchain_guard import patch_langchain
    patch_langchain(gateway_url="http://localhost:8081", api_key="...")
"""

__version__ = "0.1.0"

from .agent import CordumAgent
from .audit import AuditLogger
from .gateway import (
    ApprovalRequiredError,
    AsyncGatewayClient,
    GatewayClient,
    GatewayError,
    JobDeniedError,
    JobResult,
)
from .patch import patch_langchain, unpatch_langchain
from .worker import InProcessWorker, ToolRegistry, create_remote_worker

__all__ = [
    "ApprovalRequiredError",
    "AsyncGatewayClient",
    "AuditLogger",
    "CordumAgent",
    "GatewayClient",
    "GatewayError",
    "InProcessWorker",
    "JobDeniedError",
    "JobResult",
    "ToolRegistry",
    "create_remote_worker",
    "patch_langchain",
    "unpatch_langchain",
]
