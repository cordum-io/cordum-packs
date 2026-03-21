"""Governance wrappers for LangChain tools — routes every tool call through CAP Safety Kernel."""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("cordum.sidecar.langchain.governance")


def wrap_tools_with_governance(
    tool_configs: list[dict[str, Any]],
    callback_url: str,
    timeout_seconds: float = 30.0,
) -> list[Any]:
    """Wrap tool configs into GovernedLangChainTool instances.

    Each tool call will be routed through the Go callback server → Cordum Gateway
    → Safety Kernel for policy evaluation before execution.

    If callback_url is empty, tools are created without governance (for testing or
    when governance is explicitly disabled).
    """
    from governance import GovernedLangChainTool  # sidecar-template governance module

    tools = []
    for tool_cfg in tool_configs:
        name = tool_cfg.get("name", "")
        description = tool_cfg.get("description", "")
        if not name:
            continue

        if callback_url:
            # Governed tool: every invocation routes through CAP
            tool = GovernedLangChainTool(
                name=name,
                description=description,
                callback_url=callback_url,
                timeout_seconds=timeout_seconds,
            )
            logger.info("created governed tool: %s (callback: %s)", name, callback_url)
        else:
            # Ungoverned fallback (governance disabled)
            from langchain_core.tools import Tool
            tool = Tool(
                name=name,
                description=description,
                func=lambda *a, _name=name, **kw: f"Tool {_name} executed (ungoverned)",
            )
            logger.warning("created UNGOVERNED tool: %s (no callback_url)", name)

        tools.append(tool)

    return tools
