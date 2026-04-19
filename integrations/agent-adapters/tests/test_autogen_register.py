"""Tests for register_cordum_tools — classic + modern wiring + auto-detect."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from cordum_agent_adapters.autogen import (
    CordumAutoGenBinding,
    register_cordum_tools,
)


def _tool_defs():
    return [
        {"name": "echo", "description": "Echo", "inputSchema": {"type": "object"}},
        {"name": "ping", "description": "Ping", "inputSchema": {"type": "object"}},
    ]


# --- classic path -------------------------------------------------------


class _ClassicAgent:
    def __init__(self) -> None:
        self.registered: dict = {}
        self.reply_hooks: list = []

    def register_function(self, function_map: dict) -> None:
        self.registered = function_map

    def register_reply(self, trigger, fn) -> None:
        self.reply_hooks.append((trigger, fn))


def test_classic_auto_detect_registers_function_map():
    agent = _ClassicAgent()
    client = MagicMock()
    binding = register_cordum_tools(agent, client, tools=_tool_defs())
    assert binding.api == "classic"
    assert set(agent.registered.keys()) == {"echo", "ping"}
    assert set(binding.function_map.keys()) == {"echo", "ping"}
    assert binding.tools == []


def test_classic_explicit_api_bypasses_detection():
    agent = _ClassicAgent()
    client = MagicMock()
    binding = register_cordum_tools(agent, client, tools=_tool_defs(), api="classic")
    assert binding.api == "classic"


def test_classic_logger_hook_attached_when_logger_supplied():
    agent = _ClassicAgent()
    client = MagicMock()
    logger = MagicMock()
    logger.log_turn = MagicMock()
    register_cordum_tools(agent, client, tools=_tool_defs(), logger=logger)
    # One reply hook was attached for the logger.
    assert len(agent.reply_hooks) == 1


def test_classic_missing_register_function_raises():
    class Bare:
        def register_reply(self, trigger, fn) -> None:  # still a classic signal
            pass

    agent = Bare()
    client = MagicMock()
    with pytest.raises(TypeError):
        register_cordum_tools(agent, client, tools=_tool_defs(), api="classic")


# --- modern path --------------------------------------------------------


class _ModernAgent:
    """Duck-types AssistantAgent just enough for detection + registration."""

    def __init__(self) -> None:
        self.tools: list = []
        # Presence of on_messages_stream routes _detect_api to 'modern'.
    def on_messages_stream(self, messages, cancellation_token):  # pragma: no cover
        yield from ()


def test_modern_auto_detect_extends_tools_list():
    pytest.importorskip("autogen_core.tools")
    agent = _ModernAgent()
    client = MagicMock()
    binding = register_cordum_tools(agent, client, tools=_tool_defs())
    assert binding.api == "modern"
    assert len(binding.tools) == 2
    assert agent.tools is binding.tools or len(agent.tools) == 2


def test_modern_explicit_api():
    pytest.importorskip("autogen_core.tools")
    agent = _ModernAgent()
    client = MagicMock()
    binding = register_cordum_tools(agent, client, tools=_tool_defs(), api="modern")
    assert binding.api == "modern"
    assert len(binding.tools) == 2


def test_unknown_api_raises():
    agent = _ClassicAgent()
    client = MagicMock()
    with pytest.raises(ValueError):
        register_cordum_tools(agent, client, tools=_tool_defs(), api="bogus")  # type: ignore[arg-type]


def test_binding_dataclass_default_factories_not_shared():
    a = CordumAutoGenBinding(api="classic")
    b = CordumAutoGenBinding(api="classic")
    a.function_map["x"] = lambda: None
    assert "x" not in b.function_map
