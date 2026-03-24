"""Tests for the CrewAI adapter (does not require crewai installed)."""

import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest


def test_build_crewai_tools_missing_dependency():
    """When neither crewai_tools nor crewai is installed, a clear error is raised."""
    # Temporarily remove crewai modules if present
    hidden = {}
    for mod in list(sys.modules):
        if mod.startswith("crewai"):
            hidden[mod] = sys.modules.pop(mod)
    try:
        with patch.dict(sys.modules, {"crewai_tools": None, "crewai": None, "crewai.tools": None}):
            from cordum_agent_adapters.crewai import _load_base_tool
            # Force reimport by reloading
            import cordum_agent_adapters.crewai as mod
            importlib.reload(mod)
            with pytest.raises(RuntimeError, match="crewai-tools or crewai is required"):
                mod._load_base_tool()
    finally:
        sys.modules.update(hidden)


def test_coerce_kwargs_dict():
    from cordum_agent_adapters.crewai import _coerce_kwargs
    assert _coerce_kwargs((), {"a": 1}) == {"a": 1}


def test_coerce_kwargs_single_string():
    from cordum_agent_adapters.crewai import _coerce_kwargs
    result = _coerce_kwargs(('{"key": "val"}',), {})
    assert result == {"key": "val"}


def test_coerce_kwargs_single_non_json_string():
    from cordum_agent_adapters.crewai import _coerce_kwargs
    result = _coerce_kwargs(("plain text",), {})
    assert result == {"input": "plain text"}


def test_coerce_kwargs_empty():
    from cordum_agent_adapters.crewai import _coerce_kwargs
    assert _coerce_kwargs((), {}) == {}


def test_coerce_kwargs_multiple_args():
    from cordum_agent_adapters.crewai import _coerce_kwargs
    result = _coerce_kwargs(("a", "b"), {})
    assert result == {"args": ["a", "b"]}
