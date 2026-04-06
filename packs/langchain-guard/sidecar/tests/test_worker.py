"""Tests for the worker module."""

import pytest

from cordum_langchain_guard.worker import InProcessWorker, ToolRegistry


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


def test_registry_register_and_get():
    reg = ToolRegistry()
    tool = _make_mock_tool(tool_name="search")
    reg.register(tool)

    assert reg.get("search") is tool
    assert reg.get("nonexistent") is None
    assert len(reg) == 1
    assert reg.names() == ["search"]


def test_registry_register_many():
    reg = ToolRegistry()
    tools = [_make_mock_tool(tool_name="t1"), _make_mock_tool(tool_name="t2"), _make_mock_tool(tool_name="t3")]
    reg.register_many(tools)

    assert len(reg) == 3
    assert set(reg.names()) == {"t1", "t2", "t3"}


def test_in_process_worker_execute():
    reg = ToolRegistry()
    tool = _make_mock_tool(tool_name="search")
    reg.register(tool)

    worker = InProcessWorker(reg, "http://localhost:8081")
    result = worker.execute_tool("search", {"query": "hello"})

    assert result["tool_name"] == "search"
    assert result["output"] == "result for hello"
    assert "execution_ms" in result
    assert "error" not in result


def test_in_process_worker_unknown_tool():
    reg = ToolRegistry()
    worker = InProcessWorker(reg, "http://localhost:8081")

    result = worker.execute_tool("unknown", {})
    assert "error" in result
    assert "not registered" in result["error"]


def test_in_process_worker_tool_error():
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        pytest.skip("langchain-core not installed")

    class FailingTool(BaseTool):
        name: str = "fail"
        description: str = "Always fails"

        def _run(self, query: str) -> str:
            raise ValueError("intentional failure")

    reg = ToolRegistry()
    reg.register(FailingTool())

    worker = InProcessWorker(reg, "http://localhost:8081")
    result = worker.execute_tool("fail", {"query": "test"})

    assert result["tool_name"] == "fail"
    assert "intentional failure" in result["error"]
    assert "execution_ms" in result


def test_worker_start_stop():
    reg = ToolRegistry()
    reg.register(_make_mock_tool())

    worker = InProcessWorker(reg, "http://localhost:8081")
    worker.start()
    assert worker._running
    worker.stop()
    assert not worker._running
