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
            # Force reimport by reloading
            from cordum_agent_adapters import crewai as mod
            importlib.reload(mod)
            with pytest.raises(RuntimeError, match="CrewAI is not installed"):
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


# ---------------------------------------------------------------------------
# Redaction: word-boundary so ``api_version`` survives while ``api_key`` is
# masked. Adversarial inputs exercised with variants the scrubber must catch.
# ---------------------------------------------------------------------------


def test_redact_args_scrubs_sensitive_keys():
    from cordum_agent_adapters.crewai import _redact_args, _REDACTED_PLACEHOLDER

    out = _redact_args({
        "password": "s3cret",
        "api_key": "sk-xxx",
        "apiKey": "sk-xxx",
        "x-api-key": "sk-xxx",
        "token": "t1",
        "authorization": "Bearer abc",
        "passwd": "old-unix-style",
        "safe": "ok",
        "api_version": "v2",
    })
    for k in ("password", "api_key", "apiKey", "x-api-key", "token", "authorization", "passwd"):
        assert out[k] == _REDACTED_PLACEHOLDER, f"{k} not scrubbed"
    assert out["safe"] == "ok"
    assert out["api_version"] == "v2"


def test_redact_args_recursive_one_level():
    from cordum_agent_adapters.crewai import _redact_args, _REDACTED_PLACEHOLDER
    out = _redact_args({"meta": {"token": "s", "note": "x"}})
    assert out["meta"]["token"] == _REDACTED_PLACEHOLDER
    assert out["meta"]["note"] == "x"


# ---------------------------------------------------------------------------
# Retry wiring via build_crewai_tools. Uses a fake BaseTool that exposes
# the _run attribute directly so we can call it without instantiating a
# real CrewAI BaseTool (which would require the crewai extra).
# ---------------------------------------------------------------------------


class _FakeBaseTool:
    """Minimal stand-in for CrewAI's BaseTool.

    build_crewai_tools builds a subclass via ``type(..., (BaseTool,), attrs)``
    which carries the _run/_arun methods on the class. CrewAI's real
    BaseTool has many pydantic fields; we bypass all of it because the
    tests only exercise the _run path.
    """

    def __init__(self, **_kwargs: object) -> None:  # accept name=, description= etc.
        pass


@pytest.fixture
def patched_base_tool(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Patch _load_base_tool so build_crewai_tools works without crewai.

    Returns a MagicMock so tests can assert on how it was called.
    """
    from cordum_agent_adapters import crewai as mod
    loader = MagicMock(return_value=_FakeBaseTool)
    monkeypatch.setattr(mod, "_load_base_tool", loader)
    return loader


def _build_one_tool(client: MagicMock, name: str = "t.echo", **kwargs: object) -> object:
    from cordum_agent_adapters.crewai import build_crewai_tools
    tool_defs = [{"name": name, "description": "Echo tool", "inputSchema": {"type": "object"}}]
    built = build_crewai_tools(client, tool_defs, **kwargs)
    return built[0]


def test_build_crewai_tools_invokes_client_call_tool(patched_base_tool: MagicMock) -> None:
    client = MagicMock()
    client.call_tool.return_value = {"content": "ok"}

    tool = _build_one_tool(client)
    # CrewAI calls _run(self, *args, **kwargs); we call it bound with
    # keyword args to exercise the canonical path.
    assert tool._run(tool, msg="hi") == {"content": "ok"}
    client.call_tool.assert_called_once_with("t.echo", {"msg": "hi"})


def test_retry_policy_wired_into_run(patched_base_tool: MagicMock) -> None:
    from cordum_agent_adapters.mcp_client import McpError
    from cordum_agent_adapters.retry import RetryPolicy

    client = MagicMock()
    # Fail twice, succeed on third attempt.
    client.call_tool.side_effect = [McpError("x"), McpError("y"), {"content": "ok"}]

    tool = _build_one_tool(
        client,
        retry_policy=RetryPolicy(max_attempts=3, initial_backoff_s=0, jitter=0),
    )
    assert tool._run(tool, msg="hi") == {"content": "ok"}
    assert client.call_tool.call_count == 3


def test_exception_wrapped_as_adapter_tool_call_error(patched_base_tool: MagicMock) -> None:
    from cordum_agent_adapters.errors import AdapterToolCallError
    from cordum_agent_adapters.mcp_client import McpToolError

    inner = McpToolError("policy denied", {"isError": True})
    client = MagicMock()
    client.call_tool.side_effect = inner

    tool = _build_one_tool(client)
    with pytest.raises(AdapterToolCallError) as excinfo:
        tool._run(tool, msg="hi")
    assert excinfo.value.tool_name == "t.echo"
    assert excinfo.value.cause is inner
    assert excinfo.value.__cause__ is inner


def test_adapter_error_has_redacted_args(patched_base_tool: MagicMock) -> None:
    from cordum_agent_adapters.errors import AdapterToolCallError
    from cordum_agent_adapters.crewai import _REDACTED_PLACEHOLDER
    from cordum_agent_adapters.mcp_client import McpError

    client = MagicMock()
    client.call_tool.side_effect = McpError("x")

    tool = _build_one_tool(client)
    with pytest.raises(AdapterToolCallError) as excinfo:
        tool._run(tool, password="secret", note="ok")
    assert excinfo.value.tool_args["password"] == _REDACTED_PLACEHOLDER
    assert excinfo.value.tool_args["note"] == "ok"


def test_async_mode_generates_arun(patched_base_tool: MagicMock) -> None:
    client = MagicMock()
    tool = _build_one_tool(client, async_mode=True)
    assert hasattr(tool, "_arun")
    assert callable(tool._arun)


@pytest.mark.asyncio
async def test_async_run_delegates_to_async_client(patched_base_tool: MagicMock) -> None:
    import asyncio

    client = MagicMock()

    async def async_call(name: str, args: dict) -> dict:
        return {"content": "async ok"}

    client.call_tool_async = async_call
    tool = _build_one_tool(client, async_mode=True)
    result = await tool._arun(tool, msg="hi")
    assert result == {"content": "async ok"}


def test_result_transform_applied(patched_base_tool: MagicMock) -> None:
    client = MagicMock()
    client.call_tool.return_value = {"content": "raw"}
    tool = _build_one_tool(client, result_transform=lambda r: r["content"].upper())
    assert tool._run(tool, msg="x") == "RAW"


def test_tool_class_has_stable_module(patched_base_tool: MagicMock) -> None:
    client = MagicMock()
    client.call_tool.return_value = {"content": "ok"}
    tool = _build_one_tool(client)
    assert type(tool).__module__ == "cordum_agent_adapters.crewai"


# ---------------------------------------------------------------------------
# build_crew — convenience helper. Tested with a fake crewai module so
# these tests run without the heavy optional dep.
# ---------------------------------------------------------------------------


class _FakeAgent:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs


class _FakeTask:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs


class _FakeCrew:
    def __init__(self, agents: list, tasks: list) -> None:
        self.agents = agents
        self.tasks = tasks


def _install_fake_crewai(monkeypatch: pytest.MonkeyPatch) -> object:
    fake = MagicMock()
    fake.Agent = _FakeAgent
    fake.Task = _FakeTask
    fake.Crew = _FakeCrew
    monkeypatch.setitem(sys.modules, "crewai", fake)
    return fake


@pytest.fixture
def fake_crewai_and_base(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    _install_fake_crewai(monkeypatch)
    from cordum_agent_adapters import crewai as mod
    monkeypatch.setattr(mod, "_load_base_tool", lambda: _FakeBaseTool)
    return monkeypatch


def test_build_crew_happy_path(fake_crewai_and_base: pytest.MonkeyPatch) -> None:
    from cordum_agent_adapters.crewai import build_crew

    client = MagicMock()
    client.list_tools.return_value = [
        {"name": "list_repos", "description": "d1", "inputSchema": {"type": "object"}},
        {"name": "get_weather", "description": "d2", "inputSchema": {"type": "object"}},
    ]

    crew = build_crew(
        client,
        agents_config=[
            {"role": "researcher", "goal": "find things", "backstory": "curious"},
        ],
        tasks_config=[
            {"description": "research X", "expected_output": "a report", "agent": "researcher"},
        ],
    )
    assert isinstance(crew, _FakeCrew)
    assert len(crew.agents) == 1
    assert len(crew.tasks) == 1
    # The agent received both tools.
    agent = crew.agents[0]
    assert len(agent.kwargs["tools"]) == 2


def test_build_crew_allowed_tool_names_subsets(fake_crewai_and_base: pytest.MonkeyPatch) -> None:
    from cordum_agent_adapters.crewai import build_crew

    client = MagicMock()
    client.list_tools.return_value = [
        {"name": "list_repos", "description": "", "inputSchema": {"type": "object"}},
        {"name": "get_weather", "description": "", "inputSchema": {"type": "object"}},
        {"name": "dangerous.delete", "description": "", "inputSchema": {"type": "object"}},
    ]

    crew = build_crew(
        client,
        agents_config=[
            {
                "role": "safe_agent",
                "goal": "do safe things",
                "backstory": "x",
                "allowed_tool_names": ["list_repos", "get_weather"],
            },
        ],
        tasks_config=[{"description": "x", "expected_output": "y"}],
    )
    agent = crew.agents[0]
    tool_names = [t.name for t in agent.kwargs["tools"]]
    assert "dangerous.delete" not in tool_names
    assert set(tool_names) == {"list_repos", "get_weather"}


def test_build_crew_rejects_unknown_allowed_tool(fake_crewai_and_base: pytest.MonkeyPatch) -> None:
    from cordum_agent_adapters.crewai import build_crew
    from cordum_agent_adapters.errors import AdapterSchemaError

    client = MagicMock()
    client.list_tools.return_value = [
        {"name": "list_repos", "description": "", "inputSchema": {"type": "object"}},
    ]

    with pytest.raises(AdapterSchemaError) as excinfo:
        build_crew(
            client,
            agents_config=[
                {
                    "role": "r",
                    "goal": "g",
                    "backstory": "b",
                    "allowed_tool_names": ["does_not_exist"],
                },
            ],
            tasks_config=[{"description": "x", "expected_output": "y"}],
        )
    assert excinfo.value.offending_key == "allowed_tool_names"


def test_build_crew_reports_missing_agent_field(fake_crewai_and_base: pytest.MonkeyPatch) -> None:
    from cordum_agent_adapters.crewai import build_crew
    from cordum_agent_adapters.errors import AdapterSchemaError

    client = MagicMock()
    client.list_tools.return_value = []

    with pytest.raises(AdapterSchemaError) as excinfo:
        build_crew(
            client,
            agents_config=[{"role": "r", "goal": "g"}],  # backstory missing
            tasks_config=[],
        )
    assert excinfo.value.offending_key == "backstory"


def test_build_crew_reports_unknown_task_agent(fake_crewai_and_base: pytest.MonkeyPatch) -> None:
    from cordum_agent_adapters.crewai import build_crew
    from cordum_agent_adapters.errors import AdapterSchemaError

    client = MagicMock()
    client.list_tools.return_value = []

    with pytest.raises(AdapterSchemaError) as excinfo:
        build_crew(
            client,
            agents_config=[{"role": "r", "goal": "g", "backstory": "b"}],
            tasks_config=[{"description": "d", "expected_output": "o", "agent": "ghost"}],
        )
    assert excinfo.value.offending_key == "agent"


def test_build_crew_lazy_import_error_is_actionable() -> None:
    # Run in a clean subprocess-like state where crewai is absent:
    # remove it from sys.modules and intercept the lazy import.
    from cordum_agent_adapters import crewai as mod
    from cordum_agent_adapters.errors import AdapterSchemaError

    # Ensure `crewai` will fail to import by patching sys.modules.
    hidden: dict[str, object] = {}
    for key in list(sys.modules):
        if key == "crewai" or key.startswith("crewai."):
            hidden[key] = sys.modules.pop(key)
    sys.modules["crewai"] = None  # type: ignore[assignment]
    try:
        with pytest.raises(ImportError, match=r"cordum-adapters\[crewai\]"):
            mod._load_crewai()
    finally:
        sys.modules.pop("crewai", None)
        for key, value in hidden.items():
            sys.modules[key] = value


def test_build_crew_passes_retry_policy_through(fake_crewai_and_base: pytest.MonkeyPatch) -> None:
    from cordum_agent_adapters.crewai import build_crew
    from cordum_agent_adapters.mcp_client import McpError
    from cordum_agent_adapters.retry import RetryPolicy

    client = MagicMock()
    client.list_tools.return_value = [
        {"name": "t", "description": "", "inputSchema": {"type": "object"}},
    ]
    client.call_tool.side_effect = [McpError("a"), {"content": "ok"}]

    crew = build_crew(
        client,
        agents_config=[{"role": "r", "goal": "g", "backstory": "b"}],
        tasks_config=[{"description": "x", "expected_output": "y"}],
        retry_policy=RetryPolicy(max_attempts=2, initial_backoff_s=0, jitter=0),
    )
    # Pull the tool off the agent and invoke its _run — the second
    # attempt should succeed because the RetryPolicy was wired through.
    agent = crew.agents[0]
    tool = agent.kwargs["tools"][0]
    assert tool._run(tool, msg="hi") == {"content": "ok"}
    assert client.call_tool.call_count == 2
