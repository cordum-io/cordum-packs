"""The integration opt-in must leave normal unit tests runnable."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def collection_hook():
    path = Path(__file__).parent / "integration" / "conftest.py"
    spec = importlib.util.spec_from_file_location("integration_collection_hook", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.pytest_collection_modifyitems


@pytest.mark.parametrize("flag", [None, "0", "false"])
def test_only_integration_tests_are_skipped(collection_hook, monkeypatch, mocker, flag):
    if flag is None:
        monkeypatch.delenv("CORDUM_ADAPTERS_E2E", raising=False)
    else:
        monkeypatch.setenv("CORDUM_ADAPTERS_E2E", flag)
    tests_dir = Path(__file__).parent
    unit = mocker.Mock(path=tests_dir / "test_langchain.py")
    integration = mocker.Mock(path=tests_dir / "integration" / "test_autogen_e2e.py")
    nested = mocker.Mock(path=tests_dir / "integration" / "nested" / "test_example.py")
    sibling = mocker.Mock(path=tests_dir / "integration_helpers" / "test_example.py")

    collection_hook(mocker.Mock(), [unit, integration, nested, sibling])

    unit.add_marker.assert_not_called()
    sibling.add_marker.assert_not_called()
    for item in (integration, nested):
        item.add_marker.assert_called_once()
        assert item.add_marker.call_args.args[0].name == "skip"
        assert "CORDUM_ADAPTERS_E2E=1" in item.add_marker.call_args.args[0].kwargs["reason"]


@pytest.mark.parametrize("flag", ["1", "true", "YES"])
def test_enabled_integration_tests_are_not_skipped(collection_hook, monkeypatch, mocker, flag):
    monkeypatch.setenv("CORDUM_ADAPTERS_E2E", flag)
    integration = mocker.Mock(path=Path(__file__).parent / "integration" / "test_example.py")

    collection_hook(mocker.Mock(), [integration])

    integration.add_marker.assert_not_called()


def test_graph_modules_skip_without_optional_http_client():
    """Other framework extras need not install the demo's HTTP client."""
    tests_dir = Path(__file__).parent
    script = """
import importlib.abc
import runpy
import sys
import pytest

class WithoutHttpx(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] == 'httpx':
            raise ModuleNotFoundError("No module named 'httpx'", name='httpx')
sys.meta_path.insert(0, WithoutHttpx())
for path in sys.argv[1:]:
    try:
        runpy.run_path(path)
    except pytest.skip.Exception:
        continue
    raise AssertionError('Expected optional-dependency skip: ' + path)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tests_dir / "test_langgraph_demo.py"),
         str(tests_dir / "integration" / "test_langgraph_live.py")],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
