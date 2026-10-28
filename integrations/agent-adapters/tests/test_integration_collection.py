"""The integration opt-in must leave normal unit tests runnable."""

import importlib.util
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
