"""A second demo can reuse the disposable fixture without port collisions."""
import importlib.util
from pathlib import Path

import pytest


def fixture_module():
    path = Path(__file__).parents[1] / "examples" / "langgraph_fixture" / "stack.py"
    spec = importlib.util.spec_from_file_location("local_fixture_stack", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixture_default_ports_stay_compatible():
    ports = fixture_module().ports_for_offset(0)
    assert ports == {"nats": 14222, "redis": 16379, "gateway_http": 18081,
                     "gateway_grpc": 18080, "gateway_metrics": 19092,
                     "scheduler_metrics": 19090, "safety": 15051, "safety_admin": 19095}


def test_fixture_offset_is_applied_to_every_listener():
    ports = fixture_module().ports_for_offset(10000)
    assert ports["nats"] == 24222
    assert ports["gateway_metrics"] == 29092
    assert ports["scheduler_metrics"] == 29090
    assert ports["safety_admin"] == 29095
    assert len(set(ports.values())) == 8


@pytest.mark.parametrize("offset", [-1, 46441])
def test_fixture_rejects_invalid_offsets(offset):
    with pytest.raises(ValueError, match="port offset"):
        fixture_module().ports_for_offset(offset)
