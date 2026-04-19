"""Back-compat shim for the FakeModel helper.

This module used to hold the FakeModel implementation inline. The helper
is now a supported public API at ``cordum_agent_adapters.testing`` so
tutorial code can import it through the same package users install via
pip (the QA reopen on task-766d3e3c flagged that tutorials cannot reach
a ``tests.*`` path in a clean ``pip install`` environment). Keeping
this shim means the integration tests that pre-date the move keep
working without churn — they can continue ``from
tests.integration._fake_model import FakeModel``, and everything resolves
to the public implementation.
"""
from cordum_agent_adapters.testing import FakeModel, ScriptedTurn

__all__ = ["FakeModel", "ScriptedTurn"]
