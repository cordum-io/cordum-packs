"""Public testing helpers for cordum-adapters tutorials and integration tests.

These helpers let tutorial code run end-to-end against the docker compose
dev stack WITHOUT requiring a real OpenAI API key. They are public
package surface — importable via ``from cordum_agent_adapters.testing
import FakeModel, ScriptedTurn``.

The module intentionally re-exports a narrow surface so we can harden
the internals (shape of ``_ModelResponse``, event construction) without
breaking tutorial code. Callers should only depend on the exported
names; everything underscore-prefixed is implementation detail.

Why this exists
---------------
The QA gate for the framework-integrations tutorials (docs/tutorials/*)
flagged that the walkthroughs imported ``tests.integration._fake_model``
— a repo-private path that doesn't exist in a ``pip install
"cordum-adapters[openai-agents]"`` install. Promoting the helper into a
supported public testing module closes that gap without vendoring the
example code into the docs repo.

Usage
-----

.. code-block:: python

    from cordum_agent_adapters.testing import FakeModel, ScriptedTurn

    model = FakeModel([
        ScriptedTurn(tool_calls=[{"name": "cordum_submit_job",
                                  "arguments": {"topic": "demo"}}]),
        ScriptedTurn(content="All done."),
    ])
    agent = Agent(name="demo", instructions="test", model=model, tools=[])

The three scripted turns follow the canonical
allow → policy-denied → final-message pattern each tutorial demonstrates.
"""

from .fake_model import FakeModel, ScriptedTurn

__all__ = ["FakeModel", "ScriptedTurn"]
