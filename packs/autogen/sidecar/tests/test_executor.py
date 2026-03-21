"""Tests for AutoGen executor."""
from __future__ import annotations

import sys
import os
import unittest

_sidecar_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_integrations = os.path.normpath(os.path.join(_sidecar_root, "..", "..", "..", "integrations"))
for _path in [
    os.path.join(_integrations, "sidecar-template", "python"),
    os.path.join(_integrations, "agent-adapters"),
    _sidecar_root,
]:
    if _path not in sys.path:
        sys.path.insert(0, _path)

from cordum_autogen_sidecar.executor import AutoGenExecutor


class TestAutoGenExecutor(unittest.TestCase):

    def test_unsupported_action_raises(self):
        executor = AutoGenExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor.execute(action="unknown", config={}, payload="test", callback_url="")
        self.assertIn("unsupported action", str(ctx.exception))

    def test_groupchat_requires_agents(self):
        executor = AutoGenExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_groupchat(config={"agents": []}, payload="hello", callback_url="")
        self.assertIn("agents array is required", str(ctx.exception))

    def test_groupchat_requires_message(self):
        executor = AutoGenExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_groupchat(
                config={"agents": [{"name": "a"}]}, payload="", callback_url=""
            )
        self.assertIn("message is required", str(ctx.exception))

    def test_agent_requires_name(self):
        executor = AutoGenExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_agent(config={"name": ""}, payload="hello", callback_url="")
        self.assertIn("agent name is required", str(ctx.exception))

    def test_agent_requires_message(self):
        executor = AutoGenExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_agent(config={"name": "test"}, payload="", callback_url="")
        self.assertIn("message is required", str(ctx.exception))

    def test_code_requires_code(self):
        executor = AutoGenExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_code(config={}, payload="", callback_url="")
        self.assertIn("code is required", str(ctx.exception))

    def test_code_disabled_raises(self):
        executor = AutoGenExecutor()
        os.environ["CORDUM_AUTOGEN_CODE_EXECUTION"] = "disabled"
        try:
            with self.assertRaises(ValueError) as ctx:
                executor._execute_code(config={}, payload="print('hi')", callback_url="")
            self.assertIn("disabled", str(ctx.exception))
        finally:
            os.environ.pop("CORDUM_AUTOGEN_CODE_EXECUTION", None)

    def test_code_rejects_non_docker(self):
        executor = AutoGenExecutor()
        os.environ["CORDUM_AUTOGEN_CODE_EXECUTION"] = "local"
        try:
            with self.assertRaises(ValueError) as ctx:
                executor._execute_code(config={}, payload="print('hi')", callback_url="")
            self.assertIn("Only 'docker' is allowed", str(ctx.exception))
        finally:
            os.environ.pop("CORDUM_AUTOGEN_CODE_EXECUTION", None)


if __name__ == "__main__":
    unittest.main()
