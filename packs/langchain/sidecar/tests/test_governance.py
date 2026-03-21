"""Tests for governance wrapping — verifies tools are wrapped with GovernedLangChainTool."""
from __future__ import annotations

import sys
import os
import json
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from unittest.mock import patch, MagicMock

# Ensure sidecar modules are importable
_sidecar_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_integrations = os.path.normpath(os.path.join(_sidecar_root, "..", "..", "..", "integrations"))
for _path in [
    os.path.join(_integrations, "sidecar-template", "python"),
    os.path.join(_integrations, "agent-adapters"),
    _sidecar_root,
]:
    if _path not in sys.path:
        sys.path.insert(0, _path)

from cordum_langchain_sidecar.governance import wrap_tools_with_governance


class MockCallbackHandler(BaseHTTPRequestHandler):
    """Mock governance callback server that approves all tool calls."""

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        request = json.loads(body)

        response = {
            "approved": True,
            "result": f"Mock result for {request.get('tool_name', 'unknown')}",
            "job_id": "mock-job-123",
            "trace_id": request.get("trace_id", ""),
            "status": "succeeded",
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass  # Suppress logs during tests


class MockDenyCallbackHandler(BaseHTTPRequestHandler):
    """Mock governance callback server that denies all tool calls."""

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response = {
            "approved": False,
            "error": "Tool call denied by test policy",
            "status": "denied",
        }
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass


class TestGovernanceWrapping(unittest.TestCase):
    """Test that tools are properly wrapped with governance."""

    def test_wrap_tools_with_callback(self):
        """Tools with callback_url should be GovernedLangChainTool instances."""
        tools = wrap_tools_with_governance(
            tool_configs=[
                {"name": "search", "description": "Search the web"},
                {"name": "calculator", "description": "Do math"},
            ],
            callback_url="http://127.0.0.1:9999",
        )

        self.assertEqual(len(tools), 2)
        # Both should have governance attributes
        for tool in tools:
            self.assertTrue(hasattr(tool, "callback_url"))
            self.assertTrue(hasattr(tool, "tool_name"))

    def test_wrap_tools_without_callback(self):
        """Tools without callback_url should be plain LangChain Tools."""
        tools = wrap_tools_with_governance(
            tool_configs=[
                {"name": "search", "description": "Search the web"},
            ],
            callback_url="",
        )

        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0].name, "search")

    def test_empty_name_skipped(self):
        """Tools without a name should be skipped."""
        tools = wrap_tools_with_governance(
            tool_configs=[
                {"name": "", "description": "No name"},
                {"name": "valid", "description": "Has a name"},
            ],
            callback_url="http://127.0.0.1:9999",
        )

        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0].name, "valid")

    def test_governed_tool_approved(self):
        """Test that a governed tool call routes through callback and succeeds."""
        server = HTTPServer(("127.0.0.1", 0), MockCallbackHandler)
        port = server.server_address[1]
        thread = Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        try:
            tools = wrap_tools_with_governance(
                tool_configs=[{"name": "test_tool", "description": "A test tool"}],
                callback_url=f"http://127.0.0.1:{port}",
                timeout_seconds=5.0,
            )

            self.assertEqual(len(tools), 1)
            result = tools[0]._run({"query": "test input"})
            self.assertIn("Mock result", str(result))
        finally:
            server.shutdown()

    def test_governed_tool_denied(self):
        """Test that a denied tool call raises GovernanceDeniedError."""
        from governance import GovernanceDeniedError

        server = HTTPServer(("127.0.0.1", 0), MockDenyCallbackHandler)
        port = server.server_address[1]
        thread = Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        try:
            tools = wrap_tools_with_governance(
                tool_configs=[{"name": "denied_tool", "description": "Will be denied"}],
                callback_url=f"http://127.0.0.1:{port}",
                timeout_seconds=5.0,
            )

            self.assertEqual(len(tools), 1)
            with self.assertRaises(GovernanceDeniedError):
                tools[0]._run({"action": "delete"})
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
