"""Tests for LlamaIndex executor."""
from __future__ import annotations

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

_sidecar_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_integrations = os.path.normpath(os.path.join(_sidecar_root, "..", "..", "..", "integrations"))
for _path in [
    os.path.join(_integrations, "sidecar-template", "python"),
    _sidecar_root,
]:
    if _path not in sys.path:
        sys.path.insert(0, _path)

from cordum_llamaindex_sidecar.executor import LlamaIndexExecutor


class TestLlamaIndexExecutor(unittest.TestCase):

    def test_unsupported_action_raises(self):
        executor = LlamaIndexExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor.execute(action="unknown", config={}, payload="test", callback_url="")
        self.assertIn("unsupported action", str(ctx.exception))

    def test_query_requires_query_string(self):
        executor = LlamaIndexExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_query(config={}, payload={"query": ""})
        self.assertIn("query is required", str(ctx.exception))

    def test_retrieve_requires_query(self):
        executor = LlamaIndexExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_retrieve(config={}, payload="")
        self.assertIn("query is required", str(ctx.exception))

    def test_index_create_requires_documents(self):
        executor = LlamaIndexExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_index(config={}, payload={"action": "create", "documents": []})
        self.assertIn("documents are required", str(ctx.exception))

    def test_ingest_requires_source(self):
        executor = LlamaIndexExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_ingest(config={}, payload={"source": {"type": "text", "texts": []}})
        self.assertIn("no documents", str(ctx.exception))

    def test_unsupported_source_type(self):
        executor = LlamaIndexExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_ingest(config={}, payload={"source": {"type": "ftp"}})
        self.assertIn("unsupported source type", str(ctx.exception))

    def test_unsupported_index_action(self):
        executor = LlamaIndexExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_index(config={}, payload={"action": "rename"})
        self.assertIn("unsupported index action", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
