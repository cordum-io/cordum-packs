"""Tests for LangChain executor — chain dispatch with mock LLM."""
from __future__ import annotations

import sys
import os
import unittest
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

from cordum_langchain_sidecar.executor import LangChainExecutor


class TestLangChainExecutor(unittest.TestCase):
    """Test executor action routing."""

    def test_unsupported_action_raises(self):
        executor = LangChainExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor.execute(
                action="unknown.action",
                config={},
                payload="test",
                callback_url="",
            )
        self.assertIn("unsupported action", str(ctx.exception))

    def test_chain_invoke_with_mock_llm(self):
        """Test chain execution with a mocked LLM via pipe operator."""
        executor = LangChainExecutor()

        mock_llm = MagicMock()
        # Mock the pipe chain: llm | StrOutputParser() returns a chain
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = "Hello from mock!"
        mock_llm.__or__ = MagicMock(return_value=mock_chain)

        with patch("cordum_langchain_sidecar.executor._build_llm", return_value=mock_llm):
            result = executor._execute_chain(
                config={"chain_type": "llm", "llm_config": {"provider": "openai", "model": "gpt-4o"}},
                payload="Say hello",
                callback_url="",
            )

        self.assertIn("output", result)
        self.assertEqual(result["output"], "Hello from mock!")

    def test_retriever_requires_query(self):
        """Test retriever raises on empty query."""
        executor = LangChainExecutor()
        with self.assertRaises(ValueError) as ctx:
            executor._execute_retriever(
                config={"store_config": {"provider": "chroma"}},
                payload={"query": "", "k": 4},
                callback_url="",
            )
        self.assertIn("query is required", str(ctx.exception))

    def test_chain_unsupported_type(self):
        """Test unsupported chain type raises."""
        executor = LangChainExecutor()
        mock_llm = MagicMock()

        with patch("cordum_langchain_sidecar.executor._build_llm", return_value=mock_llm):
            with self.assertRaises(ValueError) as ctx:
                executor._execute_chain(
                    config={"chain_type": "nonexistent", "llm_config": {"provider": "openai", "model": "gpt-4o"}},
                    payload="test",
                    callback_url="",
                )
        self.assertIn("unsupported chain_type", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
