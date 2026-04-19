"""AutoGen audit subpackage — re-exports the canonical logger.

The shared :class:`cordum_agent_adapters.audit.CordumConversationLogger`
is the single source of truth so every adapter publishes turns through
identical wire conventions (session id, MCP tool name, truncation, retry).
This module exists so callers reaching for the autogen-flavoured import
path do not break.
"""
from __future__ import annotations

from ..audit import MAX_TURN_BYTES, CordumConversationLogger

__all__ = ["CordumConversationLogger", "MAX_TURN_BYTES"]
