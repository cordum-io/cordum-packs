"""Shared schema helpers used by every framework adapter.

This module is a small facade that:

- Re-exports the canonical pydantic-model builder from
  :mod:`cordum_agent_adapters._pydantic_models` so adapters import from
  one place. The legacy ``_pydantic_models`` is the source of truth.
- Adds :func:`normalise_strict_schema` for the OpenAI Agents SDK
  adapter, which requires every JSON-Schema fed to ``FunctionTool`` to
  be marked ``additionalProperties: false`` and have ``type`` declared
  on every property.

The helpers are import-safe (no optional framework deps) so test
collection on a bare interpreter works.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional, Type

from ._pydantic_models import build_model, schema_to_type


def pydantic_model_from_schema(name: str, schema: Dict[str, Any]) -> Optional[Type[Any]]:
    """Build a pydantic model class from an MCP tool input schema.

    Thin alias over :func:`cordum_agent_adapters._pydantic_models.build_model`
    so the adapters can ``from ._schema import pydantic_model_from_schema``
    without reaching across module boundaries each time.
    """
    return build_model(name, schema)


# Public re-export for callers that need the lower-level type mapping
# (used by adapter tests + the LangChain adapter).
schema_type = schema_to_type


def normalise_strict_schema(schema: Any) -> Dict[str, Any]:
    """Patch ``schema`` so the OpenAI Agents SDK accepts it under strict mode.

    Strict-mode JSON-Schema requires:

    1. A top-level ``type`` declaration. Missing → defaulted to ``object``
       (the dominant case for MCP tool inputs).
    2. ``additionalProperties: false`` on every object schema. Missing →
       defaulted to ``False``. Already-set values are preserved (a
       caller who explicitly opens a tool to extra fields is honoured).
    3. Every property under an object must declare a ``type``. Missing
       properties get ``"string"`` as a safe default — strict mode
       forbids untyped properties, and string is broadly compatible
       with how LLMs compose JSON.

    The helper is **idempotent**: feeding its output back in produces an
    identical dict. It also deep-copies the input via JSON round-trip
    so a caller's original schema dict is never mutated in place
    (important for adapters that share schema objects across multiple
    tool builds).

    Non-dict inputs (``None``, malformed entries) become an empty
    object schema rather than raising — the upstream adapter then
    surfaces a structured warning.
    """
    if not isinstance(schema, dict):
        return {"type": "object", "additionalProperties": False, "properties": {}}
    out: Dict[str, Any] = json.loads(json.dumps(schema))  # cheap deep-copy
    _strictify(out)
    return out


def _strictify(node: Dict[str, Any]) -> None:
    """Recursively normalise ``node`` in place for strict-mode compliance.

    Walks every nested object/array schema the OpenAI Agents SDK will
    traverse so a deep tree doesn't smuggle an ``additionalProperties:
    True`` under an inner object. The SDK (>=0.14) rejects any object
    schema where ``additionalProperties`` is truthy, so for strict mode
    we FORCE false — a caller who needs open extra fields should pass
    ``strict=False`` to the adapter instead.
    """
    if "type" not in node:
        node["type"] = "object"
    if node.get("type") == "object":
        # Strict mode forbids additionalProperties truthy values. Force
        # false regardless of the caller's original setting.
        node["additionalProperties"] = False
        props = node.setdefault("properties", {})
        if isinstance(props, dict):
            for prop_name, sub in list(props.items()):
                if not isinstance(sub, dict):
                    continue
                if "type" not in sub:
                    # Strict mode forbids untyped properties; default
                    # to string because the LLM composes strings most
                    # naturally and the tool is free to coerce.
                    sub["type"] = "string"
                _strictify(sub)
                props[prop_name] = sub
    elif node.get("type") == "array":
        items = node.get("items")
        if isinstance(items, dict):
            _strictify(items)


__all__ = [
    "pydantic_model_from_schema",
    "schema_type",
    "normalise_strict_schema",
]
