"""Shared pydantic-model builder for MCP tool input schemas.

All four framework adapters (CrewAI, AutoGen, OpenAI, LangChain) need to
turn an MCP ``inputSchema`` JSON-Schema dict into a pydantic model class
so their respective tool SDKs can validate call-time arguments.

This module is the single source of truth for that conversion so a
schema feature added for one adapter (arrays, enums, nested objects,
nullable types, formats) benefits every adapter the next release.

The conversion is forgiving: every unknown schema feature falls back to
``typing.Any`` and logs at DEBUG so a novel schema never crashes the
pipeline — it just loses its type hint for that field. A compliance
caller who needs strict validation can read the warnings and tighten
the schema.

Pydantic v1 and v2 are both supported; ``ConfigDict`` is preferred when
available.
"""
from __future__ import annotations

import datetime
import logging
import re
from typing import Any, Dict, List, Literal, Optional, Type, Union

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper: sanitise a name into a Python-safe identifier.
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"[^a-zA-Z0-9_]")


def _safe_name(name: str) -> str:
    cleaned = _IDENT_RE.sub("_", name or "")
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned or "Anonymous"


# ---------------------------------------------------------------------------
# Type mapping
# ---------------------------------------------------------------------------

_PRIMITIVE_MAP: Dict[str, Any] = {
    "string": str,
    "integer": int,
    "number": float,
    "boolean": bool,
    "object": dict,
    "array": list,
    "null": type(None),
}


def _format_to_type(fmt: str) -> Optional[Any]:
    """Map JSON Schema ``format`` keywords to Python types when sensible."""
    fmt = (fmt or "").strip().lower()
    if fmt == "date-time":
        return datetime.datetime
    if fmt == "date":
        return datetime.date
    if fmt == "time":
        return datetime.time
    if fmt in ("uri", "url"):
        try:
            from pydantic import AnyUrl
            return AnyUrl
        except ImportError:
            return str
    if fmt == "email":
        try:
            from pydantic import EmailStr
            return EmailStr
        except ImportError:
            return str
    if fmt == "uuid":
        import uuid
        return uuid.UUID
    return None


def _is_nullable(schema: Dict[str, Any]) -> bool:
    """True when the schema explicitly allows a JSON null value."""
    if schema.get("nullable") is True:
        return True
    t = schema.get("type")
    if isinstance(t, list) and "null" in t:
        return True
    return False


def _extract_non_null_type(schema: Dict[str, Any]) -> Optional[str]:
    """Pull the non-null type name from a ``type: ["string","null"]`` list."""
    t = schema.get("type")
    if isinstance(t, list):
        for item in t:
            if item != "null":
                return str(item)
        return None
    if isinstance(t, str):
        return t
    return None


# ---------------------------------------------------------------------------
# Primary type-resolution walker
# ---------------------------------------------------------------------------


def schema_to_type(schema: Any, parent: str = "", prop: str = "") -> Any:
    """Convert a JSON-Schema fragment into a Python / typing type hint.

    ``parent`` + ``prop`` are used to name anonymous nested models so two
    tools that both have a ``payload`` property don't collide in the
    synthetic class registry.

    Returns ``typing.Any`` for anything it doesn't recognise so the
    caller's validation stays open rather than failing hard.
    """
    if not isinstance(schema, dict):
        return Any

    # (b) enum — Literal[...] when every choice shares a base type.
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        # pydantic Literal accepts strings, ints, booleans, None.
        if all(isinstance(v, (str, int, bool)) or v is None for v in enum):
            try:
                return Literal[tuple(enum)]  # type: ignore[valid-type]
            except TypeError:
                logger.debug("Literal build failed for enum %r; falling back to Any", enum)
                return Any
        # Mixed enum — fall back to the base type if declared.

    # Resolve type, handling ["string", "null"].
    nullable = _is_nullable(schema)
    type_name = _extract_non_null_type(schema) or "object"

    inner: Any
    # (a) typed arrays.
    if type_name == "array":
        items = schema.get("items")
        if isinstance(items, dict):
            inner_item = schema_to_type(items, parent=parent, prop=f"{prop}_item")
            inner = List[inner_item]  # type: ignore[valid-type]
        else:
            inner = List[Any]
    # (c) nested objects — recursively build a sub-model when properties exist.
    elif type_name == "object":
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else None
        if properties:
            sub_name = _safe_name(f"{parent}_{prop}" if parent or prop else "Nested")
            try:
                inner = build_model(sub_name, schema)
                if inner is None:
                    inner = dict
            except Exception as exc:  # noqa: BLE001
                logger.debug("nested model build failed for %s: %s", sub_name, exc)
                inner = dict
        else:
            inner = dict
    else:
        # Primitive + format.
        fmt = schema.get("format")
        if fmt:
            mapped = _format_to_type(str(fmt))
            if mapped is not None:
                inner = mapped
            else:
                inner = _PRIMITIVE_MAP.get(type_name, Any)
        else:
            inner = _PRIMITIVE_MAP.get(type_name, Any)

    if nullable:
        return Optional[inner]
    return inner


# ---------------------------------------------------------------------------
# Pydantic model factory
# ---------------------------------------------------------------------------


def _pydantic_config(allow_extra: bool) -> Any:
    """Return a pydantic config object honouring ``allow_extra``.

    Prefers v2 ``ConfigDict``; falls back to a v1-style ``Config`` class.
    """
    mode = "allow" if allow_extra else "forbid"
    try:
        from pydantic import ConfigDict
        return ConfigDict(extra=mode)
    except ImportError:
        class Config:
            extra = mode

        return Config


def build_model(name: str, schema: Dict[str, Any]) -> Optional[Type[Any]]:
    """Build a pydantic model class from an MCP JSON-Schema fragment.

    Returns ``None`` when pydantic is not installed. Returns a concrete
    ``BaseModel`` subclass otherwise, even for an empty-properties
    schema (so CrewAI can still attach an ``args_schema`` for logging).
    """
    try:
        from pydantic import Field, create_model
    except ImportError:
        logger.debug("pydantic unavailable, skipping model build for %s", name)
        return None

    if not isinstance(schema, dict):
        schema = {"type": "object", "properties": {}}

    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = set(schema.get("required", [])) if isinstance(schema.get("required"), list) else set()

    fields: Dict[str, Any] = {}
    for prop, prop_schema in (properties or {}).items():
        if not isinstance(prop_schema, dict):
            prop_schema = {}
        try:
            field_type = schema_to_type(prop_schema, parent=name, prop=prop)
        except Exception as exc:  # noqa: BLE001
            logger.debug("schema_to_type raised for %s.%s: %s; falling back to Any", name, prop, exc)
            field_type = Any
        description = prop_schema.get("description", "") if isinstance(prop_schema, dict) else ""
        if prop in required:
            default = Field(..., description=description)
        else:
            default = Field(None, description=description)
            # Non-required fields should admit None; wrap as Optional unless
            # the type is already Optional (from nullable schema).
            if _origin(field_type) is not Union:
                field_type = Optional[field_type]
        fields[prop] = (field_type, default)

    additional_properties = schema.get("additionalProperties", True)
    allow_extra = additional_properties is not False

    model_name = f"{_safe_name(name)}_Args"
    try:
        return create_model(
            model_name,
            __config__=_pydantic_config(allow_extra),
            **fields,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("pydantic create_model failed for %s: %s; returning None", model_name, exc)
        return None


def _origin(tp: Any) -> Any:
    """Safely return typing.get_origin(tp) across Python versions."""
    try:
        import typing
        return typing.get_origin(tp)
    except Exception:  # noqa: BLE001
        return None


__all__ = [
    "build_model",
    "schema_to_type",
]
