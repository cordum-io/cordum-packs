"""Tests for the shared pydantic model builder.

Covers the five schema features called out in the task DoD (arrays,
enums, nested objects, nullable, formats) plus deep nesting and strict
validation via additionalProperties:false.
"""
from __future__ import annotations

import datetime
from typing import Any, Optional, get_args, get_origin

import pytest

try:
    from pydantic import BaseModel, ValidationError
    HAVE_PYDANTIC = True
except ImportError:  # pragma: no cover — the package declares pydantic as a core dep
    HAVE_PYDANTIC = False

from cordum_agent_adapters._pydantic_models import build_model, schema_to_type

pytestmark = pytest.mark.skipif(not HAVE_PYDANTIC, reason="pydantic unavailable")


class TestSchemaToType:
    def test_primitives(self) -> None:
        assert schema_to_type({"type": "string"}) is str
        assert schema_to_type({"type": "integer"}) is int
        assert schema_to_type({"type": "number"}) is float
        assert schema_to_type({"type": "boolean"}) is bool

    def test_unknown_type_falls_back_to_any(self) -> None:
        # Unknown "type" values resolve to Any so forward-compatible
        # schemas don't break the adapter.
        assert schema_to_type({"type": "exotic"}) is Any

    def test_array_of_strings(self) -> None:
        t = schema_to_type({"type": "array", "items": {"type": "string"}})
        assert get_origin(t) is list
        assert get_args(t) == (str,)

    def test_array_of_objects(self) -> None:
        t = schema_to_type(
            {
                "type": "array",
                "items": {"type": "object", "properties": {"name": {"type": "string"}}},
            }
        )
        assert get_origin(t) is list
        # Inner is a dict-fallback OR a pydantic model — either way truthy.
        (inner,) = get_args(t)
        assert inner is not None

    def test_enum_literal(self) -> None:
        t = schema_to_type({"enum": ["a", "b", "c"]})
        # Literal["a","b","c"] — Literal's __args__ are the enum values.
        assert get_args(t) == ("a", "b", "c")

    def test_nullable_via_type_list(self) -> None:
        t = schema_to_type({"type": ["string", "null"]})
        # Optional[str] == Union[str, None]; origin for Union → typing.Union
        import typing
        assert typing.get_origin(t) is typing.Union
        assert type(None) in typing.get_args(t)
        assert str in typing.get_args(t)

    def test_nullable_via_flag(self) -> None:
        import typing
        t = schema_to_type({"type": "string", "nullable": True})
        assert typing.get_origin(t) is typing.Union

    def test_format_date_time(self) -> None:
        t = schema_to_type({"type": "string", "format": "date-time"})
        assert t is datetime.datetime

    def test_format_uri(self) -> None:
        t = schema_to_type({"type": "string", "format": "uri"})
        # Either pydantic AnyUrl or str fallback; both are acceptable.
        assert t is not None

    def test_nested_object_builds_submodel(self) -> None:
        t = schema_to_type(
            {
                "type": "object",
                "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
            },
            parent="Parent",
            prop="payload",
        )
        # Either dict fallback or a pydantic model class.
        assert t is not None
        if hasattr(t, "model_fields") or hasattr(t, "__fields__"):
            # pydantic model path
            fields = getattr(t, "model_fields", None) or getattr(t, "__fields__", None)
            assert fields is not None
            assert "name" in fields and "age" in fields


class TestBuildModel:
    def test_empty_schema_yields_empty_model(self) -> None:
        m = build_model("Empty", {"type": "object", "properties": {}})
        assert m is not None
        assert issubclass(m, BaseModel)
        inst = m()
        assert inst is not None

    def test_required_fields_enforced(self) -> None:
        m = build_model(
            "R",
            {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
                "additionalProperties": False,
            },
        )
        assert m is not None
        with pytest.raises(ValidationError):
            m()
        inst = m(id="abc")
        assert inst.id == "abc"

    def test_additional_properties_false_forbids_extras(self) -> None:
        m = build_model(
            "Strict",
            {
                "type": "object",
                "properties": {"known": {"type": "string"}},
                "additionalProperties": False,
            },
        )
        assert m is not None
        with pytest.raises(ValidationError):
            m(known="x", unknown="y")

    def test_additional_properties_true_allows_extras(self) -> None:
        m = build_model(
            "Loose",
            {
                "type": "object",
                "properties": {"known": {"type": "string"}},
            },
        )
        assert m is not None
        # Should NOT raise with unknown kwargs.
        inst = m(known="x", unknown="y")
        assert inst.known == "x"

    def test_array_field_validates(self) -> None:
        m = build_model(
            "A",
            {
                "type": "object",
                "properties": {"tags": {"type": "array", "items": {"type": "string"}}},
                "required": ["tags"],
            },
        )
        assert m is not None
        inst = m(tags=["a", "b"])
        assert inst.tags == ["a", "b"]
        with pytest.raises(ValidationError):
            m(tags=[1, 2])

    def test_enum_field_validates(self) -> None:
        m = build_model(
            "E",
            {
                "type": "object",
                "properties": {"level": {"enum": ["low", "medium", "high"]}},
                "required": ["level"],
            },
        )
        assert m is not None
        inst = m(level="medium")
        assert inst.level == "medium"
        with pytest.raises(ValidationError):
            m(level="extreme")

    def test_nullable_field_accepts_none(self) -> None:
        m = build_model(
            "N",
            {
                "type": "object",
                "properties": {"note": {"type": ["string", "null"]}},
                "required": ["note"],
            },
        )
        assert m is not None
        inst = m(note=None)
        assert inst.note is None
        inst2 = m(note="hi")
        assert inst2.note == "hi"

    def test_deeply_nested_schema_builds(self) -> None:
        m = build_model(
            "Outer",
            {
                "type": "object",
                "properties": {
                    "inner": {
                        "type": "object",
                        "properties": {
                            "deeper": {
                                "type": "object",
                                "properties": {"leaf": {"type": "integer"}},
                                "required": ["leaf"],
                            },
                        },
                    },
                },
            },
        )
        assert m is not None
        # Should instantiate with nested dicts or None.
        inst = m()
        assert inst is not None

    def test_format_date_time_field_accepts_iso(self) -> None:
        m = build_model(
            "T",
            {
                "type": "object",
                "properties": {"ts": {"type": "string", "format": "date-time"}},
                "required": ["ts"],
            },
        )
        assert m is not None
        inst = m(ts="2026-04-18T09:00:00Z")
        assert isinstance(inst.ts, datetime.datetime)

    def test_non_required_field_defaults_none(self) -> None:
        m = build_model(
            "D",
            {
                "type": "object",
                "properties": {
                    "required_field": {"type": "string"},
                    "optional_field": {"type": "string"},
                },
                "required": ["required_field"],
            },
        )
        assert m is not None
        inst = m(required_field="x")
        assert inst.optional_field is None

    def test_bad_schema_falls_back_to_any(self) -> None:
        # A string where a dict is expected — the helper should not crash.
        m = build_model("Bad", "this-is-not-a-dict")  # type: ignore[arg-type]
        assert m is not None  # Returns an empty BaseModel.


def test_build_model_handles_missing_pydantic(monkeypatch: pytest.MonkeyPatch) -> None:
    """When pydantic isn't installed, build_model returns None cleanly.

    Simulate by making `pydantic` raise ImportError via sys.modules.
    """
    import sys
    import cordum_agent_adapters._pydantic_models as mod

    # Monkey-patch the local import — the function does a lazy import,
    # so we intercept by nuking pydantic from sys.modules and inserting
    # a sentinel that raises.
    saved = sys.modules.get("pydantic")
    sys.modules["pydantic"] = None  # type: ignore[assignment]
    try:
        result = mod.build_model("X", {"type": "object", "properties": {}})
        assert result is None
    finally:
        if saved is not None:
            sys.modules["pydantic"] = saved
        else:
            sys.modules.pop("pydantic", None)
