"""Tests for cordum_agent_adapters._schema.

The strict-schema normaliser is the OpenAI Agents SDK adapter's
load-bearing helper — every MCP tool's inputSchema flows through it
before reaching FunctionTool. The pydantic-model re-exports ride along
to give every adapter a single import surface for schema work.
"""
from __future__ import annotations

import copy

from cordum_agent_adapters._schema import (
    normalise_strict_schema,
    pydantic_model_from_schema,
    schema_type,
)


class TestNormaliseStrictSchema:
    def test_injects_object_type_when_missing(self) -> None:
        out = normalise_strict_schema({"properties": {"x": {"type": "string"}}})
        assert out["type"] == "object"

    def test_injects_additional_properties_false(self) -> None:
        out = normalise_strict_schema({"type": "object", "properties": {}})
        assert out["additionalProperties"] is False

    def test_forces_additional_properties_false_even_when_caller_set_true(self) -> None:
        # openai-agents>=0.14 rejects any strict-mode object schema
        # with additionalProperties truthy. normalise_strict_schema
        # therefore FORCES false regardless of the caller's original
        # setting; a caller who genuinely needs open extra fields
        # should pass strict=False to the adapter instead of relying
        # on their source schema being preserved here.
        out = normalise_strict_schema({"type": "object", "additionalProperties": True})
        assert out["additionalProperties"] is False

    def test_ensures_properties_dict_present(self) -> None:
        out = normalise_strict_schema({"type": "object"})
        assert "properties" in out
        assert out["properties"] == {}

    def test_recurses_into_properties_for_missing_types(self) -> None:
        out = normalise_strict_schema(
            {"type": "object", "properties": {"name": {}, "age": {"type": "integer"}}}
        )
        # Untyped property gets the safe default.
        assert out["properties"]["name"]["type"] == "string"
        # Typed property is left alone.
        assert out["properties"]["age"]["type"] == "integer"

    def test_does_not_mutate_input(self) -> None:
        original = {"type": "object", "properties": {"x": {}}}
        snapshot = copy.deepcopy(original)
        _ = normalise_strict_schema(original)
        assert original == snapshot

    def test_idempotent(self) -> None:
        once = normalise_strict_schema({"properties": {"x": {}}})
        twice = normalise_strict_schema(once)
        assert once == twice

    def test_non_dict_input_returns_safe_default(self) -> None:
        for bad in (None, "object", 0, ["x"]):
            out = normalise_strict_schema(bad)
            assert out["type"] == "object"
            assert out["additionalProperties"] is False
            assert out["properties"] == {}

    def test_preserves_required_array_unchanged(self) -> None:
        out = normalise_strict_schema(
            {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}
        )
        assert out["required"] == ["a"]

    def test_non_object_top_level_type_is_left_alone(self) -> None:
        # MCP tools usually publish object schemas, but if a tool
        # declares a primitive top-level we don't try to wrap it.
        out = normalise_strict_schema({"type": "string"})
        assert out == {"type": "string"}


class TestPydanticReExports:
    def test_pydantic_model_from_schema_builds_a_model(self) -> None:
        model = pydantic_model_from_schema(
            "Echo",
            {
                "type": "object",
                "properties": {"msg": {"type": "string"}},
                "required": ["msg"],
            },
        )
        assert model is not None
        instance = model(msg="hello")
        assert instance.msg == "hello"

    def test_schema_type_matches_underlying_helper(self) -> None:
        # schema_type is a re-export alias — calling it with a primitive
        # schema should return a typing object that Python recognises.
        from cordum_agent_adapters._pydantic_models import schema_to_type

        assert schema_type({"type": "string"}) is schema_to_type({"type": "string"})
