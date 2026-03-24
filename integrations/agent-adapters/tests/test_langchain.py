"""Tests for the LangChain adapter helper functions (does not require langchain installed)."""

import json

from cordum_agent_adapters.langchain import _parse_tool_input, _schema_type


def test_parse_tool_input_none():
    assert _parse_tool_input(None) == {}


def test_parse_tool_input_dict():
    assert _parse_tool_input({"key": "val"}) == {"key": "val"}


def test_parse_tool_input_json_string():
    assert _parse_tool_input('{"a": 1}') == {"a": 1}


def test_parse_tool_input_plain_string():
    assert _parse_tool_input("hello") == {"input": "hello"}


def test_parse_tool_input_non_dict_json():
    assert _parse_tool_input("[1, 2]") == {"input": "[1, 2]"}


def test_parse_tool_input_number():
    assert _parse_tool_input(42) == {"input": 42}


def test_schema_type_mapping():
    assert _schema_type({"type": "string"}) is str
    assert _schema_type({"type": "integer"}) is int
    assert _schema_type({"type": "number"}) is float
    assert _schema_type({"type": "boolean"}) is bool
    assert _schema_type({"type": "array"}) is list
    assert _schema_type({"type": "object"}) is dict


def test_schema_type_nullable():
    """JSON Schema nullable types like ["string", "null"] should resolve to string."""
    assert _schema_type({"type": ["string", "null"]}) is str
    assert _schema_type({"type": ["null", "integer"]}) is int
