from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

from .mcp_client import McpStdioClient


def _parse_tool_input(raw: Any) -> Dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {"input": raw}
    return {"input": raw}


def _schema_type(schema: Dict[str, Any]) -> Any:
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = next((item for item in schema_type if item != "null"), None)
    if schema_type == "string":
        return str
    if schema_type == "integer":
        return int
    if schema_type == "number":
        return float
    if schema_type == "boolean":
        return bool
    if schema_type == "array":
        return list
    if schema_type == "object":
        return dict
    return Any


def _pydantic_model_from_schema(name: str, schema: Dict[str, Any]) -> Any:
    try:
        from pydantic import Field, create_model
    except ImportError:
        return None

    properties = schema.get("properties") if isinstance(schema, dict) else {}
    required = set(schema.get("required", [])) if isinstance(schema, dict) else set()

    fields: Dict[str, Any] = {}
    if isinstance(properties, dict):
        for prop, prop_schema in properties.items():
            prop_schema = prop_schema or {}
            field_type = _schema_type(prop_schema) if isinstance(prop_schema, dict) else Any
            description = prop_schema.get("description", "") if isinstance(prop_schema, dict) else ""
            if prop in required:
                default = Field(..., description=description)
            else:
                default = Field(None, description=description)
            fields[prop] = (field_type, default)

    safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    model_name = f"{safe_name}_Args"
    return create_model(model_name, **fields)


def build_langchain_tools(
    client: McpStdioClient,
    tools: Optional[List[Dict[str, Any]]] = None,
    result_transform: Optional[Callable[[Dict[str, Any]], Any]] = None,
) -> List[Any]:
    try:
        from langchain_core.tools import StructuredTool, Tool
    except ImportError as exc:
        raise RuntimeError("langchain-core is required for LangChain adapters") from exc

    tool_defs = tools or client.list_tools()
    built_tools: List[Any] = []

    def _invoke(name: str, args: Dict[str, Any]) -> Any:
        result = client.call_tool(name, args)
        if result_transform:
            return result_transform(result)
        return result

    def _make_structured_call(bound_name: str) -> Callable[..., Any]:
        def _call(**kwargs: Any) -> Any:
            return _invoke(bound_name, kwargs)

        return _call

    def _make_tool_call(bound_name: str) -> Callable[[Any], Any]:
        def _call(raw: Any) -> Any:
            args = _parse_tool_input(raw)
            return _invoke(bound_name, args)

        return _call

    for tool in tool_defs:
        name = tool.get("name", "")
        description = tool.get("description", "")
        input_schema = tool.get("inputSchema") or {"type": "object", "properties": {}}

        args_schema = _pydantic_model_from_schema(name, input_schema)
        if args_schema is not None:
            built_tools.append(
                StructuredTool.from_function(
                    func=_make_structured_call(name),
                    name=name,
                    description=description,
                    args_schema=args_schema,
                )
            )
        else:
            built_tools.append(Tool(name=name, description=description, func=_make_tool_call(name)))

    return built_tools
