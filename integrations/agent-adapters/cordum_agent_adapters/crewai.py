from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from .mcp_client import McpStdioClient


def _load_base_tool() -> Any:
    try:
        from crewai_tools import BaseTool
        return BaseTool
    except ImportError:
        pass
    try:
        from crewai.tools import BaseTool
        return BaseTool
    except ImportError as exc:
        raise RuntimeError("crewai-tools or crewai is required for CrewAI adapters") from exc


def _coerce_kwargs(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    if kwargs:
        return kwargs
    if not args:
        return {}
    if len(args) == 1:
        raw = args[0]
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
    return {"args": list(args)}


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


def _pydantic_config_allow_extra() -> Any:
    try:
        from pydantic import ConfigDict
    except ImportError:
        class Config:
            extra = "allow"

        return Config
    return ConfigDict(extra="allow")


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

    allow_extra = True
    if isinstance(schema, dict):
        additional = schema.get("additionalProperties", True)
        allow_extra = additional is not False

    safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    model_name = f"{safe_name}_Args"
    if allow_extra:
        return create_model(model_name, __config__=_pydantic_config_allow_extra(), **fields)
    return create_model(model_name, **fields)


def build_crewai_tools(
    client: McpStdioClient,
    tools: Optional[List[Dict[str, Any]]] = None,
    result_transform: Optional[Callable[[Dict[str, Any]], Any]] = None,
) -> List[Any]:
    BaseTool = _load_base_tool()
    tool_defs = tools or client.list_tools()
    built_tools: List[Any] = []

    for tool in tool_defs:
        name = tool.get("name", "")
        description = tool.get("description", "")
        input_schema = tool.get("inputSchema") or {"type": "object", "properties": {}}
        args_schema = _pydantic_model_from_schema(name, input_schema)
        tool_name = name

        def _make_run(bound_name: str) -> Callable[..., Any]:
            def _run(self: Any, *args: Any, **kwargs: Any) -> Any:
                payload = _coerce_kwargs(args, kwargs)
                result = client.call_tool(bound_name, payload)
                if result_transform:
                    return result_transform(result)
                return result

            return _run

        attrs: Dict[str, Any] = {
            "name": tool_name,
            "description": description,
            "_run": _make_run(tool_name),
        }
        if args_schema is not None:
            attrs["args_schema"] = args_schema

        safe_class = re.sub(r"[^a-zA-Z0-9_]", "_", tool_name or "CordumTool")
        tool_class = type(f"{safe_class}Tool", (BaseTool,), attrs)
        built_tools.append(tool_class())

    return built_tools
