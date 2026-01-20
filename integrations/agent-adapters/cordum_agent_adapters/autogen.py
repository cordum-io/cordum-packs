from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Tuple

from .mcp_client import McpStdioClient
from .openai_tools import mcp_tool_to_openai_tool, mcp_tools_to_openai_tools


def _coerce_args(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
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


def build_autogen_tools(
    client: McpStdioClient,
    tools: Optional[List[Dict[str, Any]]] = None,
    result_transform: Optional[Callable[[Dict[str, Any]], Any]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Callable[..., Any]]]:
    tool_defs = tools or client.list_tools()
    functions: List[Dict[str, Any]] = []
    function_map: Dict[str, Callable[..., Any]] = {}

    for tool in tool_defs:
        name = tool.get("name", "")
        openai_tool = mcp_tool_to_openai_tool(tool)
        functions.append(openai_tool["function"])
        tool_name = name

        def _call(*args: Any, **kwargs: Any) -> Any:
            payload = _coerce_args(args, kwargs)
            result = client.call_tool(tool_name, payload)
            if result_transform:
                return result_transform(result)
            return result

        function_map[tool_name] = _call

    return functions, function_map


def build_autogen_openai_tools(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return mcp_tools_to_openai_tools(tools)
