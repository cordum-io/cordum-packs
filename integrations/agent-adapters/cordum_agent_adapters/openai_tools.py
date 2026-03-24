from __future__ import annotations

import copy
from typing import Any, Dict, List


def mcp_tool_to_openai_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an MCP tool definition to the OpenAI function-calling schema format."""
    schema = copy.deepcopy(tool.get("inputSchema") or {})
    if not isinstance(schema, dict):
        schema = {}
    if "type" not in schema:
        schema["type"] = "object"
    if "properties" not in schema:
        schema["properties"] = {}

    return {
        "type": "function",
        "function": {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "parameters": schema,
        },
    }


def mcp_tools_to_openai_tools(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert a list of MCP tool definitions to the OpenAI function-calling format."""
    return [mcp_tool_to_openai_tool(tool) for tool in tools]
