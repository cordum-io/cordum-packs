#!/usr/bin/env python3
import json
import sys

DEFAULT_PROTOCOL = "2025-11-25"


def write_response(resp):
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()


def handle_request(req):
    req_id = req.get("id")
    if req_id is None:
        return
    method = req.get("method", "")
    params = req.get("params") or {}

    if method == "initialize":
        protocol = params.get("protocolVersion") or DEFAULT_PROTOCOL
        result = {
            "protocolVersion": protocol,
            "serverInfo": {"name": "mock-mcp", "version": "0.0.1"},
            "capabilities": {"tools": {}, "resources": {}},
        }
        write_response({"jsonrpc": "2.0", "id": req_id, "result": result})
        return

    if method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "mock.echo",
                    "description": "Mock tool that echoes input.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                    },
                }
            ]
        }
        write_response({"jsonrpc": "2.0", "id": req_id, "result": result})
        return

    if method == "tools/call":
        result = {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({"ok": True, "input": params}),
                }
            ]
        }
        write_response({"jsonrpc": "2.0", "id": req_id, "result": result})
        return

    if method == "resources/list":
        write_response({"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}})
        return

    if method == "resources/read":
        result = {
            "contents": [
                {"uri": params.get("uri", ""), "mimeType": "application/json", "text": "{}"}
            ]
        }
        write_response({"jsonrpc": "2.0", "id": req_id, "result": result})
        return

    write_response({
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    })


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        handle_request(req)


if __name__ == "__main__":
    main()
