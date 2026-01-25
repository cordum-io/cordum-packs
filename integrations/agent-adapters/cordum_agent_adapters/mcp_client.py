from __future__ import annotations

import json
import queue
import shlex
import subprocess
import threading
import time
import sys
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


class McpError(Exception):
    pass


@dataclass
class McpRpcError(McpError):
    code: int
    message: str
    data: Any = None

    def __str__(self) -> str:
        return f"mcp rpc error {self.code}: {self.message}"


@dataclass
class McpToolError(McpError):
    message: str
    result: Dict[str, Any]

    def __str__(self) -> str:
        return self.message


class McpStdioClient:
    def __init__(
        self,
        command: Iterable[str] | str,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        timeout: float = 60.0,
        protocol_version: str = "2025-11-25",
        client_name: str = "cordum-agent-adapters",
        client_version: str = "0.1.0",
        auto_initialize: bool = True,
    ) -> None:
        self.command = self._normalize_command(command)
        self.env = env
        self.cwd = cwd
        self.timeout = timeout
        self.protocol_version = protocol_version
        self.client_name = client_name
        self.client_version = client_version
        self._write_lock = threading.Lock()
        self._read_queue: queue.Queue[dict] = queue.Queue()
        self._pending: Dict[Any, dict] = {}
        self._next_id = 1

        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=self.env,
            cwd=self.cwd,
        )

        if self._proc.stdin is None or self._proc.stdout is None:
            raise McpError("failed to open stdio pipes")

        self._stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_thread.start()

        self._initialized = False
        if auto_initialize:
            self.initialize()

    def initialize(self) -> dict:
        if self._initialized:
            return {}
        params = {
            "protocolVersion": self.protocol_version,
            "clientInfo": {"name": self.client_name, "version": self.client_version},
        }
        result = self._request("initialize", params)
        self._notify("notifications/initialized", {})
        self._initialized = True
        return result

    def list_tools(self) -> List[dict]:
        tools: List[dict] = []
        cursor = ""
        while True:
            params = {"cursor": cursor} if cursor else None
            result = self._request("tools/list", params)
            if isinstance(result, dict):
                tools.extend(result.get("tools", []) or [])
                cursor = result.get("nextCursor") or ""
            else:
                cursor = ""
            if not cursor:
                break
        return tools

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> dict:
        params = {"name": name, "arguments": arguments or {}}
        result = self._request("tools/call", params)
        if isinstance(result, dict) and result.get("isError"):
            raise McpToolError(f"tool call failed: {name}", result)
        if not isinstance(result, dict):
            return {"content": result}
        return result

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def _normalize_command(self, command: Iterable[str] | str) -> List[str]:
        if isinstance(command, str):
            return shlex.split(command)
        return list(command)

    def _notify(self, method: str, params: Optional[dict]) -> None:
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload)

    def _request(self, method: str, params: Optional[dict]) -> dict:
        request_id = self._next_request_id()
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload)
        return self._wait_for_response(request_id)

    def _send(self, payload: dict) -> None:
        data = json.dumps(payload)
        with self._write_lock:
            assert self._proc.stdin is not None
            self._proc.stdin.write(data + "\n")
            self._proc.stdin.flush()

    def _wait_for_response(self, request_id: int) -> dict:
        if request_id in self._pending:
            return self._resolve_response(self._pending.pop(request_id))

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                message = self._read_queue.get(timeout=remaining)
            except queue.Empty:
                break
            message_id = message.get("id")
            if message_id == request_id:
                return self._resolve_response(message)
            if message_id is not None:
                self._pending[message_id] = message
        raise McpError(f"timeout waiting for response to {request_id}")

    def _resolve_response(self, message: dict) -> dict:
        if message.get("error"):
            err = message["error"]
            raise McpRpcError(err.get("code"), err.get("message", "unknown"), err.get("data"))
        return message.get("result", {})

    def _next_request_id(self) -> int:
        request_id = self._next_id
        self._next_id += 1
        return request_id

    def _read_stdout(self) -> None:
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict):
                self._read_queue.put(message)

    def _read_stderr(self) -> None:
        if self._proc.stderr is None:
            return
        for line in self._proc.stderr:
            if line:
                # Preserve stderr output for debugging.
                print(line.rstrip(), file=sys.stderr, flush=True)
