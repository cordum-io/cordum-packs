from __future__ import annotations

import asyncio
import json
import queue
import shlex
import subprocess
import threading
import time
import sys
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Dict, Iterable, List, Optional, Type


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
        client_name: str = "cordum-adapters",
        client_version: str = "0.2.0",
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
        """Send the MCP ``initialize`` handshake and mark the client as ready."""
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
        """Return all tools advertised by the MCP server, handling cursor pagination."""
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
        """Invoke a tool by name. Raises :class:`McpToolError` if the server signals an error."""
        params = {"name": name, "arguments": arguments or {}}
        result = self._request("tools/call", params)
        if isinstance(result, dict) and result.get("isError"):
            raise McpToolError(f"tool call failed: {name}", result)
        if not isinstance(result, dict):
            return {"content": result}
        return result

    def close(self) -> None:
        """Terminate the MCP server subprocess."""
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    # ------------------------------------------------------------------
    # Async façade
    #
    # We delegate to the synchronous methods via run_in_executor rather
    # than rewriting the stdio reader as an asyncio protocol. Rationale:
    # the existing client already serialises on a single reader thread +
    # queue, which is race-free. Re-implementing that in asyncio would
    # mean another correctness review for a marginal latency win. Every
    # framework we target (CrewAI, AutoGen) is happy with a coroutine
    # that awaits a thread.
    # ------------------------------------------------------------------

    async def call_tool_async(
        self, name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> dict:
        """Async wrapper over :meth:`call_tool`.

        Exceptions raised by the sync call propagate unchanged so
        :func:`retry_call_async` can introspect them the same way it
        does for sync calls.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.call_tool, name, arguments)

    async def list_tools_async(self) -> List[dict]:
        """Async wrapper over :meth:`list_tools`."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.list_tools)

    def is_alive(self) -> bool:
        """Return True when the subprocess is still running.

        Callers use this to decide whether to reconnect before the next
        call; polling is cheap (one non-blocking syscall per call).
        """
        return self._proc.poll() is None

    # Context-manager protocol. Covers both sync `with client:` and async
    # `async with client:` usage. Close() is idempotent so double-exit is
    # harmless.
    def __enter__(self) -> "McpStdioClient":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    async def __aenter__(self) -> "McpStdioClient":
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        # close() is subprocess work — offload to a thread so the event
        # loop keeps running if the child hangs and needs the 5s timeout.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.close)

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
