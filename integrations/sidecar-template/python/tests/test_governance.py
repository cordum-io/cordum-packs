from __future__ import annotations

import json
import pathlib
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from governance import (  # noqa: E402
    GovernanceDeniedError,
    GovernanceTimeoutError,
    GovernedTool,
)


class CallbackHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8"))
        response = self.server.behavior(payload)  # type: ignore[attr-defined]
        self.send_response(response.get("status_code", 200))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            self.wfile.write(json.dumps(response["body"]).encode("utf-8"))
        except (BrokenPipeError, ConnectionAbortedError):
            return

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


class CallbackServer:
    def __init__(self, behavior):
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), CallbackHandler)
        self._server.behavior = behavior
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def callback_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


class GovernedToolTests(unittest.TestCase):
    def test_approved_tool_call_returns_result(self) -> None:
        server = CallbackServer(
            lambda payload: {
                "body": {
                    "approved": True,
                    "result": {"echo": payload["arguments"]},
                    "status": "succeeded",
                }
            }
        )
        server.start()
        self.addCleanup(server.close)

        tool = GovernedTool(tool_name="search.docs", callback_url=server.callback_url, timeout_seconds=1)
        result = tool.invoke({"query": "cordum"})

        self.assertEqual({"echo": {"query": "cordum"}}, result)

    def test_denied_tool_call_raises_error(self) -> None:
        server = CallbackServer(
            lambda payload: {
                "body": {
                    "approved": False,
                    "error": f"{payload['tool_name']} denied",
                    "status": "denied",
                }
            }
        )
        server.start()
        self.addCleanup(server.close)

        tool = GovernedTool(tool_name="deploy.prod", callback_url=server.callback_url, timeout_seconds=1)
        with self.assertRaises(GovernanceDeniedError):
            tool.invoke({"environment": "prod"})

    def test_callback_timeout_raises_timeout_error(self) -> None:
        def delayed_response(payload):
            del payload
            time.sleep(0.2)
            return {"body": {"approved": True, "result": {"late": True}, "status": "succeeded"}}

        server = CallbackServer(delayed_response)
        server.start()
        self.addCleanup(server.close)

        tool = GovernedTool(tool_name="slow.tool", callback_url=server.callback_url, timeout_seconds=0.05)
        with self.assertRaises(GovernanceTimeoutError):
            tool.invoke({"value": 1})

    def test_concurrent_tool_calls(self) -> None:
        server = CallbackServer(
            lambda payload: {
                "body": {
                    "approved": True,
                    "result": {
                        "index": payload["arguments"]["index"],
                        "trace_id": payload["trace_id"],
                    },
                    "status": "succeeded",
                }
            }
        )
        server.start()
        self.addCleanup(server.close)

        tool = GovernedTool(tool_name="concurrent.tool", callback_url=server.callback_url, timeout_seconds=1)

        def run(index: int):
            return tool.invoke({"index": index})

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(run, range(8)))

        self.assertEqual({item["index"] for item in results}, set(range(8)))
        for item in results:
            self.assertTrue(item["trace_id"])


if __name__ == "__main__":
    unittest.main()
