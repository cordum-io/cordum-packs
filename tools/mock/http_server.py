#!/usr/bin/env python3
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

DEFAULT_BODY = {"ok": True}


def build_body(service: str, path: str):
    if service == "prometheus":
        return {
            "status": "success",
            "data": {"resultType": "vector", "result": []},
            "warnings": [],
        }
    if service == "slack":
        return {"ok": True}
    return dict(DEFAULT_BODY)


class MockHandler(BaseHTTPRequestHandler):
    server_version = "cordum-mock-http/0.1"

    def _handle(self):
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        parts = [p for p in path.split("/") if p]
        service = parts[0] if parts else ""
        body = build_body(service, path)

        payload = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_PATCH(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def log_message(self, fmt, *args):
        if getattr(self.server, "quiet", False):
            return
        super().log_message(fmt, *args)


def main():
    parser = argparse.ArgumentParser(description="Cordum mock HTTP server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    httpd = HTTPServer((args.host, args.port), MockHandler)
    httpd.quiet = args.quiet
    print(f"mock http listening on http://{args.host}:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
