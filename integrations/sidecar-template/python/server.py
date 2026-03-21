from __future__ import annotations

import argparse
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping, Protocol


class Executor(Protocol):
    def execute(
        self,
        *,
        action: str,
        config: dict[str, Any],
        payload: Any,
        callback_url: str,
    ) -> Any: ...


@dataclass(slots=True)
class ExecuteRequest:
    action: str
    config: dict[str, Any]
    payload: Any
    callback_url: str


class TemplateExecutor:
    """Default placeholder executor for copied framework packs."""

    def execute(
        self,
        *,
        action: str,
        config: dict[str, Any],
        payload: Any,
        callback_url: str,
    ) -> Any:
        raise NotImplementedError(
            "TemplateExecutor.execute must be replaced by the framework-specific pack"
        )


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in ("event", "trace_id", "action", "path", "status_code"):
            value = getattr(record, field, None)
            if value not in (None, ""):
                payload[field] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def build_logger() -> logging.Logger:
    logger = logging.getLogger("cordum.sidecar")
    if logger.handlers:
        return logger

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(os.getenv("CORDUM_SIDECAR_LOG_LEVEL", "INFO").upper())
    logger.propagate = False
    return logger


def create_app(executor: Executor | None = None):
    try:
        from flask import Flask, jsonify, request
        from werkzeug.exceptions import HTTPException
    except ImportError as exc:  # pragma: no cover - environment-specific
        raise RuntimeError(
            "flask is required for the sidecar template. Install it in the pack image."
        ) from exc

    app = Flask(__name__)
    app.config["EXECUTOR"] = executor or TemplateExecutor()
    app.config["LOGGER"] = build_logger()
    app.config["SHUTDOWN_EVENT"] = threading.Event()

    logger: logging.Logger = app.config["LOGGER"]

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.post("/execute")
    def execute():
        payload = request.get_json(silent=False)
        execute_request = parse_execute_request(payload)

        logger.info(
            "sidecar execute request",
            extra={
                "event": "execute_request",
                "action": execute_request.action,
                "trace_id": request.headers.get("X-Trace-ID", ""),
                "path": request.path,
            },
        )

        result = app.config["EXECUTOR"].execute(
            action=execute_request.action,
            config=execute_request.config,
            payload=execute_request.payload,
            callback_url=execute_request.callback_url,
        )
        return jsonify({"ok": True, "result": result})

    @app.post("/shutdown")
    def shutdown():
        app.config["SHUTDOWN_EVENT"].set()
        logger.info(
            "sidecar shutdown requested",
            extra={"event": "shutdown_request", "path": request.path},
        )

        shutdown_func = request.environ.get("werkzeug.server.shutdown")
        if callable(shutdown_func):
            shutdown_func()

        return jsonify({"status": "shutting_down"})

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        logger.warning(
            "sidecar http error",
            extra={
                "event": "http_error",
                "path": request.path,
                "status_code": error.code or 500,
            },
        )
        return (
            jsonify(
                {
                    "ok": False,
                    "error": {
                        "type": error.__class__.__name__,
                        "message": error.description,
                    },
                }
            ),
            error.code or 500,
        )

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        status_code = 501 if isinstance(error, NotImplementedError) else 500
        logger.exception(
            "sidecar unhandled exception",
            extra={
                "event": "unhandled_exception",
                "path": request.path,
                "status_code": status_code,
            },
        )
        return (
            jsonify(
                {
                    "ok": False,
                    "error": {
                        "type": error.__class__.__name__,
                        "message": str(error),
                    },
                }
            ),
            status_code,
        )

    return app


def parse_execute_request(payload: Any) -> ExecuteRequest:
    if not isinstance(payload, Mapping):
        raise ValueError("request body must be a JSON object")

    action = str(payload.get("action", "")).strip()
    if not action:
        raise ValueError("action is required")

    config = payload.get("config") or {}
    if not isinstance(config, Mapping):
        raise ValueError("config must be an object")

    callback_url = str(payload.get("callback_url") or os.getenv("CORDUM_CALLBACK_URL", "")).strip()
    if not callback_url:
        raise ValueError("callback_url is required")

    return ExecuteRequest(
        action=action,
        config=dict(config),
        payload=payload.get("input"),
        callback_url=callback_url,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Cordum Python sidecar template server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.getenv("CORDUM_SIDECAR_PORT", "8000")))
    args = parser.parse_args()

    app = create_app()
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
