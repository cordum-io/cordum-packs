"""Entry point for `python -m cordum_langchain_sidecar`."""
from __future__ import annotations

import argparse
import os
import sys

# Add parent paths so the sidecar template and agent adapters are importable
# when running outside a pip-installed environment.
_sidecar_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_integrations = os.path.normpath(os.path.join(_sidecar_root, "..", "..", "..", "integrations"))
for _path in [
    os.path.join(_integrations, "sidecar-template", "python"),
    os.path.join(_integrations, "agent-adapters"),
    _sidecar_root,
]:
    if _path not in sys.path:
        sys.path.insert(0, _path)

from server import create_app  # noqa: E402 — sidecar template server
from cordum_langchain_sidecar.executor import LangChainExecutor  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Cordum LangChain sidecar")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.getenv("CORDUM_SIDECAR_PORT", "8000")))
    args = parser.parse_args()

    app = create_app(executor=LangChainExecutor())
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
