"""Entry point for `python -m cordum_llamaindex_sidecar`."""
from __future__ import annotations

import argparse
import os
import sys

_sidecar_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_integrations = os.path.normpath(os.path.join(_sidecar_root, "..", "..", "..", "integrations"))
for _path in [
    os.path.join(_integrations, "sidecar-template", "python"),
    _sidecar_root,
]:
    if _path not in sys.path:
        sys.path.insert(0, _path)

from server import create_app  # noqa: E402
from cordum_llamaindex_sidecar.executor import LlamaIndexExecutor  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Cordum LlamaIndex sidecar")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.getenv("CORDUM_SIDECAR_PORT", "8000")))
    args = parser.parse_args()

    app = create_app(executor=LlamaIndexExecutor())
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
