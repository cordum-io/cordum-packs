"""Disposable real Cordum development stack. No external tools or persistent volumes.

Run: python stack.py /absolute/path/to/cordum-core
Keep running while the demo/tests use runtime.json. Ctrl+C removes the stack.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

HERE = Path(__file__).resolve().parent
BIN = HERE / "bin"
FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def write_private_json(path: Path, payload: dict) -> None:
    """Create a secret-bearing runtime file exclusively with owner-only mode."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(payload, output, indent=2)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("core_source", type=Path, help="clean isolated Cordum Core checkout")
    source = parser.parse_args().core_source.resolve()
    if not (source / "go.mod").is_file():
        raise SystemExit("Pass an isolated Cordum core checkout")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True).strip():
        raise SystemExit("Use a clean isolated Core checkout for reproducible evidence")
    lock_path = HERE / ".running"
    try:
        with lock_path.open("x", encoding="utf-8") as lock:
            lock.write(str(os.getpid()))
    except FileExistsError:
        raise SystemExit("A fixture owns this directory (.running exists); stop it before starting another") from None
    try:
        if (HERE / "runtime.json").exists() or (HERE / "compose.runtime.json").exists():
            raise SystemExit("Existing runtime files found; inspect the prior fixture before starting another")
        serve(source, revision)
    finally:
        lock_path.unlink(missing_ok=True)


def serve(source: Path, revision: str) -> None:
    BIN.mkdir(exist_ok=True)
    requester, approver, redis_pass, nats_token = [secrets.token_hex(24) for _ in range(4)]
    project = f"cordum-langgraph-{os.getpid()}-{secrets.token_hex(4)}"
    compose = HERE / "compose.runtime.json"
    runtime_path = HERE / "runtime.json"
    nats_port, redis_port, gateway_port = 14222, 16379, 18081
    compose_config = {"services": {
        "nats": {
            "image": "nats@sha256:5498ba57b9471840be3d15b033a4eec554d1c02fa6c2cc0ca2d888637f6c6e2f",
            "command": ["-js", "--auth", nats_token, "-sd", "/data"],
            "ports": [f"127.0.0.1:{nats_port}:4222"],
            "tmpfs": ["/data"],
        },
        "redis": {
            "image": "redis@sha256:bd28fff4b665fdf1b73e8b5b73ec05d2f858f4fa3c8ea0d7c9bc09f7f6bf7039",
            "command": ["redis-server", "--save", "", "--appendonly", "no", "--requirepass", redis_pass],
            "ports": [f"127.0.0.1:{redis_port}:6379"],
            "tmpfs": ["/data"],
        },
    }}
    dc = ["docker", "compose", "-p", project, "-f", str(compose)]
    env = os.environ.copy()
    # Remove inherited production/TLS settings; these binaries run in an isolated
    # development fixture on loopback. Production code/configuration is untouched.
    for key in list(env):
        if key.startswith(("CORDUM_", "NATS_", "REDIS_", "SAFETY_KERNEL_", "GATEWAY_", "GRPC_TLS_", "CONTEXT_ENGINE_")):
            del env[key]
    env.update({
        "CORDUM_ENV": "development", "CORDUM_PRODUCTION": "false",
        "CORDUM_CAP_PROFILE": "compat", "CORDUM_TELEMETRY_MODE": "off",
        "CORDUM_SDK_HANDSHAKE": "off", "CORDUM_HEARTBEAT_MODE": "authority",
        "NATS_URL": f"nats://{nats_token}@127.0.0.1:{nats_port}",
        "NATS_USE_JETSTREAM": "1",
        "REDIS_URL": f"redis://:{redis_pass}@127.0.0.1:{redis_port}",
        "SAFETY_KERNEL_ADDR": "127.0.0.1:15051",
        "SAFETY_KERNEL_ADMIN_ADDR": "127.0.0.1:19095",
        "SAFETY_POLICY_PATH": str(HERE / "safety.yaml"),
        "POOL_CONFIG_PATH": str(HERE / "pools.yaml"),
        "TIMEOUT_CONFIG_PATH": str(HERE / "timeouts.yaml"),
        "CORDUM_POLICY_STRICT": "off", "POLICY_CHECK_FAIL_MODE": "closed",
        "OUTPUT_POLICY_ENABLED": "false", "TENANT_ID": "default",
        "CORDUM_API_KEY": requester, "CORDUM_API_KEYS": requester + "," + approver,
        "GATEWAY_HTTP_ADDR": f"127.0.0.1:{gateway_port}",
        "GATEWAY_GRPC_ADDR": "127.0.0.1:18080",
        "GATEWAY_METRICS_ADDR": "127.0.0.1:19092",
        "SCHEDULER_METRICS_ADDR": "127.0.0.1:19090",
    })
    services = ["cordum-safety-kernel", "cordum-scheduler", "cordum-api-gateway"]
    processes, logs, created_files = [], [], []
    # The endpoint is loopback-only. Never forward ephemeral API keys through
    # an HTTP_PROXY/HTTPS_PROXY inherited from the operator's environment.
    http = build_opener(ProxyHandler({}))
    try:
        write_private_json(compose, compose_config)
        created_files.append(compose)
        ldflags = f"-X github.com/cordum/cordum/core/infra/buildinfo.Commit={revision}"
        subprocess.run(["go", "build", "-ldflags", ldflags, "-o", str(BIN) + os.sep, *[f"./cmd/{s}" for s in services]], cwd=source, check=True)
        subprocess.run(dc + ["up", "-d"], check=True)
        for service in services:
            log = (HERE / f"{service}.log").open("w", encoding="utf-8")
            logs.append(log)
            exe = BIN / (service + (".exe" if os.name == "nt" else ""))
            processes.append(subprocess.Popen([str(exe)], cwd=source, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, creationflags=FLAGS))
            time.sleep(1)
        base = f"http://127.0.0.1:{gateway_port}"
        headers = {"X-API-Key": requester, "X-Tenant-ID": "default", "Content-Type": "application/json"}
        deadline = time.monotonic() + 60
        while True:
            if any(p.poll() is not None for p in processes):
                raise RuntimeError("Core service exited; inspect fixture logs")
            try:
                with http.open(Request(base + "/readyz", headers=headers), timeout=2) as response:
                    if response.status == 200:
                        break
            except (URLError, TimeoutError):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("Gateway not ready within 60 seconds")
            time.sleep(0.3)
        workflow_id = "langgraph-local-transform"
        # Routing wildcards do not register exact topics for submission. Keep
        # topic enforcement enabled and register the real bridge topic.
        topic = {"name": "job.mcp-bridge.tool", "pool": "mcp-bridge", "pack_id": "mcp-bridge",
                 "requires": ["network:egress"], "risk_tags": ["write", "network"], "status": "active"}
        with http.open(Request(base + "/api/v1/topics", data=json.dumps(topic).encode(), headers=headers, method="POST"), timeout=10) as response:
            response.read()
        workflow = {"id": workflow_id, "org_id": "default", "name": "LangGraph local transform", "steps": {
            "echo": {"id": "echo", "type": "transform", "input": {"greeting": "Hello ${ input.name }"}},
        }}
        with http.open(Request(base + "/api/v1/workflows", data=json.dumps(workflow).encode(), headers=headers, method="POST"), timeout=10) as response:
            response.read()
        # Seed a synchronous harmless transform run so approval can exercise
        # cordum.workflow.rerun without any external worker or side effect.
        with http.open(Request(base + f"/api/v1/workflows/{workflow_id}/runs", data=json.dumps({"name": "seed"}).encode(), headers=headers, method="POST"), timeout=10) as response:
            source_run_id = json.load(response)["run_id"]
        runtime = {
            "gateway_url": base, "requester_api_key": requester, "approver_api_key": approver,
            "tenant_id": "default", "nats_url": env["NATS_URL"], "redis_url": env["REDIS_URL"],
            "workflow_id": workflow_id, "source_run_id": source_run_id,
            "core_revision": revision, "project": project,
            "go_version": subprocess.check_output(["go", "version"], cwd=source, text=True).strip(),
            "python_version": sys.version.split()[0],
        }
        write_private_json(runtime_path, runtime)
        created_files.append(runtime_path)
        print(f"READY: {runtime_path} (ephemeral credentials; do not commit)", flush=True)
        while True:
            if any(p.poll() is not None for p in processes):
                raise RuntimeError("Core service exited; inspect fixture logs")
            time.sleep(1)
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        for log in logs:
            log.close()
        if compose in created_files:
            subprocess.run(dc + ["down", "--remove-orphans"], check=False)
        for path in reversed(created_files):
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
