# Disposable real control plane for the LangGraph demo

This fixture runs the actual Cordum Safety Kernel, Scheduler, and Gateway
from a clean isolated Core checkout. NATS and Redis run in temporary Docker
containers with digest-pinned images, random authentication secrets, loopback
ports, and memory-backed data. It seeds a built-in transform workflow, which
has no network, shell, money, or customer-data side effects.

Prerequisites: Python 3.11+, Go matching Core's `go.mod` toolchain, Git, and a
running Docker engine with Compose. Allow local loopback connections and
subprocess execution. Core's modules must be in the Go cache or downloadable.
Run one instance per fixture directory.
An atomic `.running` lock and existing runtime-file check prevent concurrent
starts from overwriting credentials. If a run is forcibly killed, inspect its
recorded Compose project and child processes before manually removing stale
runtime files and the lock. Local HTTP requests explicitly ignore proxy
environment settings so temporary API keys remain on loopback.

```powershell
python stack.py C:/path/to/clean/cordum-core
```

Keep the process running while using `runtime.json` in the demo/test process.
The file holds temporary requester and approver keys and the fixture's URLs.
Never commit or share it. Press Ctrl+C when finished; the fixture terminates
only its child processes and its own Compose project, then removes the
runtime configuration. It does not use persistent Docker volumes.
Runtime credential files are created exclusively with Unix mode `0600`;
Windows uses the current user's inherited directory ACL. They are never
overwritten, and cleanup removes only files created by this invocation.

The script invokes this build from the supplied clean Core checkout, using
its exact commit as `<revision>` and an absolute fixture output directory:

```text
go build -ldflags "-X github.com/cordum/cordum/core/infra/buildinfo.Commit=<revision>" -o <fixture>/bin/ ./cmd/cordum-safety-kernel ./cmd/cordum-scheduler ./cmd/cordum-api-gateway
```

This fixture deliberately uses Cordum's **development, CAP compatibility**
profile, with HTTP/NATS/Redis over loopback. It does not establish production
TLS, signed CAP, worker attestation, or deployment security. Production must
retain TLS and authenticated service/worker identities. The packs MCP bridge
HTTP client currently uses the operating system certificate trust store and
does not consume `CORDUM_TLS_CA`.

The demo's bridge subprocess must explicitly select `CORDUM_ENV=development`,
`CORDUM_CAP_PROFILE=compat`, and `CORDUM_MCP_ALLOW_UNSIGNED=true` for this local
fixture. The unsigned bridge option defaults to false and is accepted only
with development mode, compatibility profile, and loopback endpoints
(`localhost` or a literal loopback IP).
It is unsuitable for shared or production infrastructure.

The policy allows `cordum.workflow.run`, denies `cordum.workflow.cancel`, and
requires a second API key to approve `cordum.workflow.rerun`. Every bridge
action still becomes a real CAP job and passes through the real Safety Kernel
before worker dispatch. The Gateway persists a denied job and rejects its
submission with HTTP 403; admitted jobs also pass through Scheduler. Each rule includes
an exact `match.mcp.allow_tools` matcher so Core's MCP policy scope selects it;
the `decision` field determines allow, deny, or approval. A capability-only
rule belongs to the job input scope and is not selected for MCP-labeled calls.
The fixture registers exact topic `job.mcp-bridge.tool` through the topic API;
the routing configuration alone does not register it.

The harmless transform workflow executes
inside Gateway's embedded workflow engine, so no separate workflow service or
external integration worker is needed. The bridge itself is the real pack
worker for `job.mcp-bridge.tool`.

The default test ports are 127.0.0.1:14222 (NATS), :16379 (Redis), :15051
(kernel gRPC), :18081 (gateway HTTP), :18080 (gateway gRPC), :19090
(scheduler metrics), :19092 (gateway metrics), and :19095 (kernel readiness).
Startup fails if a required port is already occupied; it does not stop
preexisting processes.

The October 28 2026 local verification used clean Core revision
`2bc671415a1eee49610dd2ca767f0a30501db382`. Cached `latest` Cordum service
images were not used: they pointed at older July code. Build metadata records
the supplied source revision on subsequent starts.

Tags: LangGraph, local development, governance, human approval, E2E testing.
