# Govern a LangGraph tool call and resume after operator review

This example runs a small LangGraph application through Cordum's existing
LangChain tools. It demonstrates an allowed call, a policy denial, and a
pending job that a separate Cordum operator can approve. No model provider,
cloud account, payment, or external business action is needed.

The important boundary is explicit: **resuming LangGraph does not approve a
Cordum job**. The graph submits once, checkpoints the pending job identifier,
and later observes that original job. Cordum owns the approval and dispatch
decision.

## Source and tested dependencies

Start in the `cordum-packs` repository root. The runnable application is
[`examples/langgraph_governance.py`](../../examples/langgraph_governance.py),
and its graph tests are in
[`tests/test_langgraph_demo.py`](../../tests/test_langgraph_demo.py).

The development run used Python 3.11.15 and 3.12.13 with these versions:

| Dependency | Version |
| --- | --- |
| LangGraph | 1.2.18 |
| langchain-core | 1.7.0 |
| Pydantic | 2.14.1 |
| httpx | 0.28.1 |
| pytest | 9.2.0 |

Use a fresh environment and the checked-out adapter code rather than assuming
the published package contains this example:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e "./integrations/agent-adapters[langchain]" \
  -r integrations/agent-adapters/examples/langgraph-requirements.txt
python -m pytest integrations/agent-adapters/tests/test_langgraph_demo.py -q
```

On PowerShell, activate with `.venv\Scripts\Activate.ps1`; write the install
command on one line instead of using Bash's backslash continuation. The
package declares Python >=3.10, but this walkthrough establishes the versions
above, not an exhaustive compatibility matrix.

## How the graph enforces the boundary

`build_graph(client, get_job)` discovers tools with `build_langchain_tools`.
The returned tools are native LangChain `BaseTool` instances. The `submit`
node selects a discovered name and invokes its tool with the request
arguments. Only calls routed through these generated tools reach this
Cordum bridge; unwrapped tools are outside this example's governance path.

The current packs bridge returns JSON text in the MCP result content. A
successful call becomes graph status `succeeded`. An MCP `isError: true`
result raises `McpToolError`; the graph examines the structured payload:

| Bridge payload | Graph behavior | Tool execution |
| --- | --- | --- |
| `state: DENIED` | Ends with `denied` | Must not occur |
| `state: APPROVAL_REQUIRED` with `job_id` | Saves the job ID and interrupts | Waits for Cordum approval |
| Other error | Propagates the error | Do not interpret as success |

The approval envelope is an observable pending outcome, not a reusable
approval token. The graph does not retry `tools/call` after approval. It reads
`GET /api/v1/jobs/{job_id}` for the original submitted job and reports that
job's eventual result.

Current Core can deny at submission, persist a denied job, and return HTTP
403. The bridge recovers that job only after verifying its stored state is
`DENIED`; an authentication error is not treated as a policy decision. Core
may store a synthetic denial result, so the live test checks the actual job
history for absence of scheduled, dispatched, and running transitions. A
successful bridge result contains the tool's return value under `output`.

Submission and interruption are separate nodes. LangGraph restarts an
interrupted node when it resumes, so placing submission before `interrupt()`
inside the same node could create another job. Here `submit` has completed
before `await_operator` interrupts. The checkpointer is `InMemorySaver`, and
the same `thread_id` is used for invocation and resume. Checkpoints disappear
when this process exits; this is a local demonstration, not crash recovery.

## Run against a disposable Cordum stack

The live exercise needs the gateway, scheduler, safety kernel, NATS, Redis,
and the `packs/mcp-bridge` worker. Installing the Python adapter alone does
not provide those services or the Go bridge binary. Use the
[disposable fixture](../../examples/langgraph_fixture/README.md)
accompanying the live tests; it runs a local transform workflow
with harmless inputs and separate ephemeral requester and operator keys.
Do not point the fixture or these tests at a shared tenant.

The fixture deliberately uses authenticated plaintext transport bound to
loopback for development. It changes no production authentication or TLS
configuration. Keep generated runtime credentials local and remove them
when the fixture stops.

The bridge's explicit `CORDUM_MCP_ALLOW_UNSIGNED=true` opt-in is limited
to loopback endpoints, `CORDUM_ENV=development`, and the CAP compatibility
profile. It is disabled by default. This fixture does not validate signed
CAP transport or the CAP production profile.

For a normally secured stack, the gateway URL must use HTTPS and its
certificate must be trusted by every client. In the currently inspected
bridge, setting `CORDUM_TLS_CA` does not configure its HTTPS trust store.
The example's `--ca-file` configures only its Python job observer, not the
Go bridge. Do not treat it as a bridge TLS fix or disable certificate
verification to make a secured stack work. A private-CA stack needs a
bridge trust configuration that has been independently verified.

You need Docker with Compose, Git, and the Go toolchain required by the
checked-out modules (Go 1.26.0 for this packs revision). Supply a clean,
isolated Core checkout; the fixture refuses a dirty one. The development
verification uses Core revision
`2bc671415a1eee49610dd2ca767f0a30501db382`. Build the bridge from this packs
checkout so the graph, adapter, and worker contracts match.

In a fresh PowerShell development shell, start from the packs root:

```powershell
$fixture = Join-Path $PWD 'integrations/agent-adapters/examples/langgraph_fixture'
New-Item -ItemType Directory -Force "$fixture/bin" | Out-Null
go build -C packs/mcp-bridge -o "$fixture/bin/cordum-mcp-bridge.exe" ./cmd/cordum-mcp-bridge
python "$fixture/stack.py" C:/path/to/clean/cordum-core
```

Keep that terminal open until the fixture prints `READY`. In another
terminal with the Python environment activated, run the real control-plane
tests from the packs root:

```powershell
$fixture = Join-Path $PWD 'integrations/agent-adapters/examples/langgraph_fixture'
$env:CORDUM_ADAPTERS_E2E = '1'
$env:CORDUM_LANGGRAPH_FIXTURE = "$fixture/runtime.json"
$env:CORDUM_MCP_BRIDGE = "$fixture/bin/cordum-mcp-bridge.exe"
python -m pytest integrations/agent-adapters/tests/integration/test_langgraph_live.py -q
```

On Unix, omit the executable's `.exe` suffix and use shell `export` syntax
for these three variables. The live tests load the runtime file without
printing its keys. They exercise allow, deny, separate operator approval,
and a changed resume payload against the real local control plane. A
skipped test is not evidence that a live scenario passed.

## Review a pending job yourself

The fixture policy allows `cordum.workflow.run`, denies
`cordum.workflow.cancel`, and requires approval for
`cordum.workflow.rerun`. To observe the approval interaction, open a fresh
development shell without inherited Cordum, NATS, or Redis settings. Load
the fixture's requester environment and invoke a harmless rerun:

```powershell
$fixture = Join-Path $PWD 'integrations/agent-adapters/examples/langgraph_fixture'
$cfg = Get-Content "$fixture/runtime.json" -Raw | ConvertFrom-Json
$env:CORDUM_GATEWAY_URL = $cfg.gateway_url
$env:CORDUM_API_KEY = $cfg.requester_api_key
$env:CORDUM_TENANT_ID = $cfg.tenant_id
$env:CORDUM_NATS_URL = $cfg.nats_url
$env:CORDUM_REDIS_URL = $cfg.redis_url
$env:CORDUM_ENV = 'development'
$env:CORDUM_CAP_PROFILE = 'compat'
$env:CORDUM_MCP_ALLOW_UNSIGNED = 'true'
$arguments = @{ run_id = $cfg.source_run_id; from_step = 'echo' } | ConvertTo-Json -Compress
python integrations/agent-adapters/examples/langgraph_governance.py `
  --bridge "$fixture/bin/cordum-mcp-bridge.exe" `
  --tool cordum.workflow.rerun --arguments $arguments
```

The application prints the pending job ID, tool, and arguments. Review and
approve that stored job with the fixture's second key in another terminal:

```powershell
$fixture = Join-Path $PWD 'integrations/agent-adapters/examples/langgraph_fixture'
$cfg = Get-Content "$fixture/runtime.json" -Raw | ConvertFrom-Json
$jobId = Read-Host 'Job ID printed by the graph'
$headers = @{ 'X-API-Key' = $cfg.approver_api_key; 'X-Tenant-ID' = $cfg.tenant_id }
Invoke-RestMethod -Method Post -Uri "$($cfg.gateway_url)/api/v1/approvals/$jobId/approve" `
  -Headers $headers -ContentType 'application/json' `
  -Body '{"reason":"Reviewed harmless local transform rerun"}' | Out-Null
```

Then press Enter in the application. Enter supplies an acknowledgement through
`Command(resume=pending)`; it conveys no approval authority. If the job is
still pending approval, the graph interrupts again. After an approved job
has completed, the graph reports the original job result without submitting
another tool call.

Press Ctrl+C in the fixture terminal when finished. It stops its own child
services and Compose project and deletes its generated runtime credentials.
It does not use persistent Docker volumes.

## Changed inputs and the scope of the evidence

The graph records a SHA-256 digest of its initial tool name and JSON
arguments. On resume it requires the acknowledgement to match the pending
job ID, tool, and arguments, and checks the stored request digest. A changed
acknowledgement or changed graph arguments ends with `rejected_input`
before reading the job or submitting another call.

This is an application invariant inside a trusted checkpoint boundary. It
does not establish a Cordum replay token or cryptographically bind arbitrary
future tool calls to an approval. A caller able to rewrite both checkpoint
arguments and their digest is outside this check's protection. Editing a
request requires a new governed request and a fresh policy decision.

The original approved job may already have executed when a changed resume
payload is rejected. That rejection prevents the application from accepting
the changed payload or submitting it as a new call; it does not undo the
original approved action.

The ten graph tests use real LangGraph and native LangChain tools with a
fake Cordum transport. They cover allow, deny without execution, approval
observation without resubmission, resume without approval, changed tool,
arguments, job ID or graph state, and an unknown tool. They establish graph
behavior; they do not alone establish live Core enforcement. The separate
live tests inspect actual job state and local workflow results. They also
check that a pending job has no worker result, requester self-approval is
refused, and approval leads to the original job succeeding. Consult the
recorded test output for the checked-out revision before making an
end-to-end claim.

## Sharing the example

Frame this as an educational application about governing tool execution.
LangChain's [co-marketing guidance](https://docs.langchain.com/oss/python/contributing/comarketing)
favors complete LangGraph applications, including human interaction
patterns. A separate tools listing may be appropriate after the runnable
example and evidence are public: the
[integration guidance](https://docs.langchain.com/oss/python/contributing/integrations-langchain)
encourages tools and middleware and discourages generic adapters. File an
Integration listing issue for a published package under the
[publishing rules](https://docs.langchain.com/oss/python/contributing/publish-langchain),
rather than a manual docs PR. A LangChain-hosted guide requires 50,000
monthly downloads or maintainer-featured status; this example asserts
neither.
