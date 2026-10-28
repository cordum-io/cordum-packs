# CrewAI tools with Cordum allow, deny, and human approval

This runnable example uses actual CrewAI `BaseTool` objects created by the
existing `build_crewai_tools` adapter. It invokes a harmless local workflow
through the real packs MCP bridge, Gateway, Safety Kernel, and Scheduler.
No model provider, account, API credit, or external integration is needed.
CrewAI's native `tool.run(**arguments)` validates keyword arguments against
the generated Pydantic schema before the tool runs.

This change is stacked on **unmerged [PR418](https://github.com/cordum-io/cordum-packs/pull/418)**,
whose tested head is `f769393432e371b90734007491a4fb6b2b8ddb4b`.
That work supplies runtime signing compatibility, submit-time denial envelope
handling, and the disposable fixture reused here. Until merged, install from
this source branch; a released `cordum-adapters[crewai]` package alone is not
the verified complete setup.

## Reproduce locally

Prerequisites: Python 3.12, Git, Go matching current Core's toolchain, Docker
with Compose, and a clean isolated [Core](https://github.com/cordum-io/cordum)
checkout. The October 28 2026 verification used Core
`ebc0dd6ad210a95518efb2d7293a24fb0c1c6080`, Python 3.12.13,
Go 1.26.5 for Core, CrewAI/crewai-tools 1.15.32, and Pydantic 2.12.5.
The complete resolved dependency set is in
[`examples/crewai-requirements.txt`](../examples/crewai-requirements.txt).

From this repository root in PowerShell:

```powershell
# Use a Python 3.12 executable here (check `python --version` first).
python -m venv .venv-crewai
$python = (Resolve-Path .venv-crewai/Scripts/python.exe).Path
& $python -m pip install -r integrations/agent-adapters/examples/crewai-requirements.txt
& $python -m pip install -e integrations/agent-adapters
$env:CREWAI_TELEMETRY_ENABLED = 'false'
$env:OTEL_SDK_DISABLED = 'true'
$env:DO_NOT_TRACK = '1'
Push-Location packs/mcp-bridge
go build -o ../../cordum-mcp-bridge.exe ./cmd/cordum-mcp-bridge
Pop-Location
& $python integrations/agent-adapters/examples/langgraph_fixture/stack.py C:/path/to/clean/cordum-core --port-offset 10000
```

Keep that terminal running. The fixture binds every listener to loopback,
uses digest-pinned NATS/Redis containers with random credentials and tmpfs
data, and seeds a built-in transform workflow. The offset permits independent
demos; it shifts Gateway HTTP to :28081 and metrics to :29090/:29092.
It never stops a preexisting process to claim a port. See the
[fixture instructions](../examples/langgraph_fixture/README.md) for the
security model, endpoints, and cleanup.

In a second terminal, from the repository root, activate the same Python
environment and configure the bridge using the fixture's temporary config.
Do not display or share that private file:

```powershell
$python = (Resolve-Path .venv-crewai/Scripts/python.exe).Path
$runtime = (Resolve-Path integrations/agent-adapters/examples/langgraph_fixture/runtime.json).Path
$cfg = Get-Content -Raw $runtime | ConvertFrom-Json
$env:CREWAI_TELEMETRY_ENABLED = 'false'
$env:OTEL_SDK_DISABLED = 'true'
$env:DO_NOT_TRACK = '1'
$env:CORDUM_GATEWAY_URL = $cfg.gateway_url
$env:CORDUM_API_KEY = $cfg.requester_api_key
$env:CORDUM_TENANT_ID = $cfg.tenant_id
$env:CORDUM_NATS_URL = $cfg.nats_url
$env:CORDUM_REDIS_URL = $cfg.redis_url
$env:CORDUM_ENV = 'development'
$env:CORDUM_CAP_PROFILE = 'compat'
$env:CORDUM_MCP_ALLOW_UNSIGNED = 'true'
$env:CORDUM_MCP_POLL_INTERVAL = '50ms'
$bridge = (Resolve-Path cordum-mcp-bridge.exe).Path
$demo = 'integrations/agent-adapters/examples/crewai_governance.py'
```

Run the allowed transform (substitute values into JSON via `ConvertTo-Json`):

```powershell
$arguments = @{workflow_id=$cfg.workflow_id; input=@{name='CrewAI'}} | ConvertTo-Json -Compress
& $python $demo --bridge $bridge --tool cordum.workflow.run --arguments $arguments
```

The result is `succeeded`; the stored workflow output is
`{"greeting":"Hello CrewAI"}`. Try the denied cancellation:

```powershell
$arguments = @{workflow_id=$cfg.workflow_id; run_id=$cfg.source_run_id} | ConvertTo-Json -Compress
& $python $demo --bridge $bridge --tool cordum.workflow.cancel --arguments $arguments
```

The result is `denied`. Core persists a synthetic denial result, with zero
worker attempts and no `SCHEDULED`, `DISPATCHED`, or `RUNNING` events.

Try an approval-gated rerun:

```powershell
$arguments = @{run_id=$cfg.source_run_id; from_step='echo'} | ConvertTo-Json -Compress
& $python $demo --bridge $bridge --tool cordum.workflow.rerun --arguments $arguments
```

The example prints `approval_required` and the original `job_id`, then waits.
Pressing Enter only observes that same job; it cannot approve or resubmit it.
A separate operator, using the fixture's second API key in a third terminal,
can approve the harmless job:

```powershell
$cfg = Get-Content -Raw integrations/agent-adapters/examples/langgraph_fixture/runtime.json | ConvertFrom-Json
$jobId = 'paste-the-original-job-id'
$headers = @{'X-API-Key'=$cfg.approver_api_key; 'X-Tenant-ID'=$cfg.tenant_id}
Invoke-RestMethod -Method Post -Uri "$($cfg.gateway_url)/api/v1/approvals/$jobId/approve" -Headers $headers -ContentType application/json -Body '{"reason":"Harmless local CrewAI demo"}'
```

Return to the example and press Enter. It observes the original job completing
and returns its result. The integration test verifies one MCP submission total,
no preapproval execution, and HTTP 403 for requester self-approval. The second
key is a local test stand-in for an independent operator; do not copy this key
setup into a production access-control design.

## Verification

```powershell
& $python -m pytest integrations/agent-adapters/tests -m 'not integration' --timeout=30 -q
$env:CORDUM_ADAPTERS_E2E = '1'
$env:CORDUM_CREWAI_FIXTURE = $runtime
$env:CORDUM_MCP_BRIDGE = $bridge
& $python -m pytest integrations/agent-adapters/tests/integration/test_crewai_live.py -s --timeout=75 -q
```

The live checks inspect actual workflow results, stored job states, and event
histories in the disposable Redis instance. Unit tests use actual CrewAI
objects with a simulated transport to check schema validation and error
classification. The pinned native-tool unit job also runs in CI. Live tests
remain opt-in and need the local stack; unit CI is not live production proof.

After finishing, press Ctrl+C in the fixture terminal. It terminates only its
children, removes its Compose project, and deletes its private runtime files.
Close demo/operator terminals to discard the temporary keys held in process
environment variables and memory. Do not retain or commit runtime JSON,
container configuration, logs containing secrets, or credentials.

## Technical outline for a CrewAI Showcase

1. Start with the visible behavior: one native CrewAI tool succeeds, one is
   denied before dispatch, and one waits for an independent human decision.
2. Trace the boundary: CrewAI `BaseTool` → MCP stdio → bridge CAP job →
   Gateway/Safety Kernel → Scheduler → bridge worker → local transform.
3. Show the policy rules already present in the shared fixture and real
   event histories. Denial is an expected policy outcome, not a tool retry.
4. Explain approval as one stored original job. The CrewAI example only
   observes it after the operator's action; it never repeats the tool call.
5. Link the runnable source, exact commits/dependencies, tests, and the
   unmerged PR418 dependency. State the limits below alongside the result.

## Limits

- This verifies direct native CrewAI tool execution and its Cordum boundary.
  It does not exercise an LLM-driven Crew, autonomous planning, model guardrails,
  or a provider integration. No model calls were made.
- The bridge's unsigned mode is explicit, defaults off, and is restricted to
  development mode, the CAP compatibility profile, and loopback endpoints.
  Production signing/private-CA wiring is unsupported by this demonstrated
  path; production TLS, signed identities, and security defaults remain intact.
- The fixture uses a synthetic harmless transform and real local metrics,
  not production traffic or customer data. It proves no broad governance claim
  for other tools or environments.
- Caller state and any changed-input guard are application concerns; this
  example does not prove cryptographic Core token binding or durable CrewAI
  checkpoint recovery. It retains the job ID only in the running process.
- Core and these packs/adapters use Business Source License 1.1 (source-available).
  CAP uses Apache 2.0. Do not describe all of Cordum as OSI open source.
- No upstream CrewAI code/docs PR is proposed. If these AI-assisted materials
  are later submitted upstream, apply CrewAI's required `llm-generated` label.
  Community submission and publication are separate outreach actions.

Tags: CrewAI, native tools, governance, human approval, local development.
