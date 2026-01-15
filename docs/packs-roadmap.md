# Cordum Packs Roadmap

This roadmap defines the next 20 "must-have" packs and the consistency pattern each pack must follow. Packs are installable overlays (workflows + schemas + config/policy patches). Workers are deployed separately and should be scoped, auditable, and policy-gated.

## Guiding Principles

1) Spec-first integration: clear topics, capabilities, risk tags, and requires.
2) Governable by default: read is allowed; write requires approval; destructive/prod/secrets are restricted.
3) Observable: every pack emits useful metadata (labels, artifact pointers, logs) for audit.
4) Consistent UX: common naming, schemas, and policy tests across packs.
5) Workflows are the product surface; job topics are the building blocks.

## Standard Pack Pattern (Required)

Every pack must include:

1) **Topics + capabilities + risk tags + requires** in `pack.yaml`
2) **Policy fragment** with the same read/write split
3) **Minimal workflow template** that proves the integration
4) **Policy simulations** in `pack.yaml` for safe installs
3) Observable: every pack emits labels, artifacts, and logs suitable for audit.
4) Consistent UX: naming, schemas, and policy tests are uniform across packs.

### Topic + Capability + Risk Tags

- Topic naming: `job.<pack>.<action>`
- Capability naming: `<pack>.<action>` or `<pack>.<resource>.<action>`
- Risk tags: `read`, `write`, plus `prod`, `destructive`, `secrets`, `network` as needed
- Requires: `network:egress`, `slack:webhook`, `github:api`, `llm`, etc.

### Policy baseline
- `read`: `ALLOW`
- `write`: `REQUIRE_APPROVAL`
- `destructive` / `prod` / `secrets`: `DENY` or `REQUIRE_APPROVAL` with constraints

### Minimal workflow template
1) Collect evidence (read-only)
2) Summarize (optional LLM)
3) Approval gate for write/destructive actions
4) Execute action and emit artifacts
3) Approval (if action is write/destructive)
4) Execute action

### Workflow Governance (Required)

**Pack-managed vs user workflows**
- Pack workflows are stable APIs (IDs stay under `<pack_id>.<name>`).
- Users should clone pack workflows into new IDs (e.g., `acme.<name>`) before customizing.

**Atomic jobs + reference workflows**
- Ship atomic job topics as building blocks (e.g., `job.github.pr.create`).
- Ship 2-5 reference workflows that solve real use cases end-to-end.

**Per-step metadata (non-negotiable)**
Every worker step must set:
- `pack_id`
- `capability`
- `risk_tags`
- `requires`
- `idempotency_key` for any side-effecting step

**Approvals model**
- Prefer workflow approval steps as the human gate.
- Avoid double approvals: if a workflow step gates a write, policy should lean on `ALLOW_WITH_CONSTRAINTS`.

**Versioning**
- Breaking input/output change = new workflow ID (`.v2`).
- Backward-compatible changes stay on the same ID.

**Idempotency + locks**
- Derive idempotency from event IDs for webhooks.
- Acquire locks for irreversible changes (e.g., `repo:<org>/<repo>`, `svc:<name>:env:<env>`).

**Pack dependencies for auto-install**
If a workflow uses topics from other packs, declare the dependencies so installers can auto-install them:

```yaml
requires_packs:
  - slack
  - github
```

Use `depends_on` for step ordering only; `requires_packs` is for pack dependencies.

### Policy Simulations

Each pack should ship policy simulations verifying:
- Read path is `ALLOW`
- Write path is `REQUIRE_APPROVAL`
- Sensitive actions are constrained or denied

## Standard Artifacts

### Required artifacts
- `pack/pack.yaml`
- `pack/overlays/pools.patch.yaml`
- `pack/overlays/timeouts.patch.yaml`
- `pack/overlays/policy.fragment.yaml`
- `pack/schemas/*.json`
- `pack/workflows/*.yaml`
- `tests.policySimulations` in `pack.yaml`

## Repository Layout (Quick Reference)
- `packs/` pack projects (bundle assets and optional worker code)
- `pack/` inside a pack holds bundle assets; some packs keep `pack.yaml` at the root
- `cmd/` and `internal/` for Go-based workers
- `tools/` build tooling; `public/` is generated output

## Definition of Done (Per Pack)
- Topics/capabilities/risk tags/requires documented in `pack.yaml`
- Policy fragment + policy simulations pass
- Minimal workflow proves the integration end to end
- Worker is deployable and audited separately from the pack
- `python tools/build.py` produces bundle output in `public/`

## Pack Roadmap (20 Must-Haves)
Status legend: `in-repo` means a pack exists in this repository.

### Phase 1 (Foundation)
- mcp-client: Cordum as an MCP client; `read|write|network` (status: in-repo)
- github: repo read/search, issues, PRs, checks, releases (status: in-repo)
- slack: notifications, approvals, incident channels
- jira: issues, transitions, comments, attachments
- webhooks: inbound events to start workflows; principal mapping required
- kubernetes-triage: diagnostics, events, logs, rollout status

### Phase 2 (Ops and Observability)
- prometheus-query: PromQL queries and alert state
- datadog: metrics/logs/traces queries; monitor changes require approval
- pagerduty: on-call schedules, incidents, escalations
- servicenow: ITSM incidents/changes/CMDB; `prod` and `write` tagging
- msteams: Teams-native notifications and approvals
- sentry: issues, releases, suspect commits
- opentelemetry: trace search and dependency graphs (read-only early)

### Phase 3 (Infra and Change)
- aws: CloudWatch logs/metrics, ECS/EKS inspection, S3 evidence
- gcp: Cloud Logging/Monitoring queries, GKE inspection
- azure: Azure Monitor queries, AKS inspection
- terraform: plan, drift detection, policy checks; apply requires approval
- vault: secret resolution and dynamic credentials; no raw secrets in workflows
- gitlab: repo read/search, merge requests, pipelines, issues
- cron-triggers: scheduled runs for checks, summaries, compliance

## Governance Checklist (Per Pack)

- Define topics and capabilities in `pack.yaml`
- Annotate every action with risk tags and requires
- Add policy fragment with the read/write split
- Add policy simulation tests
- Provide a minimal, demonstrative workflow
- Ensure workers are separate deployables

## Kickoff Steps
When starting a pack:
1) Confirm integration scope and auth model.
2) Draft `pack.yaml` with topics, capabilities, risk tags, and requires.
3) Add policy fragment + simulations.
4) Implement worker + SDK calls.
5) Ship a minimal workflow for validation.
