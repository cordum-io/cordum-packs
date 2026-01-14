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

### Topic + Capability + Risk Tags

- Topic naming: `job.<pack>.<action>`
- Capability naming: `<pack>.<action>` (or `<pack>.<resource>.<action>` for precision)
- Risk tags:
  - `read` for data fetch, inspection, discovery
  - `write` for changes, mutations, creations
  - Additional tags: `prod`, `destructive`, `secrets`, `network`
- Requires:
  - `network:egress` for external APIs
  - `llm`, `slack:webhook`, `github:api`, etc. for specific capabilities

### Default Policy Fragment (Baseline)

- `read`: `ALLOW`
- `write`: `REQUIRE_APPROVAL`
- `destructive` / `prod` / `secrets`: `DENY` or `REQUIRE_APPROVAL` + constraints

### Minimal Workflow Template (Proof Pack)

Standard flow for each pack:
1) Collect evidence (read-only)
2) Summarize (optional LLM)
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

Each pack should include:

- `pack/pack.yaml`
- `pack/overlays/pools.patch.yaml`
- `pack/overlays/timeouts.patch.yaml`
- `pack/overlays/policy.fragment.yaml`
- `pack/schemas/*.json`
- `pack/workflows/*.yaml`
- `tests.policySimulations` in `pack.yaml`

## Pack List (Must-Have 20)

### 1) mcp-client
- Purpose: Cordum as an MCP client (stdio + streamable HTTP).
- Topics: `job.mcp-client.call`
- Capabilities: `mcp.call.<server>.<tool>`
- Risk: `read|write|network`

### 2) github
- Purpose: repo read/search, issues, PRs, checks, releases.
- Risk: read allow; PR creation/branch push approval.

### 3) gitlab
- Purpose: repo read/search, merge requests, pipelines, issues.
- Risk: read allow; branch push/MR creation approval.

### 4) slack
- Purpose: notifications, approvals, incident channels.
- Risk: post message allow; channel create/invite approval in regulated orgs.

### 5) msteams
- Purpose: Teams-native notifications and approvals.
- Risk: similar to Slack.

### 6) jira
- Purpose: issues, transitions, comments, attachments.
- Risk: read allow; issue create/priority change approval.

### 7) servicenow
- Purpose: ITSM incidents/changes/CMDB.
- Risk: change create/approve tagged `prod` and `write`.

### 8) pagerduty
- Purpose: on-call schedules, incidents, escalations.
- Risk: resolve/escalate approval.

### 9) webhooks
- Purpose: generic inbound events to start Cordum workflows.
- Risk: map inbound principal + tenant and policy-check every run.

### 10) cron-triggers
- Purpose: scheduled runs for checks/summaries/compliance.

### 11) kubernetes-triage
- Purpose: diagnostics, events, logs, rollout status.
- Risk: mutation actions require approval.

### 12) prometheus-query
- Purpose: PromQL queries, alert state, label discovery.
- Risk: `read` + `network`.

### 13) datadog
- Purpose: metrics/logs/traces queries; monitor state.
- Risk: mute/modify monitors require approval.

### 14) opentelemetry
- Purpose: trace search, dependency graphs.
- Risk: read only in early versions.

### 15) sentry
- Purpose: issues, releases, suspect commits.
- Risk: mute/route changes require approval.

### 16) aws
- Purpose: CloudWatch logs/metrics, ECS/EKS inspection, S3 evidence.
- Risk: IAM and infra changes require approval.

### 17) gcp
- Purpose: Cloud Logging/Monitoring queries, GKE inspection.
- Risk: infra changes require approval.

### 18) azure
- Purpose: Azure Monitor queries, AKS inspection.
- Risk: infra changes require approval.

### 19) terraform
- Purpose: plan, drift detection, policy checks; optional apply with approval.
- Risk: apply is high risk.

### 20) vault
- Purpose: secret resolution and dynamic credentials (no raw secrets in workflows).
- Risk: `secrets` tag + strict policy constraints.

## Recommended Build Order

Phase 1: `mcp-client`, `github`, `slack`, `jira`, `webhooks`, `kubernetes-triage`  
Phase 2: `prometheus-query`, `datadog`, `pagerduty`, `servicenow`  
Phase 3: `aws`, `gcp`, `azure`, `terraform`, `vault`, then remaining packs

## Governance Checklist (Per Pack)

- Define topics and capabilities in `pack.yaml`
- Annotate every action with risk tags and requires
- Add policy fragment with read/write split
- Add policy simulation tests
- Provide a minimal, demonstrative workflow
- Ensure workers are separate deployables

## Next Steps

When we start a pack:
1) Confirm integration scope + auth model.
2) Draft `pack.yaml` with topics, capabilities, risk tags, requires.
3) Add policy fragment + simulations.
4) Implement worker + SDK calls.
5) Ship a minimal workflow for validation.
