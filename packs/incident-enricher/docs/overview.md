# Cordum Pack Overview

This pack project is a public, minimal example of how Cordum is meant to scale:
keep the platform stable and install behavior as packs.

## What Cordum provides (platform-only)

- CAP protocol (bus envelopes, job requests/results, heartbeats).
- Scheduler + safety kernel + workflow engine.
- Gateway APIs for workflows, artifacts, approvals, config, and policy.
- Redis-backed pointers for job context/results.

## What a pack adds

- Workflow templates (what to run, and in what order).
- Topics and routing overlays (topic -> pool mapping).
- Policy overlays (allow, deny, require approval).
- Schemas for inputs/outputs.
- External workers that implement the topics.

The platform never executes pack code during install. Packs only write data into
existing stores via the gateway.

## Why this pack exists

Incident Enricher is a first-pack reference. It proves:

- Workflow CRUD + run lifecycle works without any special-case product code.
- Policy fragments are loaded from config service and can force approvals.
- Scheduler routing overlays work (topic -> pool mapping).
- Artifacts provide an audit trail of evidence and outputs.

## What is intentionally minimal

- LLM integration is mock by default, with Ollama support (OpenAI stub only).
- Incident fetch is mock by default (no PagerDuty integration).
- Slack posting works via webhook, gated by policy approval.

The goal is to keep the surface area small while proving the platform loop.

## Positioning: reference pack, not product

Incident Enricher is a reference pack that proves the full loop (pack bundle,
workers, overlays, policy-gated approvals, artifacts, and a multi-step
workflow). It is not the incident->PR autopatcher product yet; it is incident
enrichment plus a Slack post with an approval gate.

## Next steps to strengthen the reference pack

- Add a diagram and a screenshot to README (fastest adoption win).
- Keep README links clickable and keep the "What you get" section accurate.
- Add CI: go test ./..., golangci-lint, and docker build for each worker.
- Publish the pack bundle (.tgz from scripts/bundle.sh) as a release artifact.

## Product path (separate pack)

Keep this pack as the reference and create a dedicated product pack
(incident -> evidence -> patch -> verify -> PR).

Minimum delta from this pack:
- Replace the post step with a PR open step (GitHub/GitLab).
- Add a hard verify gate (tests/lint/templating) before the PR is opened.
- Require approvals for all write actions (PR open, merge, deploy).
- Make EvidenceBundle central and redact secrets by default.

## Risk

Do not over-polish the demo pack; it should accelerate onboarding and the
product pack.
