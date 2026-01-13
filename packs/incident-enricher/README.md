# Incident Enricher Pack

Reference Cordum pack that proves the full platform loop: config overlays,
policy-gated jobs with approvals, artifacts, and a multi-step workflow.
Part of the `cordum-packs` monorepo.

This pack project ships two things:
- A pack bundle (`pack/`) that installs into Cordum.
- Simple workers (fetch/summarize/post/ingest) that execute the workflow.

Docs:
- [docs/overview.md](docs/overview.md) for the platform pitch and pack concepts.
- [docs/quickstart.md](docs/quickstart.md) for the install + demo flow.

## Scope

Incident Enricher is a reference pack that proves the full platform loop
(pack bundle + workers + overlays + policy-gated approvals + artifacts +
multi-step workflow). It is not the incident->PR autopatcher product yet; it is
incident enrichment plus a Slack post with an approval gate.

## Build the pack bundle

```
./scripts/bundle.sh
```

## Install the pack into Cordum

```
./scripts/install.sh
```

This registers schemas/workflows, applies pools/timeouts overlays, and installs a
safety policy fragment that requires approval for the `post` step.

## Architecture at a glance

```
Webhook / cordumctl
        |
     Gateway
        |
  Workflow Engine ----> Safety Kernel
        |                   |
     Scheduler <------------- (policy decision)
        |
      NATS (CAP bus)
        |
   Pack workers (fetch/summarize/post)
        |
     Redis (context/result pointers)
        |
    Artifacts API (audit trail)
```

## Pack contents

- [pack/pack.yaml](pack/pack.yaml) - pack manifest
- [pack/workflows/incident_enrich.yaml](pack/workflows/incident_enrich.yaml) - workflow template
- [pack/schemas](pack/schemas) - workflow data contracts
- [pack/overlays](pack/overlays) - pools/timeouts/policy fragments

## What you get

- Workflow template `incident-enricher.enrich` registered in the workflow store.
- Schemas for `IncidentInput`, `EvidenceBundle`, `Summary`, and `PostResult`.
- Config overlays applied to `cfg:system:pools` and `cfg:system:timeouts`.
- Safety policy fragment that requires approval for `job.incident-enricher.post`.
- Artifacts for evidence, summary output, and post results (audit trail).

## Build and run workers

Local build:

```
go build ./cmd/...
```

Run workers with Docker (Cordum must already be running):

```
docker compose -f deploy/docker-compose.workers.yaml --env-file deploy/env.example up --build
```

`deploy/env.example` targets the Docker network (`gateway`, `nats`, `redis`). For local runs without Docker, point those to `localhost`.

## Demo

Start a run and approve the post step:

```
./scripts/demo.sh
./scripts/approve_latest_post.sh
```

If you run the ingester, set `INGESTER_URL` to post the sample webhook:

```
INGESTER_URL=http://localhost:8088 ./scripts/demo.sh
```

## Configuration summary

- `CORDUM_GATEWAY_URL`, `CORDUM_API_KEY`
- `NATS_URL`, `REDIS_ADDR` or `REDIS_URL`
- `WORKER_POOL` (per worker: `incident-enricher-fetch|summarize|post`), `WORKER_ID`, `WORKER_MAX_PARALLEL`
- `LLM_PROVIDER` (`mock` or `ollama`)
- `OLLAMA_URL`, `OLLAMA_MODEL`, `OLLAMA_TEMPERATURE` (required for `ollama`)
- `OPENAI_API_KEY`, `OPENAI_MODEL` (reserved; not implemented yet)
- `LLM_MAX_INPUT_BYTES`, `LLM_MAX_EVIDENCE_BYTES`, `LLM_MAX_EVIDENCE_ITEMS`
- `SLACK_WEBHOOK_URL`
