# CLAUDE.md

This file provides guidance to Claude Code when working with the cordum-packs repository.

## Project Overview

28 integration packs for the Cordum platform. Each pack is an independent Go module with its own worker binary, manifest, schemas, and workflows. Packs connect Cordum to external services (Slack, GitHub, AWS, Jira, etc.).

- **No root go.mod** — each pack has its own module
- **SDK module:** `github.com/cordum/cordum/sdk` (in `sdk/` directory)
- **SDK depends on:** CAP v2.0.19, NATS, gRPC, Protobuf

## Common Commands

### SDK (shared library)
```bash
cd sdk && go build ./... && go test ./...
```

### Individual Pack
```bash
cd packs/<pack-name>
go build ./...
go test ./...
go build -o cordum-<pack>.exe ./cmd/cordum-<pack>/
```

### Catalog Build
```bash
python tools/build.py    # Generates public/catalog.json + bundled packs
```

## Pack Structure (convention)

```
packs/<pack-name>/
├── pack/
│   ├── pack.yaml           # Manifest: topics, schemas, workflows, overlays
│   ├── schemas/             # JSON schemas for inputs/outputs
│   ├── workflows/           # YAML workflow definitions
│   └── overlays/            # Policy fragments
├── cmd/cordum-<pack>/       # Runtime worker binary entrypoint
├── go.mod / go.sum
├── deploy/env.example       # Required environment variables
└── README.md
```

### pack.yaml Manifest

The `pack.yaml` defines what topics the pack handles, input/output schemas, bundled workflows, and policy overlays.

## 28 Packs by Category

| Category | Packs |
|----------|-------|
| Cloud | aws, azure, gcp |
| Monitoring | datadog, opentelemetry, prometheus-query, sentry |
| Communication | slack, msteams, pagerduty |
| VCS/CI | github, gitlab, terraform |
| Ticketing | jira, servicenow |
| Infrastructure | kubernetes-triage, vault |
| Bridge | mcp-bridge, mcp-client, webhooks |
| Standard | pic-standard, hello-pack (reference), cap, cordum |
| Automation | cron-triggers, incident-enricher |

## SDK (`sdk/`)

Shared library used by all packs:
- `client/` — Cordum API client
- `gen/` — gRPC generated stubs
- `runtime/` — worker pool, bus helpers, TTL store

## Agent Adapters (`integrations/agent-adapters/`)

Python package with adapters for: CrewAI, LangChain, OpenAI Tools, MCP Client, plus autogen.py.

## Build & Publish

- `tools/build.py` generates `public/catalog.json` + bundled packs
- Published to `packs.cordum.io`
- 26 git worktrees for parallel pack development

## Development Workflow

1. Pick a pack: `cd packs/<pack-name>`
2. Check `deploy/env.example` for required credentials
3. Build: `go build ./cmd/cordum-<pack>/`
4. Test: `go test ./...`
5. Run locally with NATS + Redis running (from `cordum` repo: `make dev-up`)

## Platform Notes

- Windows/MSYS environment — use Unix shell syntax
- Python: use `python` (not `python3`)
- Each pack is an independent Go module — no workspace-level `go.mod`
