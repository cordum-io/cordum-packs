# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The official catalog of Cordum packs. A pack is a versioned bundle (workflows, JSON schemas, policy/config overlays) plus optional Go runtime code (worker/bridge/receiver). Packs are CAP-native workers that communicate via `BusPacket` envelopes over NATS with policy-before-dispatch gating.

There are **25 packs** under `packs/`. Of these, 21 ship Go runtime code (a `go.mod` + `cmd/`); 4 are **bundle-only** (`aws`, `azure`, `gcp`, `langchain-guard` — just a `pack/` directory, no Go module).

- **No root `go.mod`** — each Go pack is an independent module (the root `go.sum` is empty/vestigial).
- **Pack module path:** `github.com/cordum-io/cordum-packs/packs/<name>`
- **Shared SDK module:** `github.com/cordum/cordum/sdk` (in `sdk/`), consumed via a local `replace github.com/cordum/cordum/sdk => ../../sdk` directive in each pack's `go.mod` (version pinned `v0.2.0`).
- **Go:** 1.25.9. **CAP:** `github.com/cordum-io/cap/v2 v2.11.0`. Deps: NATS, redis/go-redis, gRPC, Protobuf.

## Common Commands

### A single Go pack (most work happens here)
```bash
cd packs/<pack-name>
go build ./...
go test ./...                                  # includes manifest + schema validation tests
go test ./internal/worker/ -run TestPackManifest
go build -o cordum-<pack>.exe ./cmd/cordum-<pack>/
```

### SDK
```bash
cd sdk && go build ./... && go test ./...
```

### Build the catalog + bundles
```bash
python -m venv .venv; . .venv/Scripts/activate     # PowerShell: .venv\Scripts\Activate.ps1
pip install -r tools/requirements.txt
python tools/build.py            # writes public/catalog.json + public/packs/<id>/<version>/pack.tgz
python tools/build.py --clean    # wipe public/ first
python tools/pack_audit.py       # check every bundle has required assets
python tools/pack_scaffold.py my-pack --title "My Pack" --description "..."
```

## Pack Structure

```
packs/<pack-name>/
├── pack/                       # the installable bundle (build.py also accepts pack.yaml at pack root)
│   ├── pack.yaml               # manifest (see below)
│   ├── schemas/                # JSON Schemas for topic input/output
│   ├── workflows/              # YAML workflow definitions
│   └── overlays/               # policy fragment + config json_merge_patch overlays
├── cmd/cordum-<pack>/main.go   # worker binary entrypoint (Go packs only)
├── internal/                   # config, gateway client, service client, worker (Go packs only)
├── go.mod / go.sum             # Go packs only
├── deploy/env.example          # required env vars / credentials
└── README.md
```

### pack.yaml manifest

```yaml
apiVersion: cordum.io/v1alpha1
kind: Pack
metadata:        { id, version, title, description, image }
compatibility:   { protocolVersion, minCoreVersion }
topics:                                    # each job topic the pack handles
  - name: job.<pack>.<verb>                # e.g. job.slack.write
    requires: ["network:egress"]           # capability requirements
    riskTags: ["write", "network"]         # drive policy decisions (read vs write)
    capability: <pack>.<verb>
    inputSchema:  <id>                      # references resources.schemas[].id
    outputSchema: <id>
resources:
  schemas:   [ { id, path } ]               # path relative to bundle root (schemas/*.json)
  workflows: [ { id, path } ]               # workflows/*.yaml
overlays:
  config: [ { name, scope, key, strategy: json_merge_patch, path } ]
  policy: [ { name, strategy: bundle_fragment, path } ]
tests:
  policySimulations:                        # exercised by go test (manifest_test.go) and pack publish
    - { name, request: {tenantId, topic, riskTags}, expectDecision: ALLOW|REQUIRE_APPROVAL|DENY }
```

Job topics follow `job.<pack>.<verb>`; `riskTags` (e.g. `read` vs `write`) drive whether the control plane allows the job or requires approval. The `manifest_test.go`/schema tests in `internal/worker/` validate that `pack.yaml` parses and that the worker's accepted/emitted payloads match the JSON schemas under `pack/schemas/` — keep them in sync.

`cordumctl pack install` registers only the bundle assets; to actually execute a topic you must run that pack's worker binary. Workflows can compose multiple packs, so every job topic a workflow uses needs a running worker. `cordumctl pack verify-signature <pack> ...` checks bundle signing (see `packs/hello-pack/README.md`).

### Running a worker against a stack

Workers are configured entirely via env (see each pack's `deploy/env.example`). Connection vars are shared across all Go packs and default to a local stack, so a worker runs with no config against `docker compose`:

- `CORDUM_GATEWAY_URL` (default `http://localhost:8081`), `CORDUM_API_KEY`, `CORDUM_TENANT_ID` (default `default`)
- `CORDUM_NATS_URL` (default `nats://localhost:4222`) — bus transport, `CORDUM_REDIS_URL` (default `redis://localhost:6379`) — result TTL store

Per-pack settings use the `CORDUM_<PACK>_*` prefix (e.g. `CORDUM_SLACK_SUBJECTS=job.slack.*`, `..._MAX_PARALLEL`, `..._REQUEST_TIMEOUT`, `..._TOKEN` / `..._TOKEN_ENV`, `..._PROFILES`, allow/deny lists). Run with `go run ./cmd/cordum-<pack>` (binary handles SIGINT/SIGTERM). Runtime details: `docs/pack-runtime-guide.md`.

## SDK (`sdk/`)

Shared library imported by all Go packs:
- `client/` — Cordum/gateway API client
- `gen/` — generated gRPC/protobuf stubs
- `runtime/` — worker pool, bus helpers, TTL store
- `logging/` — structured logging helpers

## Agent Adapters (`integrations/agent-adapters/`)

Python package (PyPI distribution name `cordum-adapters`, import `cordum_agent_adapters`) exposing MCP tools to agent frameworks. Each adapter expects an MCP stdio server such as `packs/mcp-bridge`. Public exports: `build_langchain_tools`, `build_crewai_tools`, `build_autogen_tools`, `build_autogen_openai_tools`, `mcp_tools_to_openai_tools` / `mcp_tool_to_openai_tool`, the `McpStdioClient`, and the `Adapter*Error` hierarchy. Tests under `integrations/agent-adapters/tests/`.

## Packs by Category

| Category | Packs |
|----------|-------|
| Cloud (bundle-only) | aws, azure, gcp |
| Monitoring | datadog, opentelemetry, prometheus-query, sentry |
| Communication | slack, msteams, pagerduty |
| VCS/CI/IaC | github, gitlab, terraform |
| Ticketing | jira, servicenow |
| Infrastructure | kubernetes-triage, vault |
| MCP / Bridge | mcp-bridge, mcp-client, webhooks |
| Reference / Standard | hello-pack, pic-standard, incident-enricher |
| Automation / Guards | cron-triggers, langchain-guard (bundle-only) |

## Build & Publish

- `tools/build.py` builds reproducible `pack.tgz` bundles (mtime/uid/gid zeroed), computes sha256 per bundle, verifies digests, and emits `public/catalog.json` + a stats page. Pack id/version come from `metadata`; capabilities/requires/riskTags are aggregated from `topics`.
- The `publish.yml` GitHub Actions workflow builds `public/` and serves it via GitHub Pages at `packs.cordum.io` (`/catalog.json`, `/packs/<id>/<version>/pack.tgz`). Override the base URL with `PACKS_BASE_URL` / `--base-url`.

## Platform Notes

- Windows host; default shell is **PowerShell** (use `$env:VAR`, `$null`, `.venv\Scripts\Activate.ps1`). A Bash tool is available for POSIX one-liners.
- Python: invoke as `python`.
- Each Go pack is an independent module — there is no workspace `go.mod`; run Go commands from inside the pack directory.
