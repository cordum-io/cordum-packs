# Cordum Packs

Official pack bundles and the public catalog for Cordum.

This repo produces:
- `catalog.json` (pack index)
- `packs/<id>/<version>/pack.tgz` (installable bundles)

These are published at `https://packs.cordum.io`.

## Repo layout

```
cordum-packs/
  packs/               # pack projects (pack.yaml at root or in pack/)
  tools/               # build + catalog tooling
  integrations/        # agent adapters and SDK integrations
  docs/                # repo docs and roadmap notes
  public/              # build output (published)
```

Pack projects may include worker/bridge code alongside the bundle assets. The
bundle itself lives at `pack/` (or the project root if `pack.yaml` is there).

## How packs run

A pack has two parts:
- **Bundle assets** (`pack/` or `pack.yaml`): workflows, schemas, overlays, policy fragments.
- **Runtime code** (`cmd/` + `internal/`): workers/bridges/receivers that execute jobs or
  trigger workflows.

`cordumctl pack install` only registers the bundle assets. To execute workflows,
deploy the pack runtime(s) so the job topics they emit (for example `job.slack.*`)
are actually handled. Workflows can compose multiple packs, so make sure every
job topic used by a workflow has a running worker.

## Build the catalog + bundles

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r tools/requirements.txt
python tools/build.py
```

Output:
- `public/catalog.json`
- `public/packs/<id>/<version>/pack.tgz`

## Pack tooling

Scaffold a new pack bundle:

```bash
python tools/pack_scaffold.py my-pack \
  --title "My Pack" \
  --description "Pack scaffold for My Pack"
```

Output:
- `packs/my-pack/` (pack bundle under `pack/` plus a starter README)

Audit pack bundles for required assets:

```bash
python tools/pack_audit.py
```

## Agent adapters

Python adapters that expose MCP tools to popular agent frameworks live under
`integrations/agent-adapters/`. The package exports:

- LangChain tools (`build_langchain_tools`)
- AutoGen tools (`build_autogen_tools`)
- CrewAI tools (`build_crewai_tools`)

Each adapter expects an MCP stdio server such as `packs/mcp-bridge`.

## Included packs

- `packs/hello-pack` - minimal example pack
- `packs/mcp-bridge` - MCP stdio bridge + pack bundle
- `packs/mcp-client` - call external MCP servers with policy gating
- `packs/slack` - Slack ChatOps notifications and approvals
- `packs/github` - GitHub automation workflows
- `packs/incident-enricher` - reference pack with workers + workflows
- See `packs/` for the full catalog.

## Publish (GitHub Pages)

The `publish.yml` workflow builds `public/` and publishes it as GitHub Pages.
Point `packs.cordum.io` at the Pages domain and it will serve:

```
https://packs.cordum.io/catalog.json
https://packs.cordum.io/packs/<id>/<version>/pack.tgz
```

## Install via Cordum

Set the catalog config in Cordum:

```bash
curl -X POST http://localhost:8081/api/v1/config \
  -H "X-API-Key: $CORDUM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "scope": "system",
    "scope_id": "pack_catalogs",
    "data": {
      "catalogs": [
        {
          "id": "official",
          "title": "Cordum Official",
          "url": "https://packs.cordum.io/catalog.json",
          "enabled": true
        }
      ]
    }
  }'
```

Then open the dashboard → Packs → Marketplace.

## License

See `LICENSE`.
