# Cordum Packs

The official catalog of Cordum packs: versioned, production-grade bundles and
runtime code that make workflows safe to operate in real systems.

Cordum is an AI agent orchestration platform with built-in brakes. It sits
between agents and tools to enforce policy-before-dispatch, approval gates for
risky actions, and full auditability. Packs bring those guarantees to
integrations and workflows so teams can move from proof-of-concept to
production with confidence.

## Protocol

All packs implement the [Cordum Agent Protocol (CAP)](https://github.com/cordum-io/cap) — the open wire protocol for distributed AI agent governance. Packs are CAP-native workers that communicate via `BusPacket` envelopes over NATS, with built-in safety gating and policy enforcement.

The reference control plane is [Cordum](https://github.com/cordum-io/cordum).

## From PoC to production

Most teams get stuck at the trust gap: agents can do the work, but governance,
approvals, and audit trails are missing. Packs close that gap by shipping
deterministic, policy-gated workflows and the runtimes that execute them.
Deterministic core, autonomy at the edges.

## Why teams use packs

- **Policy gate for every action**: approvals and constraints before execution.
- **Deterministic core**: predictable outcomes with replay and auditability.
- **MCP-native integrations**: connect tools and agents without glue code.
- **Pack system extensibility**: add new behaviors without changing core.

## What you get

- **Pack bundles**: workflows, schemas, overlays, and policy fragments.
- **Runtime code**: workers, bridges, and receivers that execute jobs and triggers.
- **Public catalog**: a stable index of installable bundles.
- **Security guidance**: hardening and operational playbooks.

## Typical outcomes

- Enrich incidents with context from tools like Slack, Jira, ServiceNow, and more.
- Route and correlate alerts across teams and systems with clear policy gates.
- Require approvals and replay execution when production changes are involved.

## How packs run

A pack has two parts:
- **Bundle assets** (`pack/` or `pack.yaml`): workflows, schemas, overlays, policy fragments.
- **Runtime code** (`cmd/` + `internal/`): workers/bridges/receivers that execute jobs or
  trigger workflows.

`cordumctl pack install` only registers the bundle assets. To execute workflows,
deploy the pack runtime(s) so the job topics they emit (for example `job.slack.*`)
are actually handled. Workflows can compose multiple packs, so make sure every
job topic used by a workflow has a running worker.

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

## Signing and verification

The publish build uses `cordumctl pack sign` to sign each pack's manifest and
declared resource hashes with an Ed25519 publisher key. Each bundle contains
`pack.yaml.sig` at its root. Before writing `catalog.json`, the build extracts
every bundle and verifies its signature against the pinned public key; catalog
SHA-256 values cover the resulting signed bundle bytes. A verification failure
names the failing packs and prevents catalog generation and artifact upload.

The publisher key id is `cordum-packs-1`. Its public YAML belongs at
`keys/cordum-packs-1.pub`, copied from the human-provisioned publisher key.
Publishing requires the matching private YAML in the repository's Actions
secret `PACKS_SIGNING_KEY`; the job fails if that secret is absent and runs an
`always()` cleanup step for its temporary private-key file. Never put private
keys in this repo or inside a pack directory. PR validation uses a disposable
key, not that secret.

Set this environment variable on the gateway, replacing the placeholder with
the `public_key_b64` value from the pinned public file:

```text
CORDUM_GATEWAY_PACK_TRUSTED_KEY_CORDUM_PACKS_1=<public_key_b64>
```

To check an extracted bundle against that public key:

```bash
cordumctl pack verify-signature /path/to/extracted-pack --key keys/cordum-packs-1.pub
```

For a local signed build, keep the private key outside the packs directory:

```bash
python tools/build.py --signing-key /secure/publisher.key \
  --trusted-key keys/cordum-packs-1.pub --cordumctl /path/to/cordumctl
```

Without `--signing-key`, local builds remain unsigned. These pipeline checks
do not establish that the currently published catalog is signed, or activate
policy fragments under a deployment's separate policy trust store.

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

## Security & operations docs

- `docs/security-hardening.md`
- `docs/pack-runtime-guide.md`
- `docs/testing-and-validation.md`
- `docs/wiki/` (wiki mirror content)

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

## License

See `LICENSE`.
