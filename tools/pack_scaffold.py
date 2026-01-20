#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKS_DIR = ROOT / "packs"


def yaml_str(value: str) -> str:
    return json.dumps(value)


def validate_pack_id(pack_id: str) -> None:
    if not re.match(r"^[a-z][a-z0-9-]+$", pack_id):
        raise ValueError("pack id must be kebab-case (letters, numbers, hyphens)")


def ensure_output_dir(path: Path, force: bool) -> None:
    if path.exists():
        if path.is_file():
            raise FileExistsError(f"output path is a file: {path}")
        if any(path.iterdir()) and not force:
            raise FileExistsError(f"output path not empty: {path}")
        return
    path.mkdir(parents=True, exist_ok=True)


def write_file(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def pack_yaml(pack_id: str, title: str, description: str, version: str, slug: str) -> str:
    return f"""apiVersion: cordum.io/v1alpha1
kind: Pack

metadata:
  id: {pack_id}
  version: {yaml_str(version)}
  title: {yaml_str(title)}
  description: {yaml_str(description)}

compatibility:
  protocolVersion: 1
  minCoreVersion: 0.1.0

topics:
  - name: job.{pack_id}.read
    requires: ["network:egress"]
    riskTags: ["read", "network"]
    capability: {pack_id}.read

  - name: job.{pack_id}.write
    requires: ["network:egress"]
    riskTags: ["write", "network"]
    capability: {pack_id}.write

resources:
  schemas:
    - id: {pack_id}/ReadInput
      path: schemas/ReadInput.json
    - id: {pack_id}/ReadResult
      path: schemas/ReadResult.json
    - id: {pack_id}/WriteInput
      path: schemas/WriteInput.json
    - id: {pack_id}/WriteResult
      path: schemas/WriteResult.json
  workflows:
    - id: {pack_id}.read
      path: workflows/{slug}_read.yaml
    - id: {pack_id}.write
      path: workflows/{slug}_write.yaml

overlays:
  config:
    - name: pools
      scope: system
      key: pools
      strategy: json_merge_patch
      path: overlays/pools.patch.yaml
    - name: timeouts
      scope: system
      key: timeouts
      strategy: json_merge_patch
      path: overlays/timeouts.patch.yaml
  policy:
    - name: safety
      strategy: bundle_fragment
      path: overlays/policy.fragment.yaml

tests:
  policySimulations:
    - name: allow_read
      request:
        tenantId: default
        topic: job.{pack_id}.read
        riskTags: ["read", "network"]
      expectDecision: ALLOW
    - name: write_requires_approval
      request:
        tenantId: default
        topic: job.{pack_id}.write
        riskTags: ["write", "network"]
      expectDecision: REQUIRE_APPROVAL
"""


def pools_patch(pack_id: str) -> str:
    return f"""topics:
  job.{pack_id}.read: {pack_id}
  job.{pack_id}.write: {pack_id}
pools:
  {pack_id}:
    requires: ["network:egress"]
"""


def timeouts_patch(pack_id: str) -> str:
    return f"""topics:
  job.{pack_id}.read:
    timeout_seconds: 60
    max_retries: 2
  job.{pack_id}.write:
    timeout_seconds: 120
    max_retries: 1
"""


def policy_fragment(pack_id: str) -> str:
    return f"""version: v1
rules:
  - id: {pack_id}-read
    match:
      topics:
        - job.{pack_id}.read
      risk_tags:
        - read
    decision: allow
  - id: {pack_id}-write
    match:
      topics:
        - job.{pack_id}.write
      risk_tags:
        - write
    decision: require_approval
    reason: "Write actions require approval"
"""


def workflow_read(pack_id: str, title: str) -> str:
    return f"""id: {pack_id}.read
name: {title} Read
description: Read action template for {title}.
version: "0.1.0"
timeout_sec: 60
steps:
  read:
    id: read
    name: {title} Read action
    type: worker
    topic: job.{pack_id}.read
    input:
      request_id: ${{input.request_id}}
      action: ${{input.action}}
      params: ${{input.params}}
      auth: ${{input.auth}}
    input_schema_id: {pack_id}/ReadInput
    output_schema_id: {pack_id}/ReadResult
    meta:
      pack_id: {pack_id}
      capability: {pack_id}.read
      risk_tags: ["read", "network"]
      requires: ["network:egress"]
"""


def workflow_write(pack_id: str, title: str) -> str:
    return f"""id: {pack_id}.write
name: {title} Write
description: Write action template for {title}.
version: "0.1.0"
timeout_sec: 120
steps:
  write:
    id: write
    name: {title} Write action
    type: worker
    topic: job.{pack_id}.write
    input:
      request_id: ${{input.request_id}}
      action: ${{input.action}}
      params: ${{input.params}}
      auth: ${{input.auth}}
    input_schema_id: {pack_id}/WriteInput
    output_schema_id: {pack_id}/WriteResult
    meta:
      pack_id: {pack_id}
      capability: {pack_id}.write
      risk_tags: ["write", "network"]
      requires: ["network:egress"]
"""


def read_input_schema(title: str) -> str:
    payload = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": f"{title} Read Input",
        "type": "object",
        "properties": {
            "action": {"type": "string", "description": "Action to perform."},
            "params": {
                "type": "object",
                "description": "Action parameters.",
                "additionalProperties": True,
            },
            "auth": {
                "type": "object",
                "description": "Optional auth override.",
                "additionalProperties": True,
            },
            "request_id": {"type": "string", "description": "Idempotency key."},
        },
        "required": ["action"],
        "additionalProperties": False,
    }
    return json.dumps(payload, indent=2)


def read_result_schema(title: str) -> str:
    payload = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": f"{title} Read Result",
        "type": "object",
        "properties": {
            "job_id": {"type": "string"},
            "profile": {"type": "string"},
            "action": {"type": "string"},
            "status_code": {"type": "integer"},
            "request_id": {"type": "string"},
            "duration_ms": {"type": "number"},
            "result": {"type": ["object", "array", "string", "number", "boolean", "null"]},
            "error": {"type": "string"},
        },
    }
    return json.dumps(payload, indent=2)


def write_input_schema(title: str) -> str:
    payload = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": f"{title} Write Input",
        "type": "object",
        "properties": {
            "action": {"type": "string", "description": "Action to perform."},
            "params": {
                "type": "object",
                "description": "Action parameters.",
                "additionalProperties": True,
            },
            "auth": {
                "type": "object",
                "description": "Optional auth override.",
                "additionalProperties": True,
            },
            "request_id": {"type": "string", "description": "Idempotency key."},
        },
        "required": ["action"],
        "additionalProperties": False,
    }
    return json.dumps(payload, indent=2)


def write_result_schema(title: str) -> str:
    payload = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": f"{title} Write Result",
        "type": "object",
        "properties": {
            "job_id": {"type": "string"},
            "profile": {"type": "string"},
            "action": {"type": "string"},
            "status_code": {"type": "integer"},
            "request_id": {"type": "string"},
            "duration_ms": {"type": "number"},
            "result": {"type": ["object", "array", "string", "number", "boolean", "null"]},
            "error": {"type": "string"},
        },
    }
    return json.dumps(payload, indent=2)


def readme(pack_id: str, title: str) -> str:
    return f"""# {title} Pack

Scaffolded Cordum pack with standard workflows, schemas, overlays, and policy simulations.

## Runtime component

This scaffold does not include runtime code. Add a worker under `cmd/<binary>` and `internal/`
that subscribes to:

- `job.{pack_id}.read`
- `job.{pack_id}.write`

## Install

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/{pack_id}/pack
```

## Run (example)

```bash
curl -sS -X POST http://localhost:8081/api/v1/workflows/{pack_id}.read/runs \
  -H "X-API-Key: $CORDUM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"action":"example.read","params":{}}'
```
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Scaffold a Cordum pack.")
    parser.add_argument("pack_id", help="Pack id (kebab-case).")
    parser.add_argument("--title", default=None, help="Pack title (defaults from id).")
    parser.add_argument("--description", default="", help="Pack description.")
    parser.add_argument("--version", default="0.1.0", help="Pack version.")
    parser.add_argument("--output", default=None, help="Output directory (defaults to packs/<id>).")
    parser.add_argument("--force", action="store_true", help="Overwrite files if output exists.")
    args = parser.parse_args()

    pack_id = args.pack_id.strip()
    if not pack_id:
        print("pack id is required", file=sys.stderr)
        return 2
    try:
        validate_pack_id(pack_id)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    title = args.title or pack_id.replace("-", " ").title()
    description = args.description.strip()
    version = args.version.strip() or "0.1.0"

    output_dir = Path(args.output) if args.output else PACKS_DIR / pack_id
    try:
        ensure_output_dir(output_dir, args.force)
    except FileExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    slug = pack_id.replace("-", "_")

    pack_dir = output_dir / "pack"
    overlays_dir = pack_dir / "overlays"
    schemas_dir = pack_dir / "schemas"
    workflows_dir = pack_dir / "workflows"
    overlays_dir.mkdir(parents=True, exist_ok=True)
    schemas_dir.mkdir(parents=True, exist_ok=True)
    workflows_dir.mkdir(parents=True, exist_ok=True)

    try:
        write_file(output_dir / "README.md", readme(pack_id, title), args.force)
        write_file(pack_dir / "pack.yaml", pack_yaml(pack_id, title, description, version, slug), args.force)
        write_file(overlays_dir / "pools.patch.yaml", pools_patch(pack_id), args.force)
        write_file(overlays_dir / "timeouts.patch.yaml", timeouts_patch(pack_id), args.force)
        write_file(overlays_dir / "policy.fragment.yaml", policy_fragment(pack_id), args.force)
        write_file(schemas_dir / "ReadInput.json", read_input_schema(title), args.force)
        write_file(schemas_dir / "ReadResult.json", read_result_schema(title), args.force)
        write_file(schemas_dir / "WriteInput.json", write_input_schema(title), args.force)
        write_file(schemas_dir / "WriteResult.json", write_result_schema(title), args.force)
        write_file(workflows_dir / f"{slug}_read.yaml", workflow_read(pack_id, title), args.force)
        write_file(workflows_dir / f"{slug}_write.yaml", workflow_write(pack_id, title), args.force)
    except FileExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(f"Scaffolded pack at {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
