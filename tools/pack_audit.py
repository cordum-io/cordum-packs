#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import yaml
except ImportError as exc:
    raise SystemExit("PyYAML is required. Run: pip install -r tools/requirements.txt") from exc

ROOT = Path(__file__).resolve().parents[1]
PACKS_DIR = ROOT / "packs"


@dataclass
class PackAudit:
    pack_dir: Path
    pack_id: str
    errors: List[str]


def should_skip(path: Path, packs_dir: Path) -> bool:
    rel = path.relative_to(packs_dir)
    for part in rel.parts:
        if part.startswith("."):
            return True
        if part == "__pycache__":
            return True
    return False


def find_manifest(pack_dir: Path) -> Tuple[Dict[str, Any], Path]:
    candidates = (
        pack_dir / "pack.yaml",
        pack_dir / "pack.yml",
        pack_dir / "pack" / "pack.yaml",
        pack_dir / "pack" / "pack.yml",
    )
    for path in candidates:
        if path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError(f"{path} must be a YAML object")
            return data, path.parent
    raise FileNotFoundError(f"pack.yaml not found in {pack_dir}")


def _has_files(path: Path, pattern: str) -> bool:
    if not path.exists() or not path.is_dir():
        return False
    return any(path.glob(pattern))


def audit_pack(pack_dir: Path) -> PackAudit:
    errors: List[str] = []
    pack_id = pack_dir.name

    try:
        manifest, pack_root = find_manifest(pack_dir)
    except (FileNotFoundError, ValueError) as exc:
        return PackAudit(pack_dir=pack_dir, pack_id=pack_id, errors=[str(exc)])

    metadata = manifest.get("metadata") or {}
    if isinstance(metadata, dict):
        pack_id = metadata.get("id") or pack_id

    required_files = [
        "overlays/pools.patch.yaml",
        "overlays/timeouts.patch.yaml",
        "overlays/policy.fragment.yaml",
    ]
    for rel in required_files:
        if not (pack_root / rel).exists():
            errors.append(f"missing {rel}")

    if not _has_files(pack_root / "schemas", "*.json"):
        errors.append("missing schemas/*.json")
    if not _has_files(pack_root / "workflows", "*.yaml"):
        errors.append("missing workflows/*.yaml")

    topics = manifest.get("topics") or []
    if not topics:
        errors.append("missing topics")
    else:
        for idx, topic in enumerate(topics):
            if not isinstance(topic, dict):
                errors.append(f"topic #{idx + 1} is not a map")
                continue
            for key in ("capability", "riskTags", "requires"):
                if key not in topic:
                    errors.append(f"topic {topic.get('name', idx + 1)} missing {key}")

    tests = manifest.get("tests") or {}
    sims = tests.get("policySimulations") if isinstance(tests, dict) else None
    if not sims:
        errors.append("missing tests.policySimulations")

    return PackAudit(pack_dir=pack_dir, pack_id=str(pack_id), errors=errors)


def render_text(results: List[PackAudit]) -> int:
    total_errors = sum(len(result.errors) for result in results)
    if not total_errors:
        print("All packs passed audit.")
        return 0

    for result in results:
        if not result.errors:
            continue
        print(f"{result.pack_id}:")
        for err in result.errors:
            print(f"  - {err}")
    print(f"\n{total_errors} issue(s) found across {len(results)} pack(s).")
    return 1


def render_json(results: List[PackAudit]) -> int:
    payload = [
        {"pack": result.pack_id, "path": str(result.pack_dir), "errors": result.errors}
        for result in results
    ]
    print(json.dumps(payload, indent=2))
    return 1 if any(result.errors for result in results) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit pack bundles for required artifacts.")
    parser.add_argument("--packs-dir", default=str(PACKS_DIR), help="Packs directory.")
    parser.add_argument("--format", default="text", choices=["text", "json"], help="Output format.")
    args = parser.parse_args()

    packs_dir = Path(args.packs_dir)
    if not packs_dir.exists():
        print(f"packs dir not found: {packs_dir}", file=sys.stderr)
        return 2

    results: List[PackAudit] = []
    for pack_dir in sorted(packs_dir.iterdir()):
        if not pack_dir.is_dir():
            continue
        if should_skip(pack_dir, packs_dir):
            continue
        results.append(audit_pack(pack_dir))

    if args.format == "json":
        return render_json(results)
    return render_text(results)


if __name__ == "__main__":
    raise SystemExit(main())
