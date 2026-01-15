#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PACKS_DIR = ROOT / "packs"
PUBLIC_DIR = ROOT / "public"


def find_manifest(pack_dir: Path) -> tuple[dict, Path]:
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


def author_from_metadata(metadata: dict) -> str:
    authors = metadata.get("authors")
    if isinstance(authors, list) and authors:
        first = authors[0]
        if isinstance(first, dict):
            return str(first.get("name") or "")
        if isinstance(first, str):
            return first
    author = metadata.get("author")
    if isinstance(author, str):
        return author
    return ""


def should_skip(path: Path, pack_dir: Path) -> bool:
    rel = path.relative_to(pack_dir)
    for part in rel.parts:
        if part.startswith("."):
            return True
        if part == "__pycache__":
            return True
    return False


def build_bundle(pack_root: Path, pack_id: str, version: str) -> Path:
    out_dir = PUBLIC_DIR / "packs" / pack_id / version
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = out_dir / "pack.tgz"
    if bundle_path.exists():
        bundle_path.unlink()
    with tarfile.open(bundle_path, "w:gz") as tar:
        for path in pack_root.rglob("*"):
            if not path.is_file() or should_skip(path, pack_root):
                continue
            arcname = path.relative_to(pack_root)
            tar.add(path, arcname=str(arcname))
    return bundle_path


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_catalog_entry(manifest: dict, bundle_path: Path, base_url: str) -> dict:
    metadata = manifest.get("metadata") or {}
    pack_id = str(metadata.get("id") or "").strip()
    version = str(metadata.get("version") or "").strip()
    if not pack_id or not version:
        raise ValueError(f"metadata.id and metadata.version required in {bundle_path}")
    topics = manifest.get("topics") or []
    capabilities = set()
    requires = set()
    risk_tags = set()
    for topic in topics:
        if not isinstance(topic, dict):
            continue
        cap = topic.get("capability")
        if isinstance(cap, str) and cap:
            capabilities.add(cap)
        for req in topic.get("requires") or []:
            if isinstance(req, str) and req:
                requires.add(req)
        for tag in topic.get("riskTags") or []:
            if isinstance(tag, str) and tag:
                risk_tags.add(tag)
    author = author_from_metadata(metadata)
    if not author:
        author = "Cordum"
    source = metadata.get("sourceRepo") or metadata.get("source") or ""
    image = metadata.get("image") or ""
    homepage = metadata.get("homepage") or ""
    license_name = metadata.get("license") or ""
    url = f"{base_url}/packs/{pack_id}/{version}/pack.tgz"
    return {
        "id": pack_id,
        "version": version,
        "title": metadata.get("title") or pack_id,
        "description": metadata.get("description") or "",
        "author": author,
        "homepage": homepage,
        "source": source,
        "image": image,
        "license": license_name,
        "url": url,
        "sha256": sha256_file(bundle_path),
        "capabilities": sorted(capabilities),
        "requires": sorted(requires),
        "risk_tags": sorted(risk_tags),
    }


def build_catalog(packs_dir: Path, base_url: str) -> list:
    entries = []
    for pack_dir in sorted(packs_dir.iterdir()):
        if not pack_dir.is_dir():
            continue
        if should_skip(pack_dir, packs_dir):
            continue
        manifest, pack_root = find_manifest(pack_dir)
        metadata = manifest.get("metadata") or {}
        pack_id = str(metadata.get("id") or "").strip()
        version = str(metadata.get("version") or "").strip()
        if not pack_id or not version:
            raise ValueError(f"pack metadata.id/version required in {pack_dir}")
        bundle_path = build_bundle(pack_root, pack_id, version)
        entries.append(build_catalog_entry(manifest, bundle_path, base_url))
    entries.sort(key=lambda item: item["id"])
    return entries


def write_catalog(entries: list, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "packs": entries,
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Cordum pack bundles and catalog.")
    parser.add_argument("--packs-dir", default=str(PACKS_DIR), help="Directory containing pack folders.")
    parser.add_argument("--public-dir", default=str(PUBLIC_DIR), help="Output directory for bundles + catalog.")
    parser.add_argument("--base-url", default=os.environ.get("PACKS_BASE_URL", "https://packs.cordum.io"))
    parser.add_argument("--domain", default=os.environ.get("PACKS_DOMAIN", "packs.cordum.io"))
    parser.add_argument("--clean", action="store_true", help="Remove existing public output before building.")
    args = parser.parse_args()

    packs_dir = Path(args.packs_dir)
    public_dir = Path(args.public_dir)
    base_url = str(args.base_url).rstrip("/")
    if not packs_dir.exists():
        print(f"packs dir not found: {packs_dir}", file=sys.stderr)
        return 1
    if args.clean and public_dir.exists():
        for child in public_dir.iterdir():
            if child.is_dir():
                for path in child.rglob("*"):
                    if path.is_file():
                        path.unlink()
                for path in sorted(child.rglob("*"), reverse=True):
                    if path.is_dir():
                        path.rmdir()
            else:
                child.unlink()

    entries = build_catalog(packs_dir, base_url)
    public_dir.mkdir(parents=True, exist_ok=True)
    write_catalog(entries, public_dir / "catalog.json")

    domain = str(args.domain).strip()
    if domain:
        (public_dir / "CNAME").write_text(domain + "\n", encoding="utf-8")
    print(f"built {len(entries)} pack(s) into {public_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
