#!/usr/bin/env python3
from __future__ import annotations

# Subprocess is needed for cordumctl; commands use argument lists, never a shell.
import argparse
import gzip
import hashlib
import json
import os
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PACKS_DIR = ROOT / "packs"
PUBLIC_DIR = ROOT / "public"
STATS_TEMPLATE = ROOT / "tools" / "templates" / "stats" / "index.html"
DEFAULT_PACKS_BASE_URL = "https://packs.cordum.io"


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


def is_sidecar_only(pack_dir: Path) -> bool:
    """Return true for catalogless integration dirs that only ship a sidecar."""

    try:
        visible_entries = {entry.name for entry in pack_dir.iterdir() if not entry.name.startswith(".")}
    except OSError:
        return False
    return visible_entries == {"sidecar"} and (pack_dir / "sidecar").is_dir()


def build_bundle(
    pack_root: Path, pack_id: str, version: str, public_dir: Path, signature: Path | None = None
) -> Path:
    out_dir = public_dir / "packs" / pack_id / version
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = out_dir / "pack.tgz"
    if bundle_path.exists():
        bundle_path.unlink()
    with bundle_path.open("wb") as raw_bundle, gzip.GzipFile(
        filename="", mode="wb", fileobj=raw_bundle, mtime=0
    ) as gz_bundle, tarfile.open(fileobj=gz_bundle, mode="w") as tar:
        paths = iter_bundle_files(pack_root)
        if signature is not None:
            paths = [path for path in paths if not path.name.startswith("pack.yaml.sig")]
            paths.append(signature)
        for path in paths:
            arcname = "pack.yaml.sig" if path == signature else path.relative_to(pack_root).as_posix()
            tarinfo = tar.gettarinfo(str(path), arcname=arcname)
            tarinfo.uid = 0
            tarinfo.gid = 0
            tarinfo.uname = ""
            tarinfo.gname = ""
            tarinfo.mtime = 0
            with path.open("rb") as handle:
                tar.addfile(tarinfo, handle)
    return bundle_path


def resolve_base_url(value: str | None) -> str:
    base_url = str(value or DEFAULT_PACKS_BASE_URL).strip().rstrip("/")
    return base_url or DEFAULT_PACKS_BASE_URL


def verify_bundle_digest(bundle_path: Path, expected_sha256: str) -> None:
    actual_sha256 = sha256_file(bundle_path)
    if actual_sha256 != expected_sha256:
        raise ValueError(
            f"bundle digest mismatch for {bundle_path}: catalog={expected_sha256} actual={actual_sha256}"
        )


def verify_catalog_digests(entries: list, public_dir: Path) -> None:
    for entry in entries:
        pack_id = str(entry["id"])
        version = str(entry["version"])
        bundle_path = public_dir / "packs" / pack_id / version / "pack.tgz"
        verify_bundle_digest(bundle_path, str(entry["sha256"]))


def run_cordumctl(cordumctl: str, *args: str) -> None:
    # Operator-selected executable; no shell. Capture output so key errors cannot leak material.
    subprocess.run([cordumctl, "pack", *args], check=True, capture_output=True)  # nosec B603


def verify_catalog_signatures(entries: list, public_dir: Path, trusted_key: Path, cordumctl: str) -> None:
    failures = []
    for entry in entries:
        pack_id, version = str(entry["id"]), str(entry["version"])
        bundle = public_dir / "packs" / pack_id / version / "pack.tgz"
        try:
            with tempfile.TemporaryDirectory() as target, tarfile.open(bundle) as archive:
                archive.extractall(target, filter="data")
                run_cordumctl(cordumctl, "verify-signature", target, "--key", str(trusted_key))
        except (OSError, subprocess.CalledProcessError, tarfile.TarError, ValueError):
            failures.append(f"{pack_id}@{version}")
    if failures:
        raise ValueError("pack signature verification failed: " + ", ".join(failures))


def iter_bundle_files(pack_root: Path) -> list[Path]:
    paths = []
    for path in sorted(pack_root.rglob("*"), key=lambda item: item.relative_to(pack_root).as_posix()):
        if not path.is_file() or should_skip(path, pack_root):
            continue
        paths.append(path)
    return paths


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


def build_catalog(
    packs_dir: Path, base_url: str, public_dir: Path,
    signing_key: Path | None = None, cordumctl: str = "cordumctl",
) -> list:
    entries = []
    for pack_dir in sorted(packs_dir.iterdir()):
        if pack_dir.is_symlink():
            print(f"skipping {pack_dir}: symlink is not a pack bundle", file=sys.stderr)
            continue
        try:
            if not pack_dir.is_dir():
                continue
        except OSError as exc:
            print(f"skipping {pack_dir}: cannot inspect entry ({exc})", file=sys.stderr)
            continue
        if should_skip(pack_dir, packs_dir):
            continue
        try:
            manifest, pack_root = find_manifest(pack_dir)
        except FileNotFoundError:
            if is_sidecar_only(pack_dir):
                print(f"skipping {pack_dir}: pack.yaml not found", file=sys.stderr)
                continue
            raise
        metadata = manifest.get("metadata") or {}
        pack_id = str(metadata.get("id") or "").strip()
        version = str(metadata.get("version") or "").strip()
        if not pack_id or not version:
            raise ValueError(f"pack metadata.id/version required in {pack_dir}")
        if signing_key is not None:
            with tempfile.TemporaryDirectory() as temp_dir:
                signature = Path(temp_dir) / "pack.yaml.sig"
                try:
                    run_cordumctl(cordumctl, "sign", str(pack_root), "--key", str(signing_key),
                                  "--out", str(signature))
                except (OSError, subprocess.CalledProcessError):
                    raise ValueError(f"pack signing failed: {pack_id}@{version}") from None
                bundle_path = build_bundle(pack_root, pack_id, version, public_dir, signature)
        else:
            bundle_path = build_bundle(pack_root, pack_id, version, public_dir)
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


def write_stats_page(public_dir: Path, pack_count: int, updated_at: str, catalog_url: str) -> None:
    if not STATS_TEMPLATE.exists():
        return
    target = public_dir / "stats" / "index.html"
    target.parent.mkdir(parents=True, exist_ok=True)
    template = STATS_TEMPLATE.read_text(encoding="utf-8")
    rendered = (
        template.replace("{{pack_count}}", str(pack_count))
        .replace("{{updated_at}}", updated_at)
        .replace("{{catalog_url}}", catalog_url)
    )
    target.write_text(rendered, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Cordum pack bundles and catalog.")
    parser.add_argument("--packs-dir", default=str(PACKS_DIR), help="Directory containing pack folders.")
    parser.add_argument("--public-dir", default=str(PUBLIC_DIR), help="Output directory for bundles + catalog.")
    parser.add_argument("--base-url", default=os.environ.get("PACKS_BASE_URL") or DEFAULT_PACKS_BASE_URL)
    parser.add_argument("--domain", default=os.environ.get("PACKS_DOMAIN") or "packs.cordum.io")
    parser.add_argument("--clean", action="store_true", help="Remove existing public output before building.")
    parser.add_argument("--signing-key", type=Path, help="Private pack signing key (outside the packs directory).")
    parser.add_argument("--trusted-key", type=Path, help="Public key required for a signed build.")
    parser.add_argument("--cordumctl", default="cordumctl", help="Path to cordumctl for signing and verification.")
    args = parser.parse_args()
    if args.signing_key is not None:
        (Path(args.public_dir) / "catalog.json").unlink(missing_ok=True)
        if args.trusted_key is None:
            parser.error("--trusted-key is required with --signing-key")
        if args.signing_key.resolve().is_relative_to(Path(args.packs_dir).resolve()):
            parser.error("--signing-key must be outside --packs-dir")
    return args


def main() -> int:
    args = parse_args()
    packs_dir = Path(args.packs_dir)
    public_dir = Path(args.public_dir)
    base_url = resolve_base_url(args.base_url)
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

    entries = build_catalog(packs_dir, base_url, public_dir, args.signing_key, args.cordumctl)
    verify_catalog_digests(entries, public_dir)
    if args.signing_key is not None:
        verify_catalog_signatures(entries, public_dir, args.trusted_key, args.cordumctl)
    public_dir.mkdir(parents=True, exist_ok=True)
    catalog_path = public_dir / "catalog.json"
    write_catalog(entries, catalog_path)
    catalog_payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    updated_at = str(catalog_payload.get("updated_at") or "")
    write_stats_page(public_dir, len(entries), updated_at, f"{base_url}/catalog.json")

    domain = str(args.domain).strip()
    if domain:
        (public_dir / "CNAME").write_text(domain + "\n", encoding="utf-8")
    print(f"built {len(entries)} pack(s) into {public_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
