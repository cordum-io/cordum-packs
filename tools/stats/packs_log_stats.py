#!/usr/bin/env python3
import argparse
import datetime as dt
import gzip
import json
import os
import re
import sys
from glob import glob
from pathlib import Path

LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+) '
    r'(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+'
)
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_window(token: str) -> tuple[str, int]:
    raw = token.strip().lower()
    if not raw:
        raise ValueError("empty window token")
    if raw.endswith("m"):
        minutes = int(raw[:-1])
    elif raw.endswith("h"):
        minutes = int(raw[:-1]) * 60
    elif raw.endswith("d"):
        minutes = int(raw[:-1]) * 60 * 24
    else:
        raise ValueError(f"invalid window token: {token}")
    if minutes <= 0:
        raise ValueError(f"window must be positive: {token}")
    return raw, minutes


def iter_lines(path: Path):
    if path.suffix == ".gz":
        opener = gzip.open
    else:
        opener = open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line


def parse_line(line: str):
    match = LOG_RE.match(line)
    if not match:
        return None
    try:
        ts = dt.datetime.strptime(match.group("time"), TIME_FORMAT)
    except ValueError:
        return None
    path = match.group("path").split("?", 1)[0]
    return {
        "ip": match.group("ip"),
        "ts": ts,
        "method": match.group("method"),
        "path": path,
        "status": match.group("status"),
    }


def load_catalog(path: Path):
    if not path.exists():
        return {"error": f"catalog not found: {path}"}
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return {"error": f"catalog read failed: {exc}"}
    packs = payload.get("packs", [])
    return {
        "pack_count": len(packs) if isinstance(packs, list) else 0,
        "updated_at": payload.get("updated_at") or "",
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate packs stats from nginx logs.")
    parser.add_argument(
        "--logs",
        default="/var/log/nginx/packs.cordum.io.access.log*,/var/log/nginx/access.log*",
        help="Comma-separated list of log glob patterns.",
    )
    parser.add_argument(
        "--catalog",
        default="/var/www/packs.cordum.io/catalog.json",
        help="Path to catalog.json.",
    )
    parser.add_argument(
        "--catalog-url",
        default="https://packs.cordum.io/catalog.json",
        help="Public URL for the catalog.",
    )
    parser.add_argument(
        "--windows",
        default="5m,1h,24h,7d",
        help="Comma-separated window list (e.g. 5m,1h,24h,7d).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file path.",
    )
    args = parser.parse_args(argv)

    windows = dict(parse_window(token) for token in args.windows.split(",") if token.strip())
    thresholds = {}
    now = dt.datetime.now(dt.timezone.utc)
    max_window = max(windows.values())
    cutoff = now - dt.timedelta(minutes=max_window)
    for key, minutes in windows.items():
        thresholds[key] = now - dt.timedelta(minutes=minutes)

    download_ips = {key: set() for key in windows}
    catalog_ips = {key: set() for key in windows}
    downloads = {key: 0 for key in windows}

    patterns = [pattern.strip() for pattern in args.logs.split(",") if pattern.strip()]
    paths = []
    for pattern in patterns:
        paths.extend(Path(p) for p in glob(pattern))
    paths = sorted(set(paths))

    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        for line in iter_lines(path):
            record = parse_line(line)
            if not record:
                continue
            ts = record["ts"]
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=dt.timezone.utc)
            if ts < cutoff:
                continue
            status = record["status"]
            if status not in {"200", "206", "304"}:
                continue
            path_value = record["path"]
            is_pack = path_value.startswith("/packs/") and path_value.endswith(".tgz")
            is_catalog = path_value == "/catalog.json"
            if not is_pack and not is_catalog:
                continue
            for key, threshold in thresholds.items():
                if ts < threshold:
                    continue
                if is_pack:
                    download_ips[key].add(record["ip"])
                    downloads[key] += 1
                if is_catalog:
                    catalog_ips[key].add(record["ip"])

    catalog = load_catalog(Path(args.catalog))
    catalog["url"] = args.catalog_url

    payload = {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "windows_minutes": windows,
        "unique_downloaders": {key: len(value) for key, value in download_ips.items()},
        "unique_catalog_viewers": {key: len(value) for key, value in catalog_ips.items()},
        "downloads": downloads,
        "catalog": catalog,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(".tmp")
    temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temp_path, output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
