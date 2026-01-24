#!/usr/bin/env python3
import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

LOG_PATH = os.environ.get("PACKS_TELEMETRY_LOG", "/var/log/nginx/packs.cordum.io.access.json")
OUT_DIR = Path(os.environ.get("PACKS_STATS_DIR", "/var/www/packs.cordum.io/stats"))
WINDOW_DAYS = int(os.environ.get("PACKS_STATS_WINDOW_DAYS", "7"))


def parse_ts(value: str):
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def main() -> None:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=WINDOW_DAYS)

    counts = Counter()
    packs = Counter()
    pack_versions = Counter()
    countries = Counter()
    installs = {}
    by_day = Counter()
    recent_events = []

    log_path = Path(LOG_PATH)
    if not log_path.exists():
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        output = {
            "generated_at": now.isoformat(),
            "window_days": WINDOW_DAYS,
            "window_start": window_start.isoformat(),
            "window_end": now.isoformat(),
            "counts": {"events": 0, "catalog_fetches": 0, "pack_downloads": 0},
            "unique": {"install_ids": 0, "ips": 0, "ip_ua": 0, "countries": 0},
            "top": {"packs": [], "countries": [], "versions": []},
            "activity_by_day": [],
            "recent_events": [],
            "install_activity": {"total": 0, "recent": []},
            "note": "log file not found",
        }
        (OUT_DIR / "active.json").write_text(json.dumps(output, indent=2) + "
", encoding="utf-8")
        return

    unique_ips = set()
    unique_ip_ua = set()
    unique_install_ids = set()

    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts_raw = entry.get("ts")
            ts = parse_ts(ts_raw)
            if not ts or ts < window_start:
                continue

            counts["events"] += 1
            event = entry.get("event") or "other"
            if event == "catalog_fetch":
                counts["catalog_fetches"] += 1
            elif event == "pack_download":
                counts["pack_downloads"] += 1

            pack_id = entry.get("pack_id") or ""
            pack_version = entry.get("pack_version") or ""
            if pack_id:
                packs[pack_id] += 1
                if pack_version:
                    pack_versions[f"{pack_id}@{pack_version}"] += 1

            country = entry.get("cf_country") or ""
            if country:
                countries[country] += 1

            ip = entry.get("cf_ip") or entry.get("remote_addr") or ""
            ua = entry.get("user_agent") or ""
            if ip:
                unique_ips.add(ip)
            if ip or ua:
                unique_ip_ua.add(f"{ip}|{ua}")

            install_id = entry.get("install_id") or ""
            if install_id:
                unique_install_ids.add(install_id)

            day = ts.date().isoformat()
            by_day[day] += 1

            if install_id:
                stats = installs.get(install_id)
                if stats is None:
                    stats = {"install_id": install_id, "last_seen": ts, "catalog": 0, "downloads": 0}
                    installs[install_id] = stats
                if ts > stats["last_seen"]:
                    stats["last_seen"] = ts
                if event == "catalog_fetch":
                    stats["catalog"] += 1
                elif event == "pack_download":
                    stats["downloads"] += 1

            recent_events.append({
                "ts": ts.isoformat(),
                "event": event,
                "pack": pack_id or "-",
                "install_id": install_id or "",
                "country": country or "",
            })

            if len(recent_events) > 500:
                recent_events.sort(key=lambda item: item["ts"], reverse=True)
                recent_events = recent_events[:200]

    recent_events.sort(key=lambda item: item["ts"], reverse=True)
    recent_events = recent_events[:50]

    install_list = sorted(installs.values(), key=lambda item: item["last_seen"], reverse=True)
    install_recent = [
        {
            "install_id": item["install_id"],
            "last_seen": item["last_seen"].isoformat(),
            "catalog_fetches": item["catalog"],
            "pack_downloads": item["downloads"],
        }
        for item in install_list[:200]
    ]

    output = {
        "generated_at": now.isoformat(),
        "window_days": WINDOW_DAYS,
        "window_start": window_start.isoformat(),
        "window_end": now.isoformat(),
        "counts": {
            "events": counts["events"],
            "catalog_fetches": counts["catalog_fetches"],
            "pack_downloads": counts["pack_downloads"],
        },
        "unique": {
            "install_ids": len(unique_install_ids),
            "ips": len(unique_ips),
            "ip_ua": len(unique_ip_ua),
            "countries": len(countries),
        },
        "top": {
            "packs": [{"name": name, "count": count} for name, count in packs.most_common(12)],
            "countries": [{"name": name, "count": count} for name, count in countries.most_common(12)],
            "versions": [{"name": name, "count": count} for name, count in pack_versions.most_common(12)],
        },
        "activity_by_day": [{"day": day, "count": count} for day, count in sorted(by_day.items())],
        "recent_events": recent_events,
        "install_activity": {
            "total": len(install_list),
            "recent": install_recent,
        },
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "active.json").write_text(json.dumps(output, indent=2) + "
", encoding="utf-8")


if __name__ == "__main__":
    main()
