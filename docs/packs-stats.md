# Packs Stats

Tags: stats, telemetry, packs

This repo ships a lightweight stats page for `packs.cordum.io/stats/`. It shows live user counts
based on unique IPs viewing `catalog.json` or downloading pack archives (`/packs/*/pack.tgz`).

## How it works

- A server-side cron job runs `tools/stats/packs_log_stats.py`.
- The script parses nginx access logs and emits `/var/www/packs.cordum.io/stats/stats.json`.
- The stats page fetches `stats.json` at runtime and renders live/active/24h/7d counts.

## Default windows

- Live users: 5 minutes
- Active users: 1 hour
- Unique users: 24 hours, 7 days

## Privacy

The JSON output only contains aggregate counts. No IPs are stored or served.
