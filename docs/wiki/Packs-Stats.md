# Packs Stats

Tags: stats, telemetry, packs

This page documents the stats endpoint at `packs.cordum.io/stats/`.

## What you see

- Live users (unique IPs in last 5 minutes, catalog views + pack downloads)
- Active users (unique IPs in last hour)
- Unique users (24 hours and 7 days)
- Pack downloads (24 hours)

Counts are derived from nginx access logs and only include aggregate totals.

## Operations

- Generator: `tools/stats/packs_log_stats.py`
- Output: `/var/www/packs.cordum.io/stats/stats.json`
- Frequency: run via cron (recommended every 5 minutes)
