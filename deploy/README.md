# packs.cordum.io telemetry

This repo serves a static catalog and pack bundles. Telemetry is collected via
standard HTTP access logs on the packs.cordum.io server. The config below logs
only `catalog.json` fetches and `pack.tgz` downloads in JSON format.

## Nginx install (manual)

1) Copy the telemetry config into the Nginx http context (conf.d is usually
   included there):

```
sudo cp deploy/nginx/packs.cordum.io.telemetry.conf \
  /etc/nginx/conf.d/packs.cordum.io.telemetry.conf
```

2) (Optional) Install logrotate policy (update the user/group if needed):

```
sudo cp deploy/logrotate/packs.cordum.io /etc/logrotate.d/packs.cordum.io
```

3) Validate + reload:

```
sudo nginx -t
sudo systemctl reload nginx
```

## GitHub Actions deploy (optional)

The publish workflow can install telemetry config during `deploy_server` when
enabled.

Set these repository secrets or variables:
- `PACKS_TELEMETRY_INSTALL=1`
- `PACKS_TELEMETRY_CONF_PATH` (default `/etc/nginx/conf.d/packs.cordum.io.telemetry.conf`)
- `PACKS_TELEMETRY_LOGROTATE_PATH` (default `/etc/logrotate.d/packs.cordum.io`)
- `PACKS_TELEMETRY_TMP` (default `/tmp/cordum-packs-telemetry`)


## Private stats dashboard (basic auth)

This repo ships a small stats page
Tip: for accurate unique install counts, append `?install_id=<uuid>` to the catalog URL configured in Cordum.
 and a log parser to summarize the last 7 days
of activity. It reads the JSON access log and writes `/stats/active.json`.

Files:
- `deploy/scripts/build_stats.py`
- `deploy/stats/index.html`
- `deploy/cron/cordum-packs-stats`
- `deploy/nginx/packs.cordum.io.stats.location.conf`

### Install manually

1) Copy the stats page + parser to the server:

```
sudo mkdir -p /opt/cordum-packs /var/www/packs.cordum.io/stats
sudo cp deploy/scripts/build_stats.py /opt/cordum-packs/build_stats.py
sudo cp deploy/stats/index.html /var/www/packs.cordum.io/stats/index.html
```

2) Install the cron job (runs every 15 minutes):

```
sudo cp deploy/cron/cordum-packs-stats /etc/cron.d/cordum-packs-stats
```

3) Protect `/stats/` with basic auth:

```
# Create htpasswd file (requires openssl)
printf '%s:%s\n' "admin" "$(openssl passwd -apr1 '<PASSWORD>')" | sudo tee /etc/nginx/.htpasswd_packs_stats

# Include the stats location snippet inside the packs.cordum.io server block
sudo cp deploy/nginx/packs.cordum.io.stats.location.conf /etc/nginx/snippets/

# Then add this line inside the server block:
#   include /etc/nginx/snippets/packs.cordum.io.stats.location.conf;
```

4) Reload Nginx:

```
sudo nginx -t && sudo systemctl reload nginx
```

### GitHub Actions deploy (optional)

Set these repository secrets or variables:
- `PACKS_STATS_INSTALL=1`
- `PACKS_STATS_ROOT` (default `/var/www/packs.cordum.io/stats`)
- `PACKS_STATS_SCRIPT_PATH` (default `/opt/cordum-packs/build_stats.py`)
- `PACKS_STATS_CRON_PATH` (default `/etc/cron.d/cordum-packs-stats`)
- `PACKS_STATS_HTPASSWD_PATH` (default `/etc/nginx/.htpasswd_packs_stats`)
- `PACKS_STATS_NGINX_SNIPPET_PATH` (default `/etc/nginx/snippets/packs.cordum.io.stats.location.conf`)
- `PACKS_STATS_BASIC_USER` + `PACKS_STATS_BASIC_PASS`
- `PACKS_STATS_TMP` (default `/tmp/cordum-packs-stats`)

Note: You still need to include the snippet in the server block once.

## Logged fields (JSON)

- `event`: `catalog_fetch` or `pack_download`
- `pack_id`, `pack_version` (for pack downloads)
- `install_id` (from `?install_id=` query param, avoid secrets)
- `ts`, `method`, `host`, `uri` (path only), `status`, `bytes`, `request_time`
- `remote_addr`, `xff`, `cf_ip`, `cf_country`, `cf_ray`
- `user_agent`, `accept_language`, `tls_protocol`, `tls_cipher`

## Privacy note

These logs include IP address and user agent data. If you enable telemetry on a
public service, ensure your privacy notice and retention policy cover these
fields.
