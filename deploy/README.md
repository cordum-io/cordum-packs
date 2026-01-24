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

## Logged fields (JSON)

- `event`: `catalog_fetch` or `pack_download`
- `pack_id`, `pack_version` (for pack downloads)
- `install_id` (from `?install_id=` query param, avoid secrets)
- `ts`, `method`, `host`, `uri`, `status`, `bytes`, `request_time`
- `remote_addr`, `xff`, `cf_ip`, `cf_country`, `cf_ray`
- `user_agent`, `referer`, `accept_language`, `tls_protocol`, `tls_cipher`

## Privacy note

These logs include IP address and user agent data. If you enable telemetry on a
public service, ensure your privacy notice and retention policy cover these
fields.
