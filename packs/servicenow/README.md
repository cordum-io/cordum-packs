# Cordum ServiceNow Pack

Work with ServiceNow incidents, change requests, and CMDB records using governed Cordum workflows.

## Runtime component

The runtime is the `cordum-servicenow` worker in `cmd/cordum-servicenow`. Installing the pack only registers workflows/schemas; you must run or deploy the worker so `job.servicenow.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/servicenow/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/servicenow

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_SERVICENOW_BASE_URL=https://instance.service-now.com \
CORDUM_SERVICENOW_USERNAME_ENV=SN_USER \
CORDUM_SERVICENOW_PASSWORD_ENV=SN_PASS \
SN_USER=api.user \
SN_PASS=secret \

go run ./cmd/cordum-servicenow
```

See `deploy/env.example` for the full list of environment variables.

## Supported actions

Read actions (use `job.servicenow.read`):

- `incidents.list`
- `incidents.get`
- `changes.list`
- `changes.get`
- `cmdb.list`
- `cmdb.get`

Write actions (use `job.servicenow.write`):

- `incidents.create`
- `incidents.update`
- `changes.create`
- `changes.update`

## Action parameters

`incidents.list`:

```json
{
  "action": "incidents.list",
  "params": {
    "sysparm_query": "state=1^priority=1",
    "sysparm_limit": 25
  }
}
```

`incidents.create`:

```json
{
  "action": "incidents.create",
  "params": {
    "short_description": "API latency spike",
    "category": "software",
    "severity": "2"
  }
}
```

`incidents.update`:

```json
{
  "action": "incidents.update",
  "params": {
    "sys_id": "abc123",
    "state": "2",
    "work_notes": "investigating"
  }
}
```

## Security

- Use `CORDUM_SERVICENOW_ALLOW_ACTIONS` and `CORDUM_SERVICENOW_DENY_ACTIONS` to constrain actions per profile.
- Write actions require approval by default (per pack policy fragment).
