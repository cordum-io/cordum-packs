# Cordum Sentry Pack

Connect Cordum workflows to Sentry issues, releases, and alert routing actions with governed access.

## Runtime component

The runtime is the `cordum-sentry` worker in `cmd/cordum-sentry`. Installing the pack only registers workflows/schemas; you must run or deploy the worker so `job.sentry.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/sentry/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/sentry

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_SENTRY_TOKEN_ENV=SENTRY_TOKEN \
CORDUM_SENTRY_ALLOWED_ORGS=my-org \

SENTRY_TOKEN=sntrys_*** \

go run ./cmd/cordum-sentry
```

See `deploy/env.example` for the full list of environment variables.

## Supported actions

Read actions (use `job.sentry.read`):

- `organizations.list`
- `projects.list`
- `issues.list`
- `issues.get`
- `events.list`
- `releases.list`
- `releases.get`

Write actions (use `job.sentry.write`):

- `issues.update`
- `issues.resolve`
- `issues.ignore`
- `issues.unresolve`
- `issues.mute`
- `issues.unmute`
- `releases.create`
- `releases.update`
- `releases.deploys.create`

## Action parameters

`issues.list`:

```json
{
  "action": "issues.list",
  "params": {
    "org": "my-org",
    "project": "my-project",
    "query": "is:unresolved"
  }
}
```

`issues.resolve`:

```json
{
  "action": "issues.resolve",
  "params": {
    "issue_id": "1234567890"
  }
}
```

`releases.create`:

```json
{
  "action": "releases.create",
  "params": {
    "org": "my-org",
    "version": "1.2.3",
    "projects": ["my-project"],
    "dateReleased": "2025-01-15T12:00:00Z"
  }
}
```

## Security

- Use `CORDUM_SENTRY_ALLOWED_ORGS` and `CORDUM_SENTRY_DENIED_ORGS` to constrain org access.
- Use `CORDUM_SENTRY_ALLOWED_PROJECTS` and `CORDUM_SENTRY_DENIED_PROJECTS` to constrain projects (e.g. `my-org/*`).
- Write actions require approval by default (per pack policy fragment).
