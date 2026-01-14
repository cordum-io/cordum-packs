# Cordum Jira Pack

Production-ready Jira read/write workflows routed through Cordum's policy engine.
Workers are deployed separately and authenticated with Jira API tokens.

## What you get

- **Jira worker**: calls Jira REST APIs with audit-friendly job results.
- **Governed access**: read is allowed by default; write requires approval.
- **Workflow templates**: generic read/write workflows for Jira actions.

## Runtime component

The pack runtime is the `cordum-jira` worker in `cmd/cordum-jira`. Installing
the pack only registers workflows/schemas; you must run or deploy the worker so
`job.jira.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/jira/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/jira

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_JIRA_BASE_URL=https://your-domain.atlassian.net \
CORDUM_JIRA_USERNAME_ENV=JIRA_USER \
CORDUM_JIRA_TOKEN_ENV=JIRA_TOKEN \
CORDUM_JIRA_ALLOWED_PROJECTS=OPS,ENG \

JIRA_USER=user@example.com \
JIRA_TOKEN=*** \

go run ./cmd/cordum-jira
```

## Environment

- `CORDUM_GATEWAY_URL` (default `http://localhost:8081`)
- `CORDUM_API_KEY` (optional; required for enterprise installs)
- `CORDUM_NATS_URL` (default `nats://localhost:4222`)
- `CORDUM_REDIS_URL` (default `redis://localhost:6379`)
- `CORDUM_JIRA_POOL` (default `jira`)
- `CORDUM_JIRA_QUEUE` (default `jira`)
- `CORDUM_JIRA_SUBJECTS` (default `job.jira.*`)
- `CORDUM_JIRA_MAX_PARALLEL` (default `0` = unlimited)
- `CORDUM_JIRA_REQUEST_TIMEOUT` (default `45s`)
- `CORDUM_JIRA_RESULT_TTL` (optional; example `24h`)
- `CORDUM_JIRA_ALLOW_INLINE_AUTH` (default `false`)
- `CORDUM_JIRA_DEFAULT_PROFILE` (default `default`)

### Default profile (env-based)

If `CORDUM_JIRA_PROFILES` is not set, the worker builds a single `default` profile from:

- `CORDUM_JIRA_BASE_URL` (default `https://example.atlassian.net`)
- `CORDUM_JIRA_USERNAME` or `CORDUM_JIRA_USERNAME_ENV`
- `CORDUM_JIRA_TOKEN` or `CORDUM_JIRA_TOKEN_ENV`
- `CORDUM_JIRA_TOKEN_TYPE` (default `basic`; supports `basic` or `bearer`)
- `CORDUM_JIRA_ALLOWED_PROJECTS` (comma-separated allowlist)
- `CORDUM_JIRA_DENIED_PROJECTS` (comma-separated denylist)
- `CORDUM_JIRA_ALLOW_ACTIONS` (comma-separated allowlist)
- `CORDUM_JIRA_DENY_ACTIONS` (comma-separated denylist)
- `CORDUM_JIRA_USER_AGENT` (default `cordum-jira-worker/0.1.0`)

### Profiles (recommended)

Define multiple profiles using `CORDUM_JIRA_PROFILES`:

```json
[
  {
    "name": "default",
    "base_url": "https://your-domain.atlassian.net",
    "username_env": "JIRA_USER",
    "token_env": "JIRA_TOKEN",
    "allowed_projects": ["OPS", "ENG"],
    "allow_actions": ["issues.*", "projects.*"]
  }
]
```

## Supported actions

Read actions (use `job.jira.read`):

- `issues.get`
- `issues.search`
- `projects.list`
- `projects.get`
- `users.get`
- `fields.list`
- `issuetypes.list`

Write actions (use `job.jira.write`):

- `issues.create`
- `issues.comment`
- `issues.transition`
- `issues.assign`
- `issues.update`

Notes:
- If project allowlists are configured, include `project` in params or use issue keys (e.g., `OPS-123`) so the worker can enforce policy.
- `issues.search` requires a `jql` param.

## Job input

The worker expects `JiraActionInput` payloads. Example:

```json
{
  "profile": "default",
  "action": "issues.create",
  "params": {
    "fields": {
      "project": {"key": "OPS"},
      "summary": "Investigate latency",
      "issuetype": {"name": "Incident"}
    }
  }
}
```

If `CORDUM_JIRA_ALLOW_INLINE_AUTH=true`, you may include `auth`:

```json
{
  "profile": "default",
  "action": "issues.get",
  "params": {"issue": "OPS-123"},
  "auth": {
    "username_env": "JIRA_USER",
    "token_env": "JIRA_TOKEN"
  }
}
```

## Security

- **Default policy**: read is allowed, write requires approval.
- **Allow/deny lists**: enforce action and project allowlists to limit scope.
- **Inline auth**: disabled by default; use profiles for production.

## License

BUSL-1.1 (same as Cordum core).
