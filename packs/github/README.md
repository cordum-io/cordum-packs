# Cordum GitHub Pack

Production-ready GitHub read/write workflows routed through Cordum's policy engine.
Workers are deployed separately and authenticated with GitHub tokens or GitHub App credentials.

## What you get

- **GitHub worker**: calls GitHub REST APIs with audit-friendly job results.
- **Governed access**: read is allowed by default; write requires approval.
- **Workflow template**: create issues through `github.issue.create`.

## Runtime component

The pack runtime is the `cordum-github` worker in `cmd/cordum-github`. Installing
the pack only registers workflows/schemas; you must run or deploy the worker so
`job.github.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/github/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/github

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_GITHUB_TOKEN_ENV=GITHUB_TOKEN \
CORDUM_GITHUB_ALLOWED_REPOS=cordum-io/cordum-packs \

GITHUB_TOKEN=ghp_example \

go run ./cmd/cordum-github
```

## Environment

- `CORDUM_GATEWAY_URL` (default `http://localhost:8081`)
- `CORDUM_API_KEY` (optional; required for enterprise installs)
- `CORDUM_NATS_URL` (default `nats://localhost:4222`)
- `CORDUM_REDIS_URL` (default `redis://localhost:6379`)
- `CORDUM_GITHUB_POOL` (default `github`)
- `CORDUM_GITHUB_QUEUE` (default `github`)
- `CORDUM_GITHUB_SUBJECTS` (default `job.github.*`)
- `CORDUM_GITHUB_MAX_PARALLEL` (default `0` = unlimited)
- `CORDUM_GITHUB_REQUEST_TIMEOUT` (default `45s`)
- `CORDUM_GITHUB_RESULT_TTL` (optional; example `24h`)
- `CORDUM_GITHUB_ALLOW_INLINE_AUTH` (default `false`)
- `CORDUM_GITHUB_DEFAULT_PROFILE` (default `default`)

### Default profile (env-based)

If `CORDUM_GITHUB_PROFILES` is not set, the worker builds a single `default` profile from:

- `CORDUM_GITHUB_BASE_URL` (default `https://api.github.com`)
- `CORDUM_GITHUB_TOKEN` or `CORDUM_GITHUB_TOKEN_ENV`
- `CORDUM_GITHUB_TOKEN_TYPE` (default `Bearer`)
- `CORDUM_GITHUB_ALLOWED_REPOS` (comma-separated allowlist, supports glob patterns like `org/*`)
- `CORDUM_GITHUB_DENIED_REPOS` (comma-separated denylist)
- `CORDUM_GITHUB_ALLOW_ACTIONS` (comma-separated allowlist)
- `CORDUM_GITHUB_DENY_ACTIONS` (comma-separated denylist)
- `CORDUM_GITHUB_API_VERSION` (default `2022-11-28`)
- `CORDUM_GITHUB_USER_AGENT` (default `cordum-github-worker/0.1.0`)

GitHub App credentials (optional):

- `CORDUM_GITHUB_APP_ID` or `CORDUM_GITHUB_APP_ID_ENV`
- `CORDUM_GITHUB_APP_PRIVATE_KEY` or `CORDUM_GITHUB_APP_PRIVATE_KEY_ENV`
- `CORDUM_GITHUB_APP_INSTALLATION_ID` or `CORDUM_GITHUB_APP_INSTALLATION_ID_ENV`

### Profiles (recommended)

Define multiple profiles using `CORDUM_GITHUB_PROFILES`:

```json
[
  {
    "name": "default",
    "base_url": "https://api.github.com",
    "token_env": "GITHUB_TOKEN",
    "allowed_repos": ["cordum-io/cordum-packs"],
    "allow_actions": ["issues.*", "pulls.get", "repos.get"]
  }
]
```

GitHub App profile example:

```json
[
  {
    "name": "app",
    "base_url": "https://api.github.com",
    "app": {
      "app_id": "123456",
      "app_private_key_env": "GITHUB_APP_KEY",
      "app_installation_id": "987654"
    },
    "allowed_repos": ["cordum-io/*"]
  }
]
```

## Supported actions

Read actions (use `job.github.read`):

- `repos.get`
- `issues.get`
- `issues.list`
- `pulls.get`
- `search.issues`
- `contents.get`

Write actions (use `job.github.write`):

- `issues.create`
- `issues.comment`
- `pulls.create`

All actions require `repository` (or `owner` + `repo`) so the worker can enforce repo allowlists. `search.issues` auto-scopes queries to `repo:owner/repo` when missing.

## Job input

The worker expects `GitHubActionInput` payloads. Example:

```json
{
  "profile": "default",
  "action": "issues.create",
  "repository": "cordum-io/cordum-packs",
  "title": "Docs cleanup",
  "body": "We should update the README",
  "labels": ["docs"]
}
```

If `CORDUM_GITHUB_ALLOW_INLINE_AUTH=true`, you may include `auth`:

```json
{
  "profile": "default",
  "action": "issues.create",
  "repository": "cordum-io/cordum-packs",
  "title": "Docs cleanup",
  "auth": {
    "token_env": "GITHUB_TOKEN"
  }
}
```

## Security

- **Default policy**: read is allowed, write requires approval.
- **Allow/deny lists**: enforce repo and action allowlists to limit scope.
- **Inline auth**: disabled by default; use profiles for production.

## License

BUSL-1.1 (same as Cordum core).
