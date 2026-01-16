# Cordum GitLab Pack

Connect Cordum workflows to GitLab projects, issues, merge requests, and pipelines with governed access.

## Runtime component

The runtime is the `cordum-gitlab` worker in `cmd/cordum-gitlab`. Installing the pack only registers workflows/schemas; you must run or deploy the worker so `job.gitlab.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/gitlab/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/gitlab

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_GITLAB_TOKEN_ENV=GITLAB_TOKEN \
CORDUM_GITLAB_ALLOWED_PROJECTS=group/project \

GITLAB_TOKEN=glpat-*** \

go run ./cmd/cordum-gitlab
```

See `deploy/env.example` for the full list of environment variables.

## Supported actions

Read actions (use `job.gitlab.read`):

- `projects.list`
- `projects.get`
- `issues.list`
- `issues.get`
- `merge_requests.list`
- `merge_requests.get`
- `pipelines.list`
- `pipelines.get`
- `branches.list`

Write actions (use `job.gitlab.write`):

- `issues.create`
- `issues.update`
- `merge_requests.create`
- `merge_requests.update`
- `pipelines.run`

## Action parameters

`issues.list`:

```json
{
  "action": "issues.list",
  "params": {
    "project": "group/project",
    "state": "opened",
    "per_page": 20
  }
}
```

`merge_requests.create`:

```json
{
  "action": "merge_requests.create",
  "params": {
    "project": "group/project",
    "source_branch": "feature",
    "target_branch": "main",
    "title": "Add new integration"
  }
}
```

`pipelines.run`:

```json
{
  "action": "pipelines.run",
  "params": {
    "project": "group/project",
    "ref": "main"
  }
}
```

## Security

- Use `CORDUM_GITLAB_ALLOWED_PROJECTS` and `CORDUM_GITLAB_DENIED_PROJECTS` to constrain project access.
- Use `CORDUM_GITLAB_ALLOW_ACTIONS` and `CORDUM_GITLAB_DENY_ACTIONS` to constrain actions per profile.
- Write actions require approval by default (per pack policy fragment).
