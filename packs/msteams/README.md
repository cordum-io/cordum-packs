# Cordum Microsoft Teams Pack

Connect Cordum workflows to Microsoft Teams via the Microsoft Graph API, with governed read/write actions.

## Runtime component

The runtime is the `cordum-msteams` worker in `cmd/cordum-msteams`. Installing the pack only registers workflows/schemas; you must run or deploy the worker so `job.msteams.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/msteams/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/msteams

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_MSTEAMS_TOKEN_ENV=MSTEAMS_TOKEN \
CORDUM_MSTEAMS_ALLOWED_TEAMS=team-id \

MSTEAMS_TOKEN=eyJhbGciOi... \

go run ./cmd/cordum-msteams
```

See `deploy/env.example` for the full list of environment variables.

## Supported actions

Read actions (use `job.msteams.read`):

- `teams.list`
- `teams.get`
- `channels.list`
- `channels.get`
- `messages.list`

Write actions (use `job.msteams.write`):

- `messages.post`
- `replies.post`
- `channels.create`

## Action parameters

`messages.post`:

```json
{
  "action": "messages.post",
  "params": {
    "team_id": "team-id",
    "channel_id": "channel-id",
    "content": "Hello from Cordum"
  }
}
```

`channels.list`:

```json
{
  "action": "channels.list",
  "params": {
    "team_id": "team-id"
  }
}
```

## Security

- Use `CORDUM_MSTEAMS_ALLOWED_TEAMS` and `CORDUM_MSTEAMS_DENIED_TEAMS` to constrain team access.
- Use `CORDUM_MSTEAMS_ALLOWED_CHANNELS` and `CORDUM_MSTEAMS_DENIED_CHANNELS` to constrain channels.
- Write actions require approval by default (per pack policy fragment).
