# Cordum Slack Pack

Production-ready Slack read/write workflows routed through Cordum's policy engine.
Workers are deployed separately and authenticated with Slack bot tokens.

## What you get

- **Slack worker**: calls Slack Web API with audit-friendly job results.
- **Governed access**: read is allowed by default; write requires approval.
- **Workflow templates**: generic read/write workflows for Slack actions.

## Runtime component

The pack runtime is the `cordum-slack` worker in `cmd/cordum-slack`. Installing
the pack only registers workflows/schemas; you must run or deploy the worker so
`job.slack.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/slack/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/slack

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_SLACK_TOKEN_ENV=SLACK_BOT_TOKEN \
CORDUM_SLACK_ALLOWED_CHANNELS=C0123456789,C0987654321 \

SLACK_BOT_TOKEN=xoxb-*** \

go run ./cmd/cordum-slack
```

## Environment

- `CORDUM_GATEWAY_URL` (default `http://localhost:8081`)
- `CORDUM_API_KEY` (optional; required for enterprise installs)
- `CORDUM_NATS_URL` (default `nats://localhost:4222`)
- `CORDUM_REDIS_URL` (default `redis://localhost:6379`)
- `CORDUM_SLACK_POOL` (default `slack`)
- `CORDUM_SLACK_QUEUE` (default `slack`)
- `CORDUM_SLACK_SUBJECTS` (default `job.slack.*`)
- `CORDUM_SLACK_MAX_PARALLEL` (default `0` = unlimited)
- `CORDUM_SLACK_REQUEST_TIMEOUT` (default `45s`)
- `CORDUM_SLACK_RESULT_TTL` (optional; example `24h`)
- `CORDUM_SLACK_ALLOW_INLINE_AUTH` (default `false`)
- `CORDUM_SLACK_DEFAULT_PROFILE` (default `default`)

### Default profile (env-based)

If `CORDUM_SLACK_PROFILES` is not set, the worker builds a single `default` profile from:

- `CORDUM_SLACK_BASE_URL` (default `https://slack.com/api`)
- `CORDUM_SLACK_TOKEN` or `CORDUM_SLACK_TOKEN_ENV`
- `CORDUM_SLACK_ALLOWED_CHANNELS` (comma-separated allowlist, supports glob patterns)
- `CORDUM_SLACK_DENIED_CHANNELS` (comma-separated denylist)
- `CORDUM_SLACK_ALLOW_ACTIONS` (comma-separated allowlist)
- `CORDUM_SLACK_DENY_ACTIONS` (comma-separated denylist)
- `CORDUM_SLACK_USER_AGENT` (default `cordum-slack-worker/0.1.0`)

### Profiles (recommended)

Define multiple profiles using `CORDUM_SLACK_PROFILES`:

```json
[
  {
    "name": "default",
    "base_url": "https://slack.com/api",
    "token_env": "SLACK_BOT_TOKEN",
    "allowed_channels": ["C0123456789"],
    "allow_actions": ["chat.*", "conversations.list", "users.info"]
  }
]
```

## Supported actions

Read actions (use `job.slack.read`):

- `auth.test`
- `conversations.list`
- `conversations.info`
- `conversations.history`
- `conversations.replies`
- `conversations.members`
- `conversations.listConnectedTeams`
- `users.list`
- `users.info`
- `team.info`
- `chat.getPermalink`
- `search.messages`
- `pins.list`
- `files.list`
- `files.info`
- `usergroups.list`
- `bookmarks.list`

Write actions (use `job.slack.write`):

- `chat.postMessage`
- `chat.update`
- `chat.delete`
- `chat.postEphemeral`
- `chat.scheduleMessage`
- `chat.deleteScheduledMessage`
- `reactions.add`
- `reactions.remove`
- `conversations.create`
- `conversations.rename`
- `conversations.invite`
- `conversations.kick`
- `conversations.setPurpose`
- `conversations.setTopic`
- `conversations.archive`
- `conversations.unarchive`
- `conversations.leave`
- `pins.add`
- `pins.remove`
- `usergroups.create`
- `usergroups.update`
- `usergroups.users.update`
- `bookmarks.add`
- `bookmarks.edit`
- `bookmarks.remove`

Notes:
- `files.upload` is not supported (multipart upload is out of scope for this worker).
- Actions must include required parameters for the Slack API (e.g., `channel`, `ts`, `text`).

## Job input

The worker expects `SlackActionInput` payloads. Example:

```json
{
  "profile": "default",
  "action": "chat.postMessage",
  "params": {
    "channel": "C0123456789",
    "text": "Deployment finished."
  }
}
```

If `CORDUM_SLACK_ALLOW_INLINE_AUTH=true`, you may include `auth`:

```json
{
  "profile": "default",
  "action": "conversations.list",
  "params": {
    "limit": 50
  },
  "auth": {
    "token_env": "SLACK_BOT_TOKEN"
  }
}
```

## Security

- **Default policy**: read is allowed, write requires approval.
- **Allow/deny lists**: enforce action and channel allowlists to limit scope.
- **Inline auth**: disabled by default; use profiles for production.

## License

BUSL-1.1 (same as Cordum core).
