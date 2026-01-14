# Cordum MCP Client

This pack lets Cordum workflows call external MCP servers (stdio or HTTP) through a policy-gated job topic.
Workers are deployed separately and should be configured with named servers.

## What you get

- **MCP client worker**: calls tools/resources on external MCP servers.
- **Governed access**: read is allowed by default; write requires approval.
- **Reusable workflow**: a minimal workflow template for production integrations.

## Runtime component

The pack runtime is the `cordum-mcp-client` worker in `cmd/cordum-mcp-client`.
Installing the pack only registers workflows/schemas; you must run or deploy the
worker so `job.mcp-client.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/mcp-client/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/mcp-client

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_MCP_CLIENT_SERVERS='[{"name":"local-mcp","transport":"stdio","command":"/usr/local/bin/mcp-server"}]' \

go run ./cmd/cordum-mcp-client
```

## Environment

- `CORDUM_GATEWAY_URL` (default `http://localhost:8081`)
- `CORDUM_API_KEY` (optional; required for enterprise installs)
- `CORDUM_NATS_URL` (default `nats://localhost:4222`)
- `CORDUM_REDIS_URL` (default `redis://localhost:6379`)
- `CORDUM_MCP_CLIENT_POOL` (default `mcp-client`)
- `CORDUM_MCP_CLIENT_QUEUE` (default `mcp-client`)
- `CORDUM_MCP_CLIENT_SUBJECTS` (default `job.mcp-client.*`)
- `CORDUM_MCP_CLIENT_JOB_TOPIC` (default `job.mcp-client.call`)
- `CORDUM_MCP_CLIENT_PACK_ID` (default `mcp-client`)
- `CORDUM_MCP_CLIENT_NAME` (default `cordum-mcp-client`)
- `CORDUM_MCP_CLIENT_VERSION` (default `0.1.0`)
- `CORDUM_MCP_CLIENT_CALL_TIMEOUT` (default `60s`)
- `CORDUM_MCP_CLIENT_PROTOCOL_VERSION` (default `2025-11-25`)
- `CORDUM_MCP_CLIENT_SERVERS` (JSON array of named MCP servers)
- `CORDUM_MCP_CLIENT_ALLOW_INLINE_SERVER` (default `false`)
- `CORDUM_MCP_CLIENT_ALLOW_INLINE_AUTH` (default `false`)
- `CORDUM_MCP_CLIENT_MAX_PARALLEL` (default `0` = unlimited)

### Server configuration

`CORDUM_MCP_CLIENT_SERVERS` accepts a JSON array:

```json
[
  {
    "name": "local-mcp",
    "transport": "stdio",
    "command": "/usr/local/bin/mcp-server",
    "args": ["--flag"],
    "env": {"FOO": "BAR"},
    "headers": {"X-API-Key": "..."},
    "allow_tools": ["tool.read", "tool.write"],
    "deny_tools": ["tool.delete"],
    "timeout_seconds": 45,
    "protocol_version": "2025-11-25"
  }
]
```

## MCP call input

The worker expects job input matching the `McpCallInput` schema. The simplest form:

```json
{
  "server": "local-mcp",
  "method": "tools/call",
  "tool": "demo.echo",
  "arguments": {"message": "hello"}
}
```

If `CORDUM_MCP_CLIENT_ALLOW_INLINE_SERVER=true`, you may include inline server details:

```json
{
  "transport": "http",
  "url": "https://mcp.example.com",
  "method": "tools/call",
  "tool": "demo.echo",
  "arguments": {"message": "hello"}
}
```

## Auth options

For HTTP servers, the worker can derive auth headers from `auth`:

- API key: `api_key` + optional `api_key_header` (default `X-API-Key`)
- Bearer token: `bearer`
- Basic auth: `basic_username` + `basic_password`
- OAuth client credentials: `oauth.token_url`, `oauth.client_id`, `oauth.client_secret`

Prefer environment-backed secrets:

```json
{
  "server": "local-mcp",
  "method": "tools/call",
  "tool": "demo.echo",
  "arguments": {"message": "hello"},
  "auth": {
    "api_key_env": "MCP_API_KEY"
  }
}
```

Set `CORDUM_MCP_CLIENT_ALLOW_INLINE_AUTH=true` to allow raw secrets in job input.

## Security

- By default, **only named servers** from `CORDUM_MCP_CLIENT_SERVERS` are allowed.
- Tool allow/deny lists can be set per server.
- Policy fragment enforces read allow, write approval, secrets approval.

## License

BUSL-1.1 (same as Cordum core).
