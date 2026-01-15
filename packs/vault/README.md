# Cordum Vault Pack

Resolve Vault secrets and dynamic credentials with governed access and policy enforcement.

## Runtime component

The runtime is the `cordum-vault` worker in `cmd/cordum-vault`. Installing the pack only registers workflows/schemas; you must run or deploy the worker so `job.vault.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/vault/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/vault

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_VAULT_TOKEN_ENV=VAULT_TOKEN \
CORDUM_VAULT_ALLOWED_PATHS=secret/* \

VAULT_TOKEN=hvs.*** \

go run ./cmd/cordum-vault
```

See `deploy/env.example` for the full list of environment variables.

## Supported actions

All actions use `job.vault.read`:

- `secrets.read`
- `secrets.list`
- `auth.token.lookup`
- `credentials.generate`

## Action parameters

`secrets.read` (KV v2 example):

```json
{
  "action": "secrets.read",
  "params": {
    "path": "secret/app",
    "kv_version": 2
  }
}
```

`secrets.list`:

```json
{
  "action": "secrets.list",
  "params": {
    "path": "secret/"
  }
}
```

`credentials.generate`:

```json
{
  "action": "credentials.generate",
  "params": {
    "path": "database/creds/readonly"
  }
}
```

## Security

- Use `CORDUM_VAULT_ALLOWED_PATHS` and `CORDUM_VAULT_DENIED_PATHS` to scope which secrets are accessible.
- The pack policy requires approval for all `job.vault.read` requests by default.
