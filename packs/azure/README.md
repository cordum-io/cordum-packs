# Azure Pack

Full Azure cloud integration for Cordum — Functions, Blob Storage, Service Bus, VMs, Monitor, Key Vault, and Entra ID.

## Services & Actions

| Service | Read Actions | Write Actions |
|---------|-------------|---------------|
| **Functions** | list_apps | invoke |
| **Blob Storage** | get, list, list_containers | upload, delete |
| **Service Bus** | peek | send |
| **Compute (VMs)** | list_vms, get_vm, get_vm_instance_view | — |
| **Monitor** | query_metrics, list_alert_rules | — |
| **Key Vault** | get_secret, list_secrets | — |
| **Entra ID** | get_user, list_users, list_groups | — |

## Topics & Policy

| Topic | Actions | Policy |
|-------|---------|--------|
| `job.azure.read` | All read/list/get actions | ALLOW |
| `job.azure.write` | invoke, upload, delete, send | REQUIRE_APPROVAL |

## Authentication

Uses `DefaultAzureCredential` which automatically chains:

1. **Environment variables** (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`)
2. **Managed Identity** (when running on Azure VMs, AKS, App Service)
3. **Azure CLI** (`az login`)
4. **Azure Developer CLI** (`azd auth login`)

## Quick Start

```bash
# 1. Set Azure credentials
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_SUBSCRIPTION_ID=...

# 2. Build
cd packs/azure
go build -o cordum-azure.exe ./cmd/cordum-azure/

# 3. Run
./cordum-azure.exe
```

## Example: Blob Download

```json
{
  "action": "blob.get",
  "params": {
    "storage_account": "mystorageaccount",
    "container": "mycontainer",
    "blob_name": "path/to/file.json"
  }
}
```

## Example: Key Vault Secret

```json
{
  "action": "keyvault.get_secret",
  "params": {
    "vault_name": "myvault",
    "secret_name": "database-password"
  }
}
```

## Example: Function Invoke

```json
{
  "action": "functions.invoke",
  "params": {
    "function_app": "my-function-app",
    "function_name": "ProcessOrder",
    "payload": {"order_id": 42}
  }
}
```

## Environment Variables

See [`deploy/env.example`](deploy/env.example) for the full list.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AZURE_TENANT_ID` | Yes | — | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | Yes* | — | Service principal client ID |
| `AZURE_CLIENT_SECRET` | Yes* | — | Service principal secret |
| `AZURE_SUBSCRIPTION_ID` | Yes | — | Default subscription ID |
| `CORDUM_AZURE_ALLOW_ACTIONS` | No | (all) | Action allow list (globs) |
| `CORDUM_AZURE_DENY_ACTIONS` | No | (none) | Action deny list (globs) |

*Not required when using managed identity or Azure CLI auth.

## Security

- All credentials via DefaultAzureCredential chain — never hardcoded
- Write actions require policy approval
- Topic-intent enforcement: write actions rejected on read topic
- Action allow/deny with glob patterns
- Per-scope token acquisition (management, storage, vault, graph, servicebus)
- REST API approach with azidentity — minimal dependency footprint
