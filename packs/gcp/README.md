# GCP Pack

Google Cloud integration for Cordum — Cloud Functions, Cloud Storage, Pub/Sub, Compute Engine, Monitoring, Secret Manager, and IAM.

## Services & Actions

| Service | Read Actions | Write Actions |
|---------|-------------|---------------|
| **Cloud Functions** | get_function, list_functions | call |
| **Cloud Storage** | get_object, list_objects, list_buckets | upload_object, delete_object |
| **Pub/Sub** | list_topics, list_subscriptions, pull | publish |
| **Compute Engine** | list_instances, get_instance, aggregated_list_instances | — |
| **Monitoring** | list_time_series, list_metric_descriptors, list_alert_policies | — |
| **Secret Manager** | access_secret_version, list_secrets, get_secret | — |
| **IAM** | get_iam_policy, list_roles, list_service_accounts | — |

## Topics & Policy

| Topic | Actions | Policy |
|-------|---------|--------|
| `job.gcp.read` | All read/list/get/pull actions | ALLOW |
| `job.gcp.write` | functions.call, storage.upload_object, storage.delete_object, pubsub.publish | REQUIRE_APPROVAL |

Write actions sent to `job.gcp.read` are rejected by the worker.

## Authentication

The pack uses official `google-cloud-go` clients and supports Application Default Credentials (ADC):

1. Explicit `credentials_file` on the selected profile
2. Credentials file from `credentials_file_env` (defaults to `GOOGLE_APPLICATION_CREDENTIALS` on the default profile)
3. Standard ADC sources such as `gcloud auth application-default login`, workload identity, or metadata server credentials
4. Optional service-account impersonation via `impersonate_sa` / `CORDUM_GCP_IMPERSONATE_SERVICE_ACCOUNT`

## Quick Start

```bash
# 1. Set a default project and credentials
export GCP_PROJECT_ID=my-project
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# 2. Build
cd packs/gcp
go build -o cordum-gcp ./cmd/cordum-gcp/

# 3. Run (requires NATS + Redis)
./cordum-gcp
```

## Example: Cloud Function Call

Submit to `job.gcp.write`:

```json
{
  "action": "functions.call",
  "project_id": "my-project",
  "location": "us-central1",
  "params": {
    "function_name": "process-order",
    "payload": {
      "order_id": 42
    }
  }
}
```

## Example: Storage Object Download

Submit to `job.gcp.read`:

```json
{
  "action": "storage.get_object",
  "params": {
    "bucket": "my-bucket",
    "object_name": "reports/daily.json"
  }
}
```

The response includes `data_base64`, and `data` when the payload is valid UTF-8.

## Example: Pub/Sub Pull

Submit to `job.gcp.read`:

```json
{
  "action": "pubsub.pull",
  "params": {
    "subscription": "orders-subscription",
    "max_messages": 5,
    "return_immediately": true
  }
}
```

## Action & Project Restrictions

Use allow/deny lists to lock the worker down per profile:

```bash
# Only allow storage and pubsub operations
CORDUM_GCP_ALLOW_ACTIONS=storage.*,pubsub.*

# Block destructive storage deletes
CORDUM_GCP_DENY_ACTIONS=storage.delete_object

# Restrict accessible projects
CORDUM_GCP_ALLOWED_PROJECTS=dev-*,shared-observability
CORDUM_GCP_DENIED_PROJECTS=prod-*
```

Deny rules take priority over allow rules.

## Multi-Project Profiles

```bash
CORDUM_GCP_PROFILES='[
  {
    "name": "prod",
    "project_id": "prod-project",
    "location": "us-central1",
    "credentials_file_env": "PROD_GOOGLE_APPLICATION_CREDENTIALS",
    "impersonate_sa": "cordum-prod@prod-project.iam.gserviceaccount.com",
    "allow_actions": ["storage.*", "pubsub.*"],
    "allowed_projects": ["prod-project"]
  },
  {
    "name": "staging",
    "project_id": "staging-project",
    "location": "us-east1",
    "allow_actions": ["functions.*", "compute.*"]
  }
]'
```

Select a profile in the request payload:

```json
{
  "profile": "prod",
  "action": "storage.list_buckets"
}
```

## Environment Variables

See [`deploy/env.example`](deploy/env.example) for the full list.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GCP_PROJECT_ID` | Yes* | — | Default GCP project |
| `GOOGLE_APPLICATION_CREDENTIALS` | No | — | Service account JSON for ADC |
| `CORDUM_GCP_DEFAULT_LOCATION` | No | `global` | Default region/location override |
| `CORDUM_GCP_IMPERSONATE_SERVICE_ACCOUNT` | No | — | Service account to impersonate |
| `CORDUM_GCP_ALLOW_ACTIONS` | No | (all) | Action allow list (globs) |
| `CORDUM_GCP_DENY_ACTIONS` | No | (none) | Action deny list (globs) |
| `CORDUM_GCP_ALLOWED_PROJECTS` | No | (all) | Project allow list (globs) |
| `CORDUM_GCP_DENIED_PROJECTS` | No | (none) | Project deny list (globs) |

*Not required when project resolution happens via the selected profile.

## Security

- Uses official `google-cloud-go` clients instead of raw REST calls
- Supports ADC and optional service-account impersonation
- Enforces topic-intent separation for write actions
- Supports per-profile action allow/deny rules
- Supports per-profile project allow/deny rules
- Uses structured logging and request timeouts
- Returns object payloads as base64-safe data for binary compatibility
