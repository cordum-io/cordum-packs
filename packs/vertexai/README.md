# Vertex AI Pack

Google Vertex AI integration for Cordum — online prediction, raw prediction, Gemini generation, embeddings, batch prediction jobs, and training pipelines.

## Actions

| Action | Topic | Policy |
|--------|-------|--------|
| `predict.predict` | `job.vertexai.read` | ALLOW |
| `predict.raw_predict` | `job.vertexai.read` | ALLOW |
| `embed.embed_content` | `job.vertexai.read` | ALLOW |
| `generate.generate_content` | `job.vertexai.generate` | REQUIRE_APPROVAL |
| `batch.create_prediction_job` | `job.vertexai.write` | REQUIRE_APPROVAL |
| `batch.get_prediction_job` | `job.vertexai.write` | REQUIRE_APPROVAL |
| `batch.list_prediction_jobs` | `job.vertexai.write` | REQUIRE_APPROVAL |
| `training.create_pipeline` | `job.vertexai.write` | REQUIRE_APPROVAL |
| `training.get_pipeline` | `job.vertexai.write` | REQUIRE_APPROVAL |
| `training.list_pipelines` | `job.vertexai.write` | REQUIRE_APPROVAL |

Requests sent to the wrong topic are rejected by the worker.

## SDK Usage

This pack uses the official Google Cloud Go SDKs:

- `PredictionClient` for online prediction, raw prediction, Gemini generation, and embeddings
- `JobClient` for batch prediction jobs
- `PipelineClient` for training pipelines

Authentication follows the same ADC chain as the GCP pack:

1. Explicit `credentials_file` on the selected profile
2. Credentials file from `credentials_file_env` (the default profile falls back to `GOOGLE_APPLICATION_CREDENTIALS`)
3. Standard Application Default Credentials sources
4. Optional service-account impersonation via `impersonate_sa` / `CORDUM_VERTEXAI_IMPERSONATE_SERVICE_ACCOUNT`

## Quick Start

```bash
# 1. Set a default project and credentials
export GCP_PROJECT_ID=my-project
export VERTEX_LOCATION=us-central1
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# 2. Build
cd packs/vertexai
go build -o cordum-vertexai ./cmd/cordum-vertexai/

# 3. Run (requires NATS + Redis)
./cordum-vertexai
```

## Example: Gemini Generation Workflow

The pack ships an example workflow id: `vertex-gemini-workflow`.

Submit to `job.vertexai.generate`:

```json
{
  "action": "generate.generate_content",
  "project_id": "my-project",
  "location": "us-central1",
  "params": {
    "model": "gemini-2.5-flash",
    "prompt": "Summarize the attached report in five bullets.",
    "generation_config": {
      "temperature": 0.2,
      "max_tokens": 512
    }
  }
}
```

Responses include:

- `candidates`
- `finish_reason`
- `token_usage`
- `latency_ms` / `duration_ms`

## Example: Endpoint Prediction

Submit to `job.vertexai.read`:

```json
{
  "action": "predict.predict",
  "params": {
    "endpoint_id": "1234567890123456789",
    "instances": [
      {"text": "classify this ticket"}
    ],
    "parameters": {
      "temperature": 0.0
    }
  }
}
```

## Example: Embeddings

Submit to `job.vertexai.read`:

```json
{
  "action": "embed.embed_content",
  "params": {
    "model": "textembedding-gecko@003",
    "contents": [
      "cordum governance",
      "vertex ai embeddings"
    ],
    "task_type": "RETRIEVAL_DOCUMENT"
  }
}
```

## Example: Batch Prediction Job

Submit to `job.vertexai.write`:

```json
{
  "action": "batch.create_prediction_job",
  "params": {
    "model": "projects/my-project/locations/us-central1/models/1234567890",
    "input_uri": "gs://my-bucket/input.jsonl",
    "output_uri": "gs://my-bucket/predictions/",
    "machine_type": "n1-standard-4",
    "starting_replica_count": 1,
    "max_replica_count": 2
  }
}
```

## Example: Training Pipeline Trigger

Submit to `job.vertexai.write`:

```json
{
  "action": "training.create_pipeline",
  "params": {
    "display_name": "cordum-text-classifier",
    "training_task_definition": "gs://google-cloud-aiplatform/schema/trainingjob/definition/automl_text_classification_1.0.0.yaml",
    "training_task_inputs": {
      "multiLabel": false,
      "datasetId": "1234567890",
      "modelType": "CLOUD"
    }
  }
}
```

## Model Restrictions

Use allow/deny lists to restrict which models a profile can access:

```bash
CORDUM_VERTEXAI_ALLOWED_MODELS=gemini-*,textembedding-gecko*
CORDUM_VERTEXAI_DENIED_MODELS=gemini-2.5-pro
CORDUM_VERTEXAI_MAX_TOKENS_PER_REQUEST=8192
```

Deny rules take priority over allow rules.

## Multi-Profile Example

```bash
CORDUM_VERTEXAI_PROFILES='[
  {
    "name": "prod",
    "project_id": "prod-project",
    "location": "us-central1",
    "credentials_file_env": "PROD_GOOGLE_APPLICATION_CREDENTIALS",
    "impersonate_sa": "vertex-prod@prod-project.iam.gserviceaccount.com",
    "allowed_models": ["gemini-*", "textembedding-gecko*"],
    "max_tokens_per_request": 8192
  },
  {
    "name": "staging",
    "project_id": "staging-project",
    "location": "us-east4",
    "allowed_models": ["gemini-2.5-flash"]
  }
]'
```

Select the profile in the request payload:

```json
{
  "profile": "prod",
  "action": "generate.generate_content",
  "params": {
    "model": "gemini-2.5-flash",
    "prompt": "Hello from Cordum"
  }
}
```

## Environment Variables

See [`deploy/env.example`](deploy/env.example) for the full list.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GCP_PROJECT_ID` | Yes* | — | Default GCP project |
| `VERTEX_LOCATION` | No | `us-central1` | Default Vertex AI region |
| `GOOGLE_APPLICATION_CREDENTIALS` | No | — | Service account JSON for ADC |
| `CORDUM_VERTEXAI_IMPERSONATE_SERVICE_ACCOUNT` | No | — | Service account to impersonate |
| `CORDUM_VERTEXAI_ALLOWED_MODELS` | No | (all) | Allowed model globs |
| `CORDUM_VERTEXAI_DENIED_MODELS` | No | (none) | Denied model globs |
| `CORDUM_VERTEXAI_MAX_TOKENS_PER_REQUEST` | No | `32768` | Max generation tokens per request |

*Not required when the selected profile provides the project id.

## Security & Operations

- No hardcoded credentials; all auth is environment-driven
- Reuses official SDK clients with pooled gRPC transports
- Tracks token usage and latency metadata for inference calls
- Enforces topic separation for read, generate, and write intents
- Supports per-profile model restrictions and token ceilings
- Supports ADC plus service-account impersonation
- Uses structured logging, request timeouts, and Redis-backed blob storage
