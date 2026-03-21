# Hugging Face Pack

Hugging Face integration for Cordum — serverless inference, embeddings, model hub search, and Spaces management.

## Capabilities

| Topic | Description | Policy |
|-------|-------------|--------|
| `job.huggingface.inference` | Serverless inference (any task) | ALLOW |
| `job.huggingface.embed` | Feature extraction embeddings | ALLOW |
| `job.huggingface.models` | Model hub search/metadata | ALLOW |
| `job.huggingface.spaces` | Spaces status (read) | ALLOW |
| `job.huggingface.spaces.manage` | Spaces restart (write) | REQUIRE_APPROVAL |

## Supported Tasks

text-generation, text-classification, token-classification, summarization, translation, question-answering, fill-mask, image-classification, object-detection, feature-extraction, zero-shot-classification, sentence-similarity, conversational

## Dual API Architecture

The pack routes to two different HF APIs:
- **Inference API** (`api-inference.huggingface.co`) — inference + embed actions
- **Hub API** (`huggingface.co/api`) — models.search, models.get, spaces.*

## Model Loading (503 Handling)

When a model isn't loaded, the inference API returns 503 with `estimated_time`. The pack:
- Returns the error with `estimated_time` in the result for caller visibility
- Supports `wait_for_model: true` option which sends `X-Wait-For-Model` header (blocks until loaded)

## Quick Start

```bash
export HF_TOKEN=hf_...
cd packs/huggingface
go build -o cordum-huggingface.exe ./cmd/cordum-huggingface/
./cordum-huggingface.exe
```

## Example: Text Generation

```json
{
  "action": "inference",
  "params": {
    "model": "meta-llama/Llama-3-8b-Instruct",
    "task": "text-generation",
    "inputs": "The future of AI is",
    "parameters": {"max_new_tokens": 100, "temperature": 0.7},
    "options": {"wait_for_model": true}
  }
}
```

## Example: Embeddings

```json
{
  "action": "embed",
  "params": {
    "model": "sentence-transformers/all-MiniLM-L6-v2",
    "inputs": ["Hello world", "How are you?"]
  }
}
```

## Example: Model Search

```json
{
  "action": "models.search",
  "params": {
    "search": "llama",
    "filter": "task:text-generation",
    "sort": "downloads",
    "limit": 5
  }
}
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HF_TOKEN` | Yes | — | Hugging Face API token |
| `CORDUM_HUGGINGFACE_INFERENCE_URL` | No | `https://api-inference.huggingface.co` | Inference API URL |
| `CORDUM_HUGGINGFACE_HUB_URL` | No | `https://huggingface.co/api` | Hub API URL |
| `CORDUM_HUGGINGFACE_ALLOWED_TASKS` | No | (all) | Task allow list |

## Security

- HF token via environment variable only
- Bearer token authentication
- Connection pooling
- Task allow/deny lists
- Spaces management requires approval
