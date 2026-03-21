# Mistral Pack

Mistral AI integration for Cordum — chat completions, embeddings, streaming, function calling, and Codestral FIM code generation.

## Capabilities

| Topic | Description | Policy |
|-------|-------------|--------|
| `job.mistral.chat` | Chat completions | ALLOW |
| `job.mistral.chat.stream` | Streaming chat completions | ALLOW |
| `job.mistral.embed` | Text embeddings | ALLOW |
| `job.mistral.code` | Code generation | ALLOW |
| `job.mistral.fim` | Fill-in-the-middle (Codestral) | ALLOW |

All operations are read-only (no destructive side effects) — all policies ALLOW.

## Supported Models

- `mistral-large-latest` — Most capable
- `mistral-medium-latest` — Balanced
- `mistral-small-latest` — Fast and efficient
- `codestral-latest` — Code generation + FIM
- `open-mistral-nemo` — Open-weight
- `mistral-embed` — Embeddings

## Features

- **Chat Completions**: Multi-turn with system prompts, JSON mode, safe prompt injection
- **Streaming**: SSE with NATS progress publishing
- **Function Calling**: Tools + tool_choice support
- **Embeddings**: Text embedding via mistral-embed
- **Codestral FIM**: Fill-in-the-middle for code completion (prompt + suffix)
- **Cost Tracking**: Token usage + USD cost estimates per model
- **Model Restrictions**: Allow/deny lists

## Quick Start

```bash
export MISTRAL_API_KEY=...
cd packs/mistral
go build -o cordum-mistral.exe ./cmd/cordum-mistral/
./cordum-mistral.exe
```

## Example: Chat Completion

```json
{
  "action": "chat.completions",
  "params": {
    "model": "mistral-large-latest",
    "messages": [
      {"role": "user", "content": "Explain quantum computing in one paragraph."}
    ],
    "temperature": 0.7
  }
}
```

## Example: Codestral FIM

```json
{
  "action": "fim.completions",
  "params": {
    "model": "codestral-latest",
    "prompt": "def fibonacci(n):\n    if n <= 1:\n        return n\n",
    "suffix": "\n\nprint(fibonacci(10))",
    "max_tokens": 256
  }
}
```

## Example: Embeddings

```json
{
  "action": "embeddings",
  "params": {
    "model": "mistral-embed",
    "input": ["Hello world", "How are you?"]
  }
}
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MISTRAL_API_KEY` | Yes | — | Mistral API key |
| `CORDUM_MISTRAL_BASE_URL` | No | `https://api.mistral.ai` | API base URL |
| `CORDUM_MISTRAL_ALLOWED_MODELS` | No | (all) | Model allow list |
| `CORDUM_MISTRAL_SAFE_PROMPT` | No | `false` | Force safety prompt |

## Security

- API key via environment variable only
- Bearer token authentication
- Connection pooling (MaxIdleConns=100)
- Model allow/deny lists
- Max tokens limit enforcement
- Optional safe prompt injection
