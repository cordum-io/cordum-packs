# Anthropic Pack

Full Anthropic Claude AI integration for Cordum. Provides messages, streaming, tool use with governance, batch processing, and model listing.

## Capabilities

| Topic | Description | Policy |
|-------|-------------|--------|
| `job.anthropic.messages` | Messages API (non-streaming) | ALLOW |
| `job.anthropic.messages.stream` | Streaming via NATS chunked delivery | ALLOW |
| `job.anthropic.messages.tooluse` | Tool use with CAP governance | REQUIRE_APPROVAL |
| `job.anthropic.batch` | Batch create/cancel operations | REQUIRE_APPROVAL |
| `job.anthropic.batch.read` | Batch list/get (read-only) | ALLOW |

## Supported Models

- `claude-opus-4-6` — Most capable model
- `claude-sonnet-4-6` — Balanced performance and cost
- `claude-haiku-4-5` — Fastest, most cost-effective

## Features

- **Messages API**: Multi-turn conversations with system prompts
- **Streaming**: Server-sent events parsed and forwarded via NATS progress subjects
- **Vision**: Image inputs via base64 or URL in message content blocks
- **Tool Use**: Governed through CAP Safety Kernel (submit, approve/deny, continue)
- **Extended Thinking**: Configurable thinking budget per profile
- **Batch API**: Create, list, get, and cancel message batches
- **Cost Tracking**: Input/output token usage and USD cost estimates per request
- **Multi-Profile**: Per-tenant API keys, model restrictions, and thinking limits

## Tool Governance Architecture

When `CORDUM_ANTHROPIC_TOOL_GOVERNANCE=true` and the model responds with `tool_use` content blocks:

1. Worker extracts each `tool_use` block from the response
2. Each tool call is submitted as a governed job through the Cordum Gateway (`job.anthropic.tool.{tool_name}`)
3. The Safety Kernel evaluates the job against policy rules
4. On **approval**: the tool result is collected and fed back to the Messages API
5. On **denial**: an error tool_result is returned to the model
6. The model continues with the tool results until it produces a final response
7. Maximum 10 governance iterations to prevent infinite loops

This ensures no tool executes without policy approval — the key differentiator for this pack.

## Quick Start

```bash
# 1. Set required env vars
export ANTHROPIC_API_KEY=sk-ant-...
export CORDUM_NATS_URL=nats://localhost:4222
export CORDUM_REDIS_URL=redis://localhost:6379

# 2. Build
cd packs/anthropic
go build -o cordum-anthropic.exe ./cmd/cordum-anthropic/

# 3. Run
./cordum-anthropic.exe
```

## Example: Messages Request

Submit a job to `job.anthropic.messages`:

```json
{
  "action": "messages.create",
  "params": {
    "model": "claude-sonnet-4-6",
    "max_tokens": 1024,
    "system": "You are a helpful assistant.",
    "messages": [
      {"role": "user", "content": "What is the capital of France?"}
    ]
  }
}
```

## Example: Tool Use with Governance

Submit to `job.anthropic.messages.tooluse`:

```json
{
  "action": "messages.create.tooluse",
  "params": {
    "model": "claude-sonnet-4-6",
    "max_tokens": 1024,
    "messages": [
      {"role": "user", "content": "What's the weather in San Francisco?"}
    ],
    "tools": [
      {
        "name": "get_weather",
        "description": "Get current weather for a location",
        "input_schema": {
          "type": "object",
          "properties": {
            "location": {"type": "string"}
          },
          "required": ["location"]
        }
      }
    ]
  }
}
```

Each `get_weather` tool call will be governed via `job.anthropic.tool.get_weather` before execution.

## Example: Vision (Image Input)

```json
{
  "params": {
    "model": "claude-sonnet-4-6",
    "max_tokens": 1024,
    "messages": [
      {
        "role": "user",
        "content": [
          {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "..."}},
          {"type": "text", "text": "Describe this image."}
        ]
      }
    ]
  }
}
```

## Example: Extended Thinking

Requires `CORDUM_ANTHROPIC_THINKING_ENABLED=true`:

```json
{
  "params": {
    "model": "claude-sonnet-4-6",
    "max_tokens": 16000,
    "thinking": {"type": "enabled", "budget_tokens": 10000},
    "messages": [
      {"role": "user", "content": "Solve this step by step: ..."}
    ]
  }
}
```

## Environment Variables

See [`deploy/env.example`](deploy/env.example) for the full list.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes | — | Anthropic API key |
| `CORDUM_NATS_URL` | Yes | `nats://localhost:4222` | NATS server URL |
| `CORDUM_REDIS_URL` | Yes | `redis://localhost:6379` | Redis server URL |
| `CORDUM_ANTHROPIC_TOOL_GOVERNANCE` | No | `true` | Route tool calls through Safety Kernel |
| `CORDUM_ANTHROPIC_THINKING_ENABLED` | No | `false` | Allow extended thinking |
| `CORDUM_ANTHROPIC_MAX_TOKENS_LIMIT` | No | `128000` | Max tokens per request |
| `CORDUM_ANTHROPIC_ALLOWED_MODELS` | No | (all) | Comma-separated allow list |
| `CORDUM_ANTHROPIC_DENIED_MODELS` | No | (none) | Comma-separated deny list |

## Security

- API keys are never hardcoded — sourced from environment variables only
- Inline auth is disabled by default (`CORDUM_ANTHROPIC_ALLOW_INLINE_AUTH=false`)
- Tool use requires policy approval via CAP Safety Kernel
- Batch operations require approval (write risk tag)
- Model access controlled via allow/deny lists per profile
- All HTTP clients use connection pooling (no per-request client creation)
- Authentication uses `x-api-key` header (Anthropic's native auth, not Bearer tokens)
