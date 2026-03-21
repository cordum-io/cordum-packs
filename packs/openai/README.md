# Cordum OpenAI Pack

Production-ready OpenAI chat, embeddings, image generation, audio, fine-tuning, and model-management workflows for Cordum.

## What you get

- **OpenAI worker**: handles `job.openai.*` topics with pooled HTTP clients and retry-aware API calls.
- **Governed cost controls**: chat/embed/transcribe are allowed by default; image generation, speech, and fine-tuning require approval.
- **Usage + cost metadata**: every result includes `usage.prompt_tokens`, `usage.completion_tokens`, `usage.total_tokens`, rate-limit metadata, and a USD cost estimate when pricing is known.
- **Example workflows**: chat, streaming chat, embeddings, images, transcription, speech, and fine-tuning templates.

## Topics

| Topic | Capability | Default policy |
|---|---|---|
| `job.openai.chat` | Chat completions | Allow |
| `job.openai.chat.stream` | Streaming chat completions | Allow |
| `job.openai.embed` | Text embeddings | Allow |
| `job.openai.image.generate` | DALL-E image generation | Require approval |
| `job.openai.audio.transcribe` | Whisper transcription | Allow |
| `job.openai.audio.tts` | Text-to-speech | Require approval |
| `job.openai.finetune` | Fine-tune create/cancel | Require approval |
| `job.openai.finetune.read` | Fine-tune list/get + models list | Allow |

## Supported actions

- `chat.completions`
- `chat.completions.stream`
- `embeddings`
- `images.generate`
- `audio.transcriptions`
- `audio.speech`
- `fine_tuning.jobs.create`
- `fine_tuning.jobs.list`
- `fine_tuning.jobs.get`
- `fine_tuning.jobs.cancel`
- `models.list`

## Model support

| Capability | Models validated by schema |
|---|---|
| Chat | `gpt-4o`, `gpt-4-turbo`, `gpt-3.5-turbo` |
| Embeddings | `text-embedding-3-small`, `text-embedding-3-large` |
| Images | `dall-e-3`, `dall-e-2` |
| Transcription | `whisper-1` |
| Speech | `tts-1`, `tts-1-hd` |
| Fine-tuning | caller-supplied model string |

Profile-level `allowed_models` / `denied_models` rules are enforced in addition to schema validation.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/openai/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/openai

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_TENANT_ID=default \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_OPENAI_API_KEY_ENV=OPENAI_API_KEY \
CORDUM_OPENAI_ALLOWED_MODELS=gpt-4o,text-embedding-3-small,text-embedding-3-large,dall-e-3,whisper-1,tts-1 \
OPENAI_API_KEY=sk-example \
go run ./cmd/cordum-openai
```

See `deploy/env.example` for the full environment reference.

## Workflow templates

- `openai.chat`
- `openai.chat.stream`
- `openai.embed`
- `openai.image.generate`
- `openai.audio.transcribe`
- `openai.audio.tts`
- `openai.finetune.create`

## Example job payloads

### Chat completion

```json
{
  "profile": "default",
  "action": "chat.completions",
  "model": "gpt-4o",
  "messages": [
    { "role": "system", "content": "You are concise." },
    { "role": "user", "content": "Summarize the incident timeline." }
  ],
  "max_tokens": 512,
  "temperature": 0.2
}
```

### Embeddings

```json
{
  "profile": "default",
  "action": "embeddings",
  "model": "text-embedding-3-small",
  "input": [
    "cordum incident summary",
    "postmortem action items"
  ]
}
```

### Image generation

```json
{
  "profile": "default",
  "action": "images.generate",
  "model": "dall-e-3",
  "prompt": "A clean architectural diagram of a governed AI workflow",
  "size": "1024x1024",
  "quality": "standard"
}
```

### Fine-tune create

```json
{
  "profile": "default",
  "action": "fine_tuning.jobs.create",
  "model": "gpt-4o-mini-2024-07-18",
  "training_file": "file-abc123",
  "hyperparameters": {
    "n_epochs": "auto"
  }
}
```

## Environment

Core Cordum settings:

- `CORDUM_GATEWAY_URL`
- `CORDUM_API_KEY`
- `CORDUM_TENANT_ID`
- `CORDUM_NATS_URL`
- `CORDUM_REDIS_URL`

Worker settings:

- `CORDUM_OPENAI_POOL` (default `openai`)
- `CORDUM_OPENAI_QUEUE` (default `openai`)
- `CORDUM_OPENAI_SUBJECTS` (default `job.openai.*`)
- `CORDUM_OPENAI_MAX_PARALLEL` (`0` = unlimited)
- `CORDUM_OPENAI_REQUEST_TIMEOUT` (default `90s`)
- `CORDUM_OPENAI_RESULT_TTL` (optional)
- `CORDUM_OPENAI_ALLOW_INLINE_AUTH` (default `false`)
- `CORDUM_OPENAI_ALLOW_INLINE_SECRETS` (default `false`)
- `CORDUM_OPENAI_DEFAULT_PROFILE` (default `default`)

Default profile settings:

- `CORDUM_OPENAI_BASE_URL` (default `https://api.openai.com/v1`)
- `CORDUM_OPENAI_API_KEY` or `CORDUM_OPENAI_API_KEY_ENV`
- `CORDUM_OPENAI_ORGANIZATION` or `CORDUM_OPENAI_ORGANIZATION_ENV`
- `CORDUM_OPENAI_ALLOWED_MODELS`
- `CORDUM_OPENAI_DENIED_MODELS`
- `CORDUM_OPENAI_MAX_TOKENS_LIMIT`
- `CORDUM_OPENAI_COST_TRACKING` (default `true`)
- `CORDUM_OPENAI_RATE_LIMIT_RETRY` (default `true`)
- `CORDUM_OPENAI_MAX_RETRIES` (default `2`)
- `CORDUM_OPENAI_PROFILES` for multi-account / multi-policy deployments

## Cost tracking

Results include:

- `usage.prompt_tokens`
- `usage.completion_tokens`
- `usage.total_tokens`
- `rate_limit.*`
- `cost_estimate`

`cost_estimate` is computed from model/token usage for the models with known pricing in the worker (`gpt-4o`, `gpt-4-turbo`, `gpt-3.5-turbo`, `text-embedding-3-small`, `text-embedding-3-large`). Treat it as an operational estimate rather than a billing source of truth; OpenAI pricing can change.

## Security notes

- **No hardcoded credentials**: use env vars or profile JSON with `*_env` fields.
- **Inline auth is off by default**: enable `CORDUM_OPENAI_ALLOW_INLINE_AUTH=true` only when necessary.
- **Inline secrets stay off by default**: keep `CORDUM_OPENAI_ALLOW_INLINE_SECRETS=false` in production.
- **Write/cost controls**: image generation, speech synthesis, and fine-tuning are policy-gated by default.
- **Model guardrails**: use `allowed_models`, `denied_models`, and `max_tokens_limit` to keep jobs within approved budgets.

## License

BUSL-1.1 (same as Cordum core).
