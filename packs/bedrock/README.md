# AWS Bedrock Pack

AWS Bedrock integration for Cordum — managed AI model invocation, Converse API, embeddings, knowledge bases, and Bedrock agents.

## Supported Models

- **Anthropic**: claude-3.5-sonnet, claude-3-haiku, claude-v2
- **Meta**: llama3-8b, llama3-70b
- **Amazon**: titan-text, titan-embed-text-v2
- **Cohere**: command-r-plus, embed-english-v3
- **Mistral**: mistral-large, mistral-7b
- **AI21**: jamba-instruct

## Capabilities

| Topic | Actions | Policy |
|-------|---------|--------|
| `job.bedrock.read` | models.list, models.get | ALLOW |
| `job.bedrock.generate` | invoke, converse, embed | ALLOW |
| `job.bedrock.write` | kb.query, kb.retrieve, agent.invoke | REQUIRE_APPROVAL |

## Recommended: Converse API

Use the `converse` action for multi-turn conversations — it provides a unified format across all model families with normalized token usage reporting.

## Quick Start

```bash
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
cd packs/bedrock
go build -o cordum-bedrock.exe ./cmd/cordum-bedrock/
./cordum-bedrock.exe
```

## Example: Converse

```json
{
  "action": "converse",
  "params": {
    "model_id": "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "messages": [
      {"role": "user", "content": [{"text": "Explain quantum computing."}]}
    ],
    "inference_config": {"maxTokens": 1024, "temperature": 0.7}
  }
}
```

## Example: Embeddings

```json
{
  "action": "embed",
  "params": {
    "model_id": "amazon.titan-embed-text-v2:0",
    "texts": ["Hello world"]
  }
}
```

## Model Allow/Deny

```bash
# Only allow Anthropic and Titan models
CORDUM_BEDROCK_ALLOWED_MODELS=anthropic,amazon.titan

# Block specific models
CORDUM_BEDROCK_DENIED_MODELS=meta.llama
```

Uses substring matching — `anthropic` matches `anthropic.claude-3-5-sonnet-20241022-v2:0`.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AWS_REGION` | No | `us-east-1` | AWS region |
| `AWS_ACCESS_KEY_ID` | Yes | — | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | Yes | — | AWS secret key |
| `CORDUM_BEDROCK_ALLOWED_MODELS` | No | (all) | Model allow list (substring) |
| `CORDUM_BEDROCK_DENIED_MODELS` | No | (none) | Model deny list (substring) |

## Security

- AWS credentials via standard credential chain
- 3-tier policy: read/generate ALLOW, write REQUIRE_APPROVAL
- Model allow/deny with substring matching
- Topic-intent enforcement
- Connection pooling
