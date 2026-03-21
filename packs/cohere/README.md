# Cohere Pack

Cohere AI integration for Cordum — chat, embeddings, rerank, and classification.

## Capabilities

| Topic | Description | Policy |
|-------|-------------|--------|
| `job.cohere.chat` | Chat with RAG documents + tool calling | ALLOW |
| `job.cohere.generate` | Text generation (routes to chat) | ALLOW |
| `job.cohere.embed` | Text embeddings with input_type | ALLOW |
| `job.cohere.rerank` | Document reranking for RAG | ALLOW |
| `job.cohere.classify` | Few-shot text classification | ALLOW |

## Features

- **Chat**: Multi-turn with RAG documents, connectors, tool calling
- **Embeddings**: v3 models with required `input_type` (search_document, search_query, classification, clustering)
- **Rerank**: Document relevance scoring — ideal for RAG pipeline second stage
- **Classify**: Few-shot classification with labeled examples
- **Billed Units**: Tracks Cohere billing units (input/output tokens, search units, classifications)
- **Model Restrictions**: Allow/deny lists

## Quick Start

```bash
export COHERE_API_KEY=...
cd packs/cohere
go build -o cordum-cohere.exe ./cmd/cordum-cohere/
./cordum-cohere.exe
```

## Example: RAG Rerank Pipeline

```json
{
  "action": "rerank",
  "params": {
    "model": "rerank-english-v3.0",
    "query": "What is machine learning?",
    "documents": [
      "ML is a subset of AI that enables systems to learn from data.",
      "The weather today is sunny and warm.",
      "Deep learning uses neural networks with many layers."
    ],
    "top_n": 2,
    "return_documents": true
  }
}
```

## Example: Embeddings (input_type required)

```json
{
  "action": "embed",
  "params": {
    "model": "embed-english-v3.0",
    "texts": ["Hello world", "How are you?"],
    "input_type": "search_document"
  }
}
```

## Example: Classification

```json
{
  "action": "classify",
  "params": {
    "inputs": ["This product is amazing!", "Terrible service"],
    "examples": [
      {"text": "Great quality", "label": "positive"},
      {"text": "Very disappointing", "label": "negative"}
    ]
  }
}
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `COHERE_API_KEY` | Yes | — | Cohere API key |
| `CORDUM_COHERE_BASE_URL` | No | `https://api.cohere.com` | API base URL |
| `CORDUM_COHERE_ALLOWED_MODELS` | No | (all) | Model allow list |

## Security

- API key via environment variable only
- Bearer token authentication
- Connection pooling (MaxIdleConns=100)
- Model allow/deny lists
- Embed enforces input_type (prevents misuse of embedding models)
