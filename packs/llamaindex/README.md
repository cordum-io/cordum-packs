# LlamaIndex Pack

LlamaIndex RAG integration for Cordum — index management, query engine, document ingestion, and retrieval pipelines.

## Architecture

```
Cordum NATS bus
  │
  ▼
Go Worker (cordum-llamaindex)
  └── Sidecar Manager
        └── Python Sidecar (:auto)
              ├── Query Engine (query + retrieve)
              ├── Index Manager (create + delete)
              └── Document Ingestion (file, directory, text)
```

## Capabilities

| Topic | Description | Policy |
|-------|-------------|--------|
| `job.llamaindex.query` | Query with synthesized response | ALLOW |
| `job.llamaindex.retrieve` | Retrieve documents without synthesis | ALLOW |
| `job.llamaindex.index` | Create/delete vector indices | REQUIRE_APPROVAL |
| `job.llamaindex.ingest` | Ingest documents into index | REQUIRE_APPROVAL |

## Vector Store Backends

- **local** — File-based persistence (default)
- **chroma** — ChromaDB (recommended for development)
- **pinecone** — Pinecone (cloud, requires API key)
- **qdrant** — Qdrant (self-hosted or cloud)

## Quick Start

```bash
export OPENAI_API_KEY=sk-...
cd packs/llamaindex/sidecar && pip install -r requirements.txt
cd packs/llamaindex && go build -o cordum-llamaindex.exe ./cmd/cordum-llamaindex/
./cordum-llamaindex.exe
```

## Example: RAG Query

```json
{
  "action": "query",
  "config": {
    "index_config": {
      "store_config": { "backend": "chroma", "collection_name": "docs" }
    },
    "llm_config": { "provider": "openai", "model": "gpt-4o-mini" }
  },
  "input": {
    "query": "How does authentication work?",
    "similarity_top_k": 5,
    "response_mode": "compact"
  }
}
```

## Example: Document Ingestion

```json
{
  "action": "ingest",
  "config": { "index_config": { "store_config": { "backend": "chroma" } } },
  "input": {
    "source": { "type": "text", "texts": ["Document 1 content...", "Document 2 content..."] },
    "chunking": { "chunk_size": 1024, "chunk_overlap": 200 }
  }
}
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | Yes* | — | LLM API key |
| `CORDUM_LLAMAINDEX_STORAGE_DIR` | No | `./llamaindex_storage` | Local persist directory |
| `CORDUM_LLAMAINDEX_DEFAULT_BACKEND` | No | `chroma` | Default vector store |

## Security

- LLM API keys via environment variables only
- Index/ingest operations require approval (write policy)
- Query/retrieve are read-only (ALLOW)
- Sidecar runs on localhost only
