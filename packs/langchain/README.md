# LangChain Pack

LangChain integration for Cordum with chain execution, agent dispatch with CAP governance, and retriever queries.

## Architecture

```
Cordum NATS bus
  │
  ▼
Go Worker (cordum-langchain)
  ├── Callback Server (:auto)     ← Python sidecar posts tool calls here
  │     └── Gateway API            ← Submits governed jobs
  │           └── Safety Kernel    ← Approves/denies tool calls
  └── Sidecar Manager
        └── Python Sidecar (:auto)
              ├── LangChain chains
              ├── LangChain agents (with GovernedLangChainTool)
              └── LangChain retrievers
```

Every agent tool call is intercepted by `GovernedLangChainTool`, which POSTs to the Go callback server. The callback server submits a governed job through the Cordum Gateway, waits for Safety Kernel approval, and returns the result to the Python sidecar. **Zero ungoverned tool execution.**

## Capabilities

| Topic | Description | Policy |
|-------|-------------|--------|
| `job.langchain.chain` | Execute a LangChain chain | ALLOW |
| `job.langchain.agent` | Run a governed LangChain agent | REQUIRE_APPROVAL |
| `job.langchain.retriever` | Query a retriever for documents | ALLOW |
| `job.langchain.toolcall` | Individual governed tool calls | REQUIRE_APPROVAL |

## Supported LLM Providers

- **OpenAI** (`langchain-openai`) — GPT-4o, GPT-4-turbo, etc.
- **Anthropic** (`langchain-anthropic`) — Claude 4.5/4.6
- **Mistral** (`langchain-mistralai`) — Mistral models
- **Cohere** (`langchain-cohere`) — Command models

## Features

- **Chain Execution**: Run any LangChain chain with configurable prompt templates and output parsers
- **Governed Agent Execution**: Every tool call routes through CAP Safety Kernel
- **Intermediate Step Reporting**: Agent steps with governance decisions returned in results
- **Retriever Queries**: Vector store retrieval with configurable search type and parameters
- **Multi-Provider LLM**: Configure any supported LLM provider per request
- **Sidecar Architecture**: Go worker manages Python subprocess lifecycle with auto-restart

## Quick Start

```bash
# 1. Set required env vars
export OPENAI_API_KEY=sk-...
export CORDUM_NATS_URL=nats://localhost:4222
export CORDUM_REDIS_URL=redis://localhost:6379

# 2. Install Python dependencies
cd packs/langchain/sidecar
pip install -r requirements.txt

# 3. Build Go worker
cd packs/langchain
go build -o cordum-langchain.exe ./cmd/cordum-langchain/

# 4. Run
./cordum-langchain.exe
```

## Example: Chain Execution

Submit to `job.langchain.chain`:

```json
{
  "chain_config": {
    "chain_type": "llm",
    "llm_config": {
      "provider": "openai",
      "model": "gpt-4o",
      "temperature": 0.7
    },
    "prompt_template": "Translate the following to French: {text}"
  },
  "input": {"text": "Hello, how are you?"}
}
```

## Example: Governed Agent

Submit to `job.langchain.agent`:

```json
{
  "agent_config": {
    "agent_type": "openai-functions",
    "llm_config": {
      "provider": "openai",
      "model": "gpt-4o"
    },
    "tools": [
      {
        "name": "search",
        "description": "Search the web for information"
      },
      {
        "name": "calculator",
        "description": "Perform mathematical calculations"
      }
    ],
    "max_iterations": 5,
    "system_message": "You are a helpful research assistant."
  },
  "input": "What is the population of France multiplied by 3?",
  "tool_governance": true
}
```

Each `search` and `calculator` tool call will be governed via `job.langchain.toolcall` before execution.

## Example: Retriever Query

Submit to `job.langchain.retriever`:

```json
{
  "retriever_config": {
    "type": "vectorstore",
    "store_config": {
      "provider": "chroma",
      "collection_name": "docs",
      "embedding_config": {
        "provider": "openai",
        "model": "text-embedding-3-small"
      }
    },
    "search_type": "similarity"
  },
  "query": "How does authentication work?",
  "k": 5
}
```

## Environment Variables

See [`deploy/env.example`](deploy/env.example) for the full list.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CORDUM_NATS_URL` | Yes | `nats://localhost:4222` | NATS server URL |
| `CORDUM_REDIS_URL` | Yes | `redis://localhost:6379` | Redis server URL |
| `OPENAI_API_KEY` | Depends | — | OpenAI API key (if using OpenAI provider) |
| `ANTHROPIC_API_KEY` | Depends | — | Anthropic API key (if using Anthropic provider) |
| `CORDUM_LANGCHAIN_TOOL_GOVERNANCE` | No | `true` | Route agent tool calls through Safety Kernel |
| `CORDUM_LANGCHAIN_PYTHON_CMD` | No | `python` | Python executable for sidecar |
| `CORDUM_LANGCHAIN_REQUEST_TIMEOUT` | No | `300s` | Request timeout |

## Security

- All LLM API keys sourced from environment variables only — never hardcoded
- Tool governance enabled by default — every agent tool call requires Safety Kernel approval
- Sidecar runs on localhost only (127.0.0.1) — no external network exposure
- Callback server auto-allocates ephemeral ports — no port conflicts
- Connection pooling on all HTTP clients
