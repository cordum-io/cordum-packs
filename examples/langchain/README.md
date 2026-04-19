# LangGraph + Cordum Example

Governed LangGraph research agent with PII detection.

## Quick start

```bash
# From the Cordum repo root
cordumctl init --framework langchain my-agent
cd my-agent
export CORDUM_API_KEY="$(openssl rand -hex 32)"
docker compose up -d
```

## Submit a job

```bash
curl -s http://localhost:8081/api/v1/jobs \
  -H "X-API-Key: $CORDUM_API_KEY" \
  -H "X-Tenant-ID: default" \
  -H "Content-Type: application/json" \
  -d '{"topic": "job.default", "prompt": "What are the key features of LangGraph?"}'
```

## Full tutorial

See [Govern Your LangGraph Agent in 5 Minutes](https://docs.cordum.io/tutorials/langgraph-5min).
