# AutoGen + Cordum Example

AutoGen multi-agent system with rate limiting and injection detection.

## Quick start

```bash
cordumctl init --framework autogen my-agents
cd my-agents
export CORDUM_API_KEY="$(openssl rand -hex 32)"
docker compose up -d
```

## Submit a job

```bash
curl -s http://localhost:8081/api/v1/jobs \
  -H "X-API-Key: $CORDUM_API_KEY" \
  -H "X-Tenant-ID: default" \
  -H "Content-Type: application/json" \
  -d '{"topic": "job.default", "prompt": "Analyze our deployment pipeline and suggest improvements"}'
```

## Full tutorial

See [Cordum + AutoGen: Multi-Agent Governance](https://docs.cordum.io/tutorials/autogen-multi-agent).
