# CrewAI + Cordum Example

CrewAI crew with PII gates and approval workflows.

## Quick start

```bash
cordumctl init --framework crewai my-crew
cd my-crew
export CORDUM_API_KEY="$(openssl rand -hex 32)"
docker compose up -d
```

## Submit a job

```bash
curl -s http://localhost:8081/api/v1/jobs \
  -H "X-API-Key: $CORDUM_API_KEY" \
  -H "X-Tenant-ID: default" \
  -H "Content-Type: application/json" \
  -d '{"topic": "job.default", "prompt": "Summarize our Q3 revenue trends"}'
```

## Full tutorial

See [Add Safety Gates to CrewAI](https://docs.cordum.io/tutorials/crewai-safety-gates).
