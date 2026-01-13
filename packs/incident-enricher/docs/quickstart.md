# Quickstart

This assumes Cordum is already running (gateway, scheduler, safety kernel,
workflow engine, NATS, Redis).

## 1) Install the pack

```
./scripts/bundle.sh
./scripts/install.sh
```

This registers schemas + workflow, applies pools/timeouts overlays, and installs
the safety policy fragment that requires approval for the post step.

## 2) Run workers

```
docker compose -f deploy/docker-compose.workers.yaml --env-file deploy/env.example up --build
```

Optional: enable real summaries with Ollama by setting in `deploy/env.example`:

```
LLM_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3
```

## 3) Start a run

```
cordumctl run start incident-enricher.enrich --input testdata/sample_incident.json
```

Or use the ingester:

```
INGESTER_URL=http://localhost:8088 ./scripts/demo.sh
```

## 4) Approve the post step

```
./scripts/approve_latest_post.sh
```

## 5) Inspect artifacts

Fetch artifacts via the gateway:

```
curl -H "X-API-Key: $CORDUM_API_KEY" "$CORDUM_GATEWAY_URL/api/v1/artifacts/<artifact_ptr>"
```
