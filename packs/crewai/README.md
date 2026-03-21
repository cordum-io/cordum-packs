# CrewAI Pack

CrewAI integration for Cordum with governed crew orchestration, single-task execution, and NATS progress events.

## Architecture

```text
Cordum NATS bus
  │
  ▼
Go Worker (cordum-crewai)
  ├── Callback Server (:auto)
  │     ├── /tool-call  → submits governed tool jobs through Gateway/Safety Kernel
  │     └── /progress   → publishes active-agent/task progress to NATS
  └── Python Sidecar
        └── CrewAI runtime + existing cordum_agent_adapters.crewai bridge
```

Every CrewAI tool invocation routes through the callback server before execution. The sidecar never executes an external tool directly.

## Capabilities

| Topic | Description | Policy |
| --- | --- | --- |
| `job.crewai.crew` | Run a governed multi-agent crew kickoff | REQUIRE_APPROVAL |
| `job.crewai.task` | Execute a single governed CrewAI task | ALLOW |
| `job.crewai.toolcall` | Governed tool call bridge used by CrewAI agents | REQUIRE_APPROVAL |

## Features

- Multi-agent crew orchestration with sequential or hierarchical process selection
- Single-task execution with CrewAI agents
- CAP governance on every CrewAI tool call via the existing `cordum_agent_adapters.crewai` adapter
- Progress reporting for active agent and task completion through NATS job progress events
- Configurable LLM provider/model wiring via `llm_config`
- Go-managed Python sidecar lifecycle with health checks and graceful shutdown

## Example Workflow

`pack/workflows/crewai_crew_run.yaml` is the multi-agent crew workflow example for this pack.

## Example: crew kickoff

Submit to `job.crewai.crew`:

```json
{
  "crew_config": {
    "process": "hierarchical",
    "manager_llm_config": {
      "provider": "openai",
      "model": "gpt-4o-mini",
      "api_key_env": "OPENAI_API_KEY"
    },
    "agents": [
      {
        "role": "Researcher",
        "goal": "Find relevant facts",
        "tools": [
          {
            "name": "search",
            "description": "Search the web",
            "input_schema": {
              "type": "object",
              "properties": {
                "query": { "type": "string" }
              }
            }
          }
        ]
      },
      {
        "role": "Writer",
        "goal": "Write the final answer"
      }
    ],
    "tasks": [
      {
        "description": "Research {topic}",
        "expected_output": "A fact list",
        "agent_role": "Researcher"
      },
      {
        "description": "Write a concise summary about {topic}",
        "expected_output": "A short answer",
        "agent_role": "Writer"
      }
    ]
  },
  "input": {
    "topic": "Cordum CrewAI governance"
  },
  "tool_governance": true
}
```

## Example: single task

Submit to `job.crewai.task`:

```json
{
  "task_config": {
    "description": "Summarize {topic}",
    "expected_output": "A short summary",
    "agent_config": {
      "role": "Writer",
      "goal": "Summarize research",
      "llm_config": {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "api_key_env": "OPENAI_API_KEY"
      },
      "tools": [
        {
          "name": "search",
          "description": "Search supporting facts"
        }
      ]
    }
  },
  "input": {
    "topic": "CrewAI task execution"
  },
  "context": [
    "Use plain language."
  ],
  "tool_governance": true
}
```

## Progress events

The Python sidecar posts intermediate progress back to the Go callback server, which publishes NATS `JobProgress` events containing:

- active agent name
- completed task count / total task count
- percent complete
- human-readable progress messages

## Environment

See [`deploy/env.example`](deploy/env.example) for the full configuration surface.

Important variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `CORDUM_CREWAI_TIMEOUT` | `300s` | Maximum runtime for a crew/task execution |
| `CORDUM_CREWAI_TOOL_TOPIC` | `job.crewai.toolcall` | Topic used for governed tool jobs |
| `CORDUM_CREWAI_MAX_RPM` | `0` | Optional CrewAI request-per-minute throttle |
| `CORDUM_CREWAI_SIDECAR_ARGS` | `-m,cordum_crewai_sidecar` | Python module invocation for the sidecar |

## Validation

Recommended local checks:

```bash
go test ./...
python -m unittest discover -s sidecar/tests -p "test_*.py"
python -m py_compile sidecar/cordum_crewai_sidecar/*.py
```

## Security notes

- No credentials are hardcoded; all API keys come from environment variables referenced by `api_key_env`
- Crew/tool topics default to approval-required policy overlays
- Sidecar HTTP endpoints bind to localhost only
- Governed tool calls preserve tenant/principal/actor metadata from the parent job
