# AutoGen Pack

AutoGen integration for Cordum — multi-agent group chat, single agent tasks, and sandboxed code execution with CAP governance.

## Architecture

```
Cordum NATS bus
  │
  ▼
Go Worker (cordum-autogen)
  ├── Callback Server (:auto)     ← Python sidecar posts tool calls here
  │     └── Gateway API → Safety Kernel
  └── Sidecar Manager
        └── Python Sidecar (:auto)
              ├── Group Chat (multi-agent conversations)
              ├── Single Agent (one-shot tasks)
              └── Code Execution (Docker sandbox)
```

## Capabilities

| Topic | Description | Policy |
|-------|-------------|--------|
| `job.autogen.agent` | Single agent task | ALLOW |
| `job.autogen.groupchat` | Multi-agent group conversation | REQUIRE_APPROVAL |
| `job.autogen.code` | Sandboxed code execution | REQUIRE_APPROVAL |
| `job.autogen.toolcall` | Governed tool calls | REQUIRE_APPROVAL |

## Code Execution Security

Code execution **always** runs in a Docker sandbox — never on the host. Set `CORDUM_AUTOGEN_CODE_EXECUTION=disabled` to block code execution entirely. The `local` mode is explicitly rejected.

## Quick Start

```bash
export OPENAI_API_KEY=sk-...
cd packs/autogen/sidecar && pip install -r requirements.txt
cd packs/autogen && go build -o cordum-autogen.exe ./cmd/cordum-autogen/
./cordum-autogen.exe
```

## Example: Multi-Agent Debate

```json
{
  "agents": [
    {"name": "researcher", "system_message": "You research topics thoroughly."},
    {"name": "critic", "system_message": "You critically evaluate arguments."},
    {"name": "summarizer", "system_message": "You summarize discussions concisely."}
  ],
  "message": "Debate: Should AI systems be open-sourced?",
  "max_rounds": 6,
  "speaker_selection": "auto"
}
```

## Example: Code Execution

```json
{
  "action": "code",
  "config": {
    "code": "import math\nprint(math.factorial(20))",
    "language": "python",
    "docker_image": "python:3.12-slim",
    "timeout": 15
  }
}
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | Yes | — | LLM API key |
| `CORDUM_AUTOGEN_CODE_EXECUTION` | No | `docker` | `docker` or `disabled` |
| `CORDUM_AUTOGEN_DOCKER_IMAGE` | No | `python:3.12-slim` | Docker image for code |
| `CORDUM_AUTOGEN_MAX_ROUNDS` | No | `20` | Max group chat rounds |
| `CORDUM_AUTOGEN_TOOL_GOVERNANCE` | No | `true` | Govern tool calls via CAP |
