# Cordum Python Sidecar Template

This template is the common starting point for the Python framework packs:

- LangChain
- CrewAI
- AutoGen
- LlamaIndex

It is **copied into each pack** and then customized. It is **not** intended to be imported as a shared Go library.

## Architecture

```text
+--------------------+      HTTP /execute       +---------------------------+
| Cordum Go worker   | -----------------------> | Python sidecar            |
| (pack-specific)    |                          | (framework runtime)       |
|                    | <----------------------- | /health + /shutdown       |
+----------+---------+      tool governance     +------------+--------------+
           |                                                  |
           | HTTP /tool-call                                  |
           v                                                  v
+----------------------+                          +---------------------------+
| Callback server      | -- SubmitJob/GetJob --> | Cordum gateway + safety   |
| (Go, local only)     |                          | policy / approval flow    |
+----------------------+                          +---------------------------+
```

### Responsibilities

- **manager.go**: starts and supervises the Python subprocess, injects `CORDUM_CALLBACK_URL`, health-checks `/health`, and restarts after crashes.
- **callback.go**: receives tool governance requests from Python, submits governed jobs through the gateway, and returns approval/denial outcomes.
- **server.py**: base Flask sidecar with `/health`, `/execute`, and `/shutdown`.
- **governance.py**: framework-agnostic `GovernedTool` plus LangChain/CrewAI/AutoGen wrappers.

## Governance callback flow

1. Framework agent decides to call a tool.
2. `GovernedTool` sends `POST /tool-call` to the local Go callback server.
3. The callback server submits a governed Cordum job with topic, capability, risk tags, and labels.
4. Cordum policy/safety evaluates the job.
5. The callback server waits for the terminal job result.
6. Python receives `{approved, result, error}` and either continues or degrades gracefully.

## How to create a new framework pack

1. **Copy the template**
   - Copy `integrations/sidecar-template/go/*` into the new pack's Go worker area.
   - Copy `integrations/sidecar-template/python/*` into the new pack's Python sidecar area.
   - Copy `Dockerfile.template` into the new pack root and rename it to `Dockerfile`.

2. **Customize the Go worker**
   - Embed `SidecarManager` in the pack worker lifecycle.
   - Start the callback server before launching the Python subprocess.
   - Pass framework-specific action names, risk tags, and capabilities into callback requests.

3. **Customize the Python side**
   - Replace `TemplateExecutor` in `server.py` with framework-specific execution logic.
   - Instantiate `GovernedLangChainTool`, `GovernedCrewAITool`, or `GovernedAutoGenFunction` as needed.
   - Add framework dependencies to `python/requirements.txt`.

4. **Wire deployment**
   - Ensure the Go worker starts the callback server and sidecar manager during boot.
   - Ensure the Python subprocess binds to the port supplied via `--port`.
   - Keep the callback URL local-only; it should never be exposed publicly.

## Docker build pattern

`Dockerfile.template` assumes it has been copied into a pack root and that the pack root contains:

- `go.mod` / `go.sum`
- `cmd/`
- `internal/`
- `python/requirements.txt`
- `python/server.py`
- `python/governance.py`

The runtime image:

- installs Flask from `python/requirements.txt`
- installs `integrations/agent-adapters` as a pip package
- ships only the compiled Go worker and Python runtime assets

## Deployment guidance

- Run the Go worker as PID 1 inside the container; it should own sidecar lifecycle and shutdown.
- Use localhost-only networking between the Go process and Python sidecar.
- Keep `threaded=True` or equivalent concurrency enabled in the Python HTTP server because frameworks can issue multiple governed tool calls in parallel.
- Treat `/tool-call` as a privileged local endpoint; do not publish it outside the container or pod.
- Add pack-specific readiness checks if the framework requires model loading or index hydration.

## Validation commands

```bash
# Go template tests
cd integrations/sidecar-template/go && go test ./...

# Python governance tests
cd integrations/sidecar-template/python && python -m unittest discover -s tests -p "test_*.py"
```

## Notes for pack authors

- The default callback server waits by polling `GetJob`; packs can replace that with a custom waiter if they want direct NATS result handling.
- `governance.py` uses only the Python standard library for callback transport so framework packs can stay lightweight.
- `integrations/agent-adapters/` is packaged with a local `pyproject.toml` so container builds can install it with pip.
