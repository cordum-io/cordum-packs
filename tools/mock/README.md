# Mock services

Lightweight mocks used for local pack smoke tests. These avoid real credentials
and external systems while validating wiring and job flows.

## HTTP mock server

```bash
python3 tools/mock/http_server.py --port 9999
```

- Responds `200` with JSON for any path.
- Service-specific responses are keyed by the first URL segment:
  - `/slack/...` -> `{ "ok": true }`
  - `/prometheus/...` -> `{ "status": "success", "data": {"resultType": "vector", "result": [] } }`
  - everything else -> `{ "ok": true }`

Point pack base URLs at the mock server, e.g. `http://localhost:9999/github`.

## MCP stdio mock server

```bash
python3 tools/mock/mcp_stdio_server.py
```

Implements `initialize`, `tools/list`, and `tools/call` for the MCP client pack.

## Mock kubectl

```bash
CORDUM_K8S_KUBECTL_PATH=tools/mock/kubectl
```

Returns empty JSON for `-o json` commands and `mock kubectl ok` for others.

## Mock terraform

```bash
CORDUM_TERRAFORM_PATH=tools/mock/terraform
CORDUM_TERRAFORM_WORKDIR=tools/mock/terraform-workdir
```

Outputs deterministic, successful results for `init`, `validate`, `plan`,
`output`, `show`, and `apply`.
