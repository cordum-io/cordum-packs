# Cordum Kubernetes Triage Pack

Production-ready Kubernetes diagnostics and remediation workflows routed through Cordum's policy engine.
Workers use `kubectl` to run read-only inspections or approved remediation commands.

## What you get

- **Kubernetes triage worker**: runs `kubectl` commands and returns structured results.
- **Governed access**: read is allowed by default; write requires approval.
- **Workflow templates**: generic read/write workflows for triage actions.

## Runtime component

The pack runtime is the `cordum-kubernetes-triage` worker in
`cmd/cordum-kubernetes-triage`. Installing the pack only registers
workflows/schemas; you must run or deploy the worker so `job.kubernetes-triage.*`
jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/kubernetes-triage/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/kubernetes-triage

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_K8S_KUBECONFIG=~/.kube/config \
CORDUM_K8S_CONTEXT=prod-cluster \
CORDUM_K8S_NAMESPACE=default \
CORDUM_K8S_ALLOWED_NAMESPACES=default,platform \

kubectl version --client \

go run ./cmd/cordum-kubernetes-triage
```

## Environment

- `CORDUM_GATEWAY_URL` (default `http://localhost:8081`)
- `CORDUM_API_KEY` (optional; required for enterprise installs)
- `CORDUM_NATS_URL` (default `nats://localhost:4222`)
- `CORDUM_REDIS_URL` (default `redis://localhost:6379`)
- `CORDUM_K8S_POOL` (default `kubernetes-triage`)
- `CORDUM_K8S_QUEUE` (default `kubernetes-triage`)
- `CORDUM_K8S_SUBJECTS` (default `job.kubernetes-triage.*`)
- `CORDUM_K8S_MAX_PARALLEL` (default `0` = unlimited)
- `CORDUM_K8S_REQUEST_TIMEOUT` (default `45s`)
- `CORDUM_K8S_COMMAND_TIMEOUT` (default `30s`)
- `CORDUM_K8S_RESULT_TTL` (optional; example `24h`)
- `CORDUM_K8S_DEFAULT_PROFILE` (default `default`)

### Default profile (env-based)

If `CORDUM_K8S_PROFILES` is not set, the worker builds a single `default` profile from:

- `CORDUM_K8S_KUBECONFIG` (optional)
- `CORDUM_K8S_CONTEXT` (optional)
- `CORDUM_K8S_NAMESPACE` (default `default`)
- `CORDUM_K8S_KUBECTL_PATH` (default `kubectl`)
- `CORDUM_K8S_ALLOWED_NAMESPACES` (comma-separated allowlist)
- `CORDUM_K8S_DENIED_NAMESPACES` (comma-separated denylist)
- `CORDUM_K8S_ALLOW_ACTIONS` (comma-separated allowlist)
- `CORDUM_K8S_DENY_ACTIONS` (comma-separated denylist)

### Profiles (recommended)

Define multiple profiles using `CORDUM_K8S_PROFILES`:

```json
[
  {
    "name": "prod",
    "kubeconfig": "/etc/kubeconfigs/prod",
    "context": "prod",
    "namespace": "platform",
    "allowed_namespaces": ["platform", "default"],
    "allow_actions": ["pods.*", "deployments.get", "deployments.restart"]
  }
]
```

## Supported actions

Read actions (use `job.kubernetes-triage.read`):

- `pods.list` (params: `namespace`, `label_selector`, `field_selector`)
- `pods.get` (params: `namespace`, `name`)
- `pods.logs` (params: `namespace`, `name`, `container`, `tail_lines`, `since_seconds`, `timestamps`, `previous`)
- `events.list` (params: `namespace`, `label_selector`, `field_selector`)
- `deployments.list` (params: `namespace`, `label_selector`, `field_selector`)
- `deployments.get` (params: `namespace`, `name`)
- `nodes.list`
- `rollouts.status` (params: `namespace`, `name`)

Write actions (use `job.kubernetes-triage.write`):

- `deployments.restart` (params: `namespace`, `name`)
- `deployments.scale` (params: `namespace`, `name`, `replicas`)
- `pods.delete` (params: `namespace`, `name`)

## Job input

The worker expects `KubernetesTriageActionInput` payloads. Example:

```json
{
  "profile": "prod",
  "action": "pods.logs",
  "params": {
    "namespace": "platform",
    "name": "api-7d9b9df6f7-4p9l2",
    "tail_lines": 200
  }
}
```

## Security

- **Default policy**: read is allowed, write requires approval.
- **Allow/deny lists**: enforce namespace and action allowlists to limit scope.
- **No inline auth**: access is controlled by kubeconfig/profile settings.

## License

BUSL-1.1 (same as Cordum core).
