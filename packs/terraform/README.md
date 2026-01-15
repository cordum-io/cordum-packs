# Cordum Terraform Pack

Run Terraform plan/apply workflows with governed access, directory scoping, and approval gates.

## Runtime component

The runtime is the `cordum-terraform` worker in `cmd/cordum-terraform`. Installing the pack only registers workflows/schemas; you must run or deploy the worker so `job.terraform.*` jobs are executed.

## Quickstart

### 1) Install the pack

```bash
cd path/to/cordum
./cmd/cordumctl/cordumctl pack install path/to/cordum-packs/packs/terraform/pack
```

### 2) Run the worker

```bash
cd path/to/cordum-packs/packs/terraform

CORDUM_GATEWAY_URL=http://localhost:8081 \
CORDUM_API_KEY=super-secret-key \
CORDUM_NATS_URL=nats://localhost:4222 \
CORDUM_REDIS_URL=redis://localhost:6379 \
CORDUM_TERRAFORM_WORKDIR=/repos/infra \
CORDUM_TERRAFORM_ALLOWED_DIRS=/repos/infra/* \

go run ./cmd/cordum-terraform
```

See `deploy/env.example` for the full list of environment variables.

## Supported actions

Read actions (use `job.terraform.read`):

- `plan.run`
- `plan.show`
- `validate.run`
- `output.list`

Write actions (use `job.terraform.write`):

- `apply.run`

## Action parameters

`plan.run`:

```json
{
  "action": "plan.run",
  "params": {
    "dir": "/repos/infra/envs/prod",
    "var_file": ["prod.tfvars"],
    "detailed_exitcode": true
  }
}
```

`apply.run` (auto-approve):

```json
{
  "action": "apply.run",
  "params": {
    "dir": "/repos/infra/envs/prod",
    "auto_approve": true
  }
}
```

`plan.show`:

```json
{
  "action": "plan.show",
  "params": {
    "dir": "/repos/infra/envs/prod",
    "plan_file": "tfplan.out"
  }
}
```

## Security

- Use `CORDUM_TERRAFORM_ALLOWED_DIRS` and `CORDUM_TERRAFORM_DENIED_DIRS` to constrain working directories.
- Write actions require approval by default (per pack policy fragment).
