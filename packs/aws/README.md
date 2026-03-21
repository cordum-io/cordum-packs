# AWS Pack

Full AWS cloud integration for Cordum — Lambda, S3, SQS, SNS, EC2, IAM, CloudWatch, and Secrets Manager.

## Services & Actions

| Service | Read Actions | Write Actions |
|---------|-------------|---------------|
| **Lambda** | get_function, list_functions | invoke |
| **S3** | get_object, list_buckets, list_objects, head_object | put_object, delete_object |
| **SQS** | receive_message, get_queue_url, list_queues | send_message |
| **SNS** | list_topics, list_subscriptions | publish |
| **EC2** | describe_instances, describe_security_groups, describe_vpcs | — |
| **CloudWatch** | get_metric_data, list_metrics, describe_alarms | — |
| **IAM** | get_user, list_users, list_roles, list_policies | — |
| **Secrets Manager** | get_secret_value, list_secrets, describe_secret | — |

## Topics & Policy

| Topic | Actions | Policy |
|-------|---------|--------|
| `job.aws.read` | All read/describe/list/get actions | ALLOW |
| `job.aws.write` | invoke, put, delete, send, publish | REQUIRE_APPROVAL |

Write actions sent to `job.aws.read` are rejected — the worker enforces topic-intent alignment.

## Credential Chain

AWS credentials are resolved in this order:

1. **Static credentials** from profile config (`access_key_id` + `secret_access_key`)
2. **Default chain** (env vars `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, shared credentials `~/.aws/credentials`, EC2 instance metadata)
3. **STS AssumeRole** if `role_arn` is set on the profile (for cross-account access)

## Quick Start

```bash
# 1. Set AWS credentials
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...

# 2. Build
cd packs/aws
go build -o cordum-aws.exe ./cmd/cordum-aws/

# 3. Run (requires NATS + Redis)
./cordum-aws.exe
```

## Example: Lambda Invoke

Submit to `job.aws.write`:

```json
{
  "action": "lambda.invoke",
  "region": "us-east-1",
  "params": {
    "function_name": "my-function",
    "payload": {"key": "value"},
    "invocation_type": "RequestResponse"
  }
}
```

## Example: S3 Get Object

Submit to `job.aws.read`:

```json
{
  "action": "s3.get_object",
  "params": {
    "bucket": "my-bucket",
    "key": "path/to/file.json"
  }
}
```

Response includes `body_base64` (base64-encoded content, truncated at 10MB).

## Example: SQS Send Message

Submit to `job.aws.write`:

```json
{
  "action": "sqs.send_message",
  "params": {
    "queue_url": "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue",
    "message_body": "{\"event\": \"order_placed\", \"id\": 42}",
    "delay_seconds": 10
  }
}
```

## Example: CloudWatch Metrics

Submit to `job.aws.read`:

```json
{
  "action": "cloudwatch.get_metric_data",
  "params": {
    "namespace": "AWS/EC2",
    "metric_name": "CPUUtilization",
    "dimensions": {"InstanceId": "i-0123456789abcdef0"},
    "stat": "Average",
    "period": 300,
    "hours_back": 6
  }
}
```

## Action/Resource Restrictions

Control which actions and resources are accessible per profile:

```bash
# Only allow S3 and Lambda actions
CORDUM_AWS_ALLOW_ACTIONS=s3.*,lambda.*

# Block destructive actions
CORDUM_AWS_DENY_ACTIONS=s3.delete_object,lambda.invoke

# Only allow dev resources
CORDUM_AWS_ALLOWED_RESOURCES=arn:aws:s3:::dev-*,arn:aws:lambda:*:*:function:dev-*

# Block production resources
CORDUM_AWS_DENIED_RESOURCES=arn:aws:s3:::prod-*
```

Glob patterns use `*` as wildcard. Deny takes priority over allow.

## Multi-Account Profiles

```bash
CORDUM_AWS_PROFILES='[
  {
    "name": "prod",
    "region": "us-east-1",
    "role_arn": "arn:aws:iam::123456789012:role/cordum-prod",
    "external_id": "cordum-external",
    "allow_actions": ["s3.get_object", "s3.list_*"]
  },
  {
    "name": "staging",
    "region": "us-west-2",
    "access_key_id_env": "STAGING_AWS_KEY",
    "secret_access_key_env": "STAGING_AWS_SECRET"
  }
]'
```

Use the `profile` field in requests to select a profile: `{"action": "s3.list_buckets", "profile": "prod"}`.

## Environment Variables

See [`deploy/env.example`](deploy/env.example) for the full list.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AWS_REGION` | No | `us-east-1` | Default AWS region |
| `AWS_ACCESS_KEY_ID` | Yes* | — | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | Yes* | — | AWS secret key |
| `CORDUM_AWS_ROLE_ARN` | No | — | STS role ARN for cross-account |
| `CORDUM_AWS_ALLOW_ACTIONS` | No | (all) | Comma-separated action allow list |
| `CORDUM_AWS_DENY_ACTIONS` | No | (none) | Comma-separated action deny list |

*Not required when using EC2 instance metadata or shared credentials.

## Security

- All credentials sourced from environment variables or AWS credential chain — never hardcoded
- Write actions require policy approval (REQUIRE_APPROVAL)
- Topic-intent enforcement: write actions rejected on read topic
- Action allow/deny lists with glob pattern matching
- Resource ARN allow/deny for fine-grained access control
- Cross-account access via STS AssumeRole with optional external ID
- S3 binary responses base64-encoded and truncated at 10MB to prevent memory issues
- Uses aws-sdk-go-v2 with connection pooling
