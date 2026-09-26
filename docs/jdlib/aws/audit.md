---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules:
  - src/jdlib/security/audit/cloudwatch.py
exports:
  - CloudWatchLogsAuditSink
  - CloudWatchLogsConfig
  - CloudWatchLogsClient
test_files:
  - tests/unit/test_aws_audit_cloudwatch.py
---

# Audit: CloudWatch Logs as a security event sink

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). Classified **ADAPTER** (optional in the directive,
> and it fits: the `SecurityEventSink` protocol already exists).

## What it is

`CloudWatchLogsAuditSink` — a `SecurityEventSink` that writes each event to CloudWatch Logs as one
JSON document, for deployments that ship security events to a log platform where they are retained,
searched and alerted on. The client is injected, duck-typed like every other transport in this
programme, so the sink is testable without AWS.

## The two sinks, and why both exist

| | `TransactionAuditSink` | `CloudWatchLogsAuditSink` |
| --- | --- | --- |
| Where | the database, in the caller's transaction | CloudWatch Logs |
| On failure | the operation fails with its audit row | `emit` raises |
| Guarantee | the audit row and the operation commit together or not at all | the event is in the log platform, searchable and alertable |
| Use it for | evidence that an operation happened | detection, retention, correlation across services |

They are complementary, not alternatives: a deployment usually wants both, which is why the emitter
takes a sink rather than a list of them.

## Two decisions stated plainly

**Fail-closed, visibly.** `emit` raises when the write fails, and it treats CloudWatch's
`rejectedLogEventsInfo` as a failure even though the API call succeeded — an accepted call is not a
written event, and an audit trail that treats it as one is worse than an audit trail that admits it
lost something. A deployment that prefers best-effort can wrap this sink; the choice is then explicit
in code rather than hidden in the library.

**No secret material.** The document is the event's own fields. `metadata` has already been through
the audit model's sanitiser, and this sink adds nothing to it. A client exception's *message* is
never echoed into the event or into the raised error, because a rejected payload can be quoted back
inside it — the same rule the Secrets Manager provider follows.

## CloudTrail is not this

CloudTrail records the AWS **control plane and data plane**: who called which AWS API. It does not
record that a user was refused permission to read a document, which tenant they belonged to, or
which policy decided it. Application audit answers those questions, and the two are read together
during an investigation rather than substituted for one another.

## Limits and costs

CloudWatch Logs charges per ingestion and per stored GB, and `PutLogEvents` is rate-limited per
stream. This sink writes one event per call, which is correct and chatty; a high-volume deployment
should batch upstream (the emitter is the natural place) or accept the per-call cost. Retention is a
log-group setting — the library does not set it, because a retention policy is a compliance decision.

## Testing

Eleven tests in `tests/unit/test_aws_audit_cloudwatch.py` with an injected client: the document
shape, the millisecond timestamp, the absence of a sequence token, the failure paths (including the
rejected-event case), and two leak assertions. No AWS account, so the live path is
`NOT RUN — AWS credentials unavailable`.
