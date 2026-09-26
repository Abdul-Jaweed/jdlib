---
guide: aws
authority: docs/jdlib/aws/research-sources.md
modules: []
exports: []
test_files: []
---

# Observability: OpenTelemetry first, AWS through the collector

> **Design authority:** [the AWS capability matrix](aws-capability-matrix.md) and
> [the research sources](research-sources.md). Classified **ADOPT**: the library already emits
> OpenTelemetry, and nothing about AWS requires it to emit anything else.

## The rule

The library's tracing and telemetry are OpenTelemetry (`security/tracing.py`,
`security/telemetry.py`), and **no core module imports an AWS SDK for observability**. The
deployment runs a collector — the AWS Distro for OpenTelemetry, or any OTel collector — and the
collector exports to CloudWatch, X-Ray or both.

```text
JDLib (OTLP) --> OTel collector (ADOT) --> CloudWatch Logs / CloudWatch metrics / X-Ray
```

That indirection is the whole design: a library that spoke CloudWatch directly would be unusable
outside AWS and untestable without credentials, and the trace context it propagates would be an AWS
detail rather than a standard.

## What maps to what

| JDLib / OTel concept | AWS destination | Note |
| --- | --- | --- |
| Traces and spans | X-Ray, or CloudWatch Transaction Search | both ingest OTLP through the collector |
| Trace context (`traceparent`) | propagated in-band | the library's outbound calls already carry it |
| Metrics | CloudWatch metrics via the EMF exporter or OTLP | the collector chooses; the library does not |
| Logs | CloudWatch Logs | structured, with the trace id attached so a log line joins its trace |
| Resource attributes | CloudWatch dimensions | attributes are not dimensions by default — the collector maps them |
| Span annotations vs metadata | X-Ray annotations are indexed and filterable, metadata is not | anything you want to search by must be an annotation, and the collector or the application decides that, not the library |

## What to instrument, in this library's terms

* **The decision point**: whether a decision was allowed, denied or degraded, and how long the
  engine took. A degraded decision is the most important signal in the system — it means
  authorization infrastructure failed and requests were refused because of it.
* **Authentication**: token validation outcomes and JWKS refreshes (an unknown `kid` forcing a
  refresh is normal; a JWKS endpoint that stops answering is not).
* **Tenant scoping**: which tenant a request resolved to, as a span attribute rather than a metric
  dimension — high-cardinality dimensions are a cost trap.
* **Data-plane calls**: database, cache, graph and object-store spans, with the operation and the
  outcome but never the payload.

## What not to instrument

Never a secret value, never a token, never a request body, and never a principal's personal data.
The library's own rule is that attributes are chosen deliberately; an observability change that adds
a payload "for debugging" is a data-protection incident waiting for a retention window.

## Health is not observability

Metrics tell you how the system behaved; they do not tell a load balancer whether to send traffic.
That is [the health page](health.md), and the two must not be conflated — an alarm that pages a human
is not a readiness check, and a readiness check that pages a human is a misconfigured probe.
