---
guide: observability
authority: docs/security/observability-hardening.md
modules:
  - src/jdlib/security/tracing.py
  - src/jdlib/security/telemetry.py
  - src/jdlib/reliability/__init__.py
  - src/jdlib/reliability/breaker.py
  - src/jdlib/reliability/budget.py
  - src/jdlib/reliability/concurrency.py
  - src/jdlib/reliability/lifecycle.py
  - src/jdlib/reliability/policy.py
exports:
  - security_span
  - SecuritySpan
  - TraceContext
  - parse_traceparent
  - format_traceparent
  - SPAN_ATTRIBUTE_ALLOWLIST
  - CORRELATION_ID_HEADER
  - CircuitBreaker
  - BreakerPolicy
  - RetryBudget
  - ShutdownCoordinator
example:
  - examples/enterprise/app/main.py
test_files:
  - tests/unit/test_reliability_breaker.py
  - tests/unit/test_reliability_concurrency.py
  - tests/unit/test_graph_observability.py
  - tests/unit/test_mcp_observability.py
---
# Observability and reliability

> **Design authority:** [`docs/security/observability-hardening.md`](../../security/observability-hardening.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

Spans with a fixed attribute allow-list, correlation ids carried end to end, and the reliability primitives -- circuit breaker, retry budget, concurrency gate, shutdown coordinator -- that keep a failing dependency from becoming a failing process.

## Why it exists

Observability in a security system has two jobs, and only one of them is debugging: the other is *not leaking*. An allow-list means a span cannot carry a token because someone passed one by accident; the reliability primitives mean a degraded dependency is a degraded feature, not an outage.

## When to use it

From the first request in production, and before: the ids are what make every other feature's evidence joinable, and the primitives are what make a dependency's failure a state the application has rather than an incident it suffers.

## When not to use it

Do not put anything in a span that you would not put in the audit trail, and do not use the breaker as a retry mechanism -- they answer different failures.

## How it works

`security_span` opens a span with the security attributes the allow-list permits (`SPAN_ATTRIBUTE_ALLOWLIST`; anything else is dropped, and `FORBIDDEN_SPAN_ATTRIBUTES` names the ones that must never appear); `TraceContext` carries `traceparent` across a hop, and `request_ids_from_headers` picks up or creates the request and correlation ids. `CircuitBreaker` + `BreakerPolicy` open a failing dependency, `RetryBudget` bounds retries so a storm cannot amplify, and `ShutdownCoordinator` drains in-flight work on the way down.

## Architecture

`security/tracing.py` (spans, ids, the allow-list), `security/telemetry.py` (the emitter seam), `reliability/` (breaker, budget, concurrency, shutdown, dead letter). The `TracerLike` protocol is the seam an application plugs its own tracer into.

## Example

`examples/enterprise/app/main.py` shows both halves: `/readyz` refuses to report ready when the policy engine cannot decide, and the composition is released through `aclose` -- the shutdown path a coordinator would drive.

## Security

The allow-list is the security property: spans carry ids, actions, outcomes and resource kinds -- never values, tokens, DSNs or personal data. A forbidden attribute is dropped rather than recorded, and the list is asserted by test rather than trusted to reviewers.

## Reliability

Each primitive answers one failure mode: the breaker stops hammering a dead dependency, the budget stops retry amplification, the concurrency gate stops an unbounded fan-out, and the coordinator stops work being cut off mid-write. Together they are what makes 'degraded' a state the application has.

## Observability

Correlation ids come from the request and are carried into jobs and tool calls, so one id joins the HTTP request, its audit events, its spans and anything it enqueued.

## Audit

Reliability events that matter are audited (a breaker opening on a security dependency, a privileged read timing out) -- an outage of an authorization dependency is a security event, not only an operational one.

## Configuration

The tracer implementation, the breaker's thresholds and the budget's limits are configuration; the attribute allow-list is code, because it is a claim about what may leave the process.

## Testing

`test_reliability_breaker.py` and `test_reliability_concurrency.py` cover the primitives; the graph and MCP observability suites assert the span vocabulary and the allow-list end to end.

## Common mistakes

Logging a whole request or a resolved credential into a span attribute; treating a breaker as a retry mechanism; retrying without a budget; reporting ready while a security dependency is degraded; shutting down without draining.

## Production checklist

Ship spans to a collector with its own access control; alert on breaker opens and budget exhaustion; keep `/readyz` honest about the engine; and rehearse a dependency outage to confirm the application degrades rather than falls over.
