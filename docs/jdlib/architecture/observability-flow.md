# The observability flow

What leaves the process, what must never leave it, and how one id joins the whole story.

## The ids

```
an inbound request
  ├── traceparent (W3C)     honoured if present, created if not   (parse_traceparent / format_traceparent)
  ├── request_id            the request's own id                  (REQUEST_ID_HEADERS, or created)
  └── correlation_id        stable across the work a request causes (CORRELATION_ID_HEADER)
        │
        ├─ the SecurityContext        carried by the context
        ├─ every audit event          recorded on the row
        ├─ every span                 an allow-listed attribute
        └─ anything enqueued          the envelope carries it, so a job joins its cause
```

One id is what makes the trail, the spans and the caller's error envelope joinable — which is the
difference between an incident you can reconstruct and one you can only describe.

## What a span may carry

`SPAN_ATTRIBUTE_ALLOWLIST` is the whole list: ids, the action, the outcome, the resource kind, the
tenant, the operation. `FORBIDDEN_SPAN_ATTRIBUTES` names what must never appear — tokens, DSNs,
values, personal data — and a forbidden attribute is **dropped** rather than recorded. The list is
asserted by test, not trusted to reviewers, because "someone passed the whole request object" is a
one-line mistake with a permanent consequence.

## Degrading rather than failing

| Primitive | The failure it answers |
|---|---|
| `CircuitBreaker` + `BreakerPolicy` | a dependency that is not answering: stop hammering it, and serve what does not need it |
| `RetryBudget` | retries that amplify: a bounded number, then fail fast |
| `ConcurrencyGate` | unbounded fan-out: a ceiling on in-flight work |
| `ShutdownCoordinator` + `DrainHook` | a stop that cuts work mid-write: drain, then exit |
| `backoff_seconds`, `is_retryable_failure` | retrying what cannot succeed, or retrying too eagerly |

The graph and MCP paths use the same primitives, so a slow graph does not become a slow application
and a degraded engine refuses rather than allowing.

## What the example shows

`/readyz` is the honest half: it executes a statement in the control plane **and** gets a decision
from the engine, and reports not-ready when either fails — because a probe that says ready while
every authorization question would be refused is a probe that lies during exactly the incident it
exists for. `Collaborators.aclose()` is the shutdown path a coordinator would drive.
