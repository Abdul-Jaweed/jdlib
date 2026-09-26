# Reliability architecture

Reliability in this library is about *failing in a way the deployment can see and recover from*: a
dependency that is down should produce a bounded, observable refusal rather than a queue of stuck
requests, and a shutdown should finish the work it accepted.

## The failure domains

```mermaid
flowchart TB
    req["a request"] --> gate["ConcurrencyGate<br/>jdlib.reliability.concurrency"]
    gate -->|"admitted"| call["the call"]
    gate -->|"over the limit"| refuse["429 / refusal<br/>audited, counted"]
    call --> cb["CircuitBreaker<br/>jdlib.reliability.breaker"]
    cb -->|"closed"| dep["dependency"]
    cb -->|"open"| failfast["immediate refusal<br/>no attempt made"]
    dep -->|"transient"| retry["RetryBudget<br/>jdlib.reliability.budget"]
    retry -->|"budget left"| call
    retry -->|"exhausted"| give["refusal + the budget is spent"]
    dep -->|"permanent"| give
    stop["ShutdownCoordinator<br/>jdlib.reliability.lifecycle"] -.->|"drain"| gate
    stop -.->|"report"| probe["/readyz tells the truth"]
```

| Primitive | Module | The question it answers |
|---|---|---|
| `ConcurrencyGate` | `jdlib.reliability.concurrency` | how much work is admitted at once, and what happens to the rest |
| `CircuitBreaker` (`BreakerPolicy`, `BreakerState`) | `jdlib.reliability.breaker` | when to stop trying, and how it closes again |
| `RetryBudget` | `jdlib.reliability.budget` | how much retrying is allowed in total, so retries cannot amplify an outage |
| `ShutdownCoordinator` (`ShutdownReport`) | `jdlib.reliability.lifecycle` | how accepted work finishes while new work is refused |

## Why a *budget* rather than per-call retries

A retry policy that counts attempts per call multiplies load on a dependency that is already
struggling: every caller retries, and the dependency sees the product. A `RetryBudget` is a shared
allowance — when it is spent, callers stop retrying and fail fast, which is the behaviour that lets a
degraded dependency recover.

## Readiness that tells the truth

`/healthz` answers for the process (it is serving, no dependencies checked); `/readyz` answers for
the dependencies (`SELECT 1` against the control plane). The split is not cosmetic: a probe that
needs a token fails during an identity-provider outage and gets a healthy process restarted for it.
The minimal example asserts both, including `/readyz` answering `503 DEPENDENCY_UNAVAILABLE` when its
database is down, through the library's own envelope.

## What is deliberately not here

* **A job queue.** `jdlib.tenancy.job_envelope` gives work an authority, a tenant and a lifetime;
  delivery, retries and the dead-letter store belong to the deployment's queue. `jdlib.tenancy.dead_letter`
  is the *shape* the library hands a queue, not a queue.
* **A scheduler.** Nothing in the library wakes up and does work on its own.
* **Cross-process coordination.** The breaker, the budget and the gate are per-process. A fleet
  shares the dependency, not the state — the deployment's metrics are what make that visible.
