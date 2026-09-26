# Shutdown and draining

`jdlib.reliability.lifecycle.ShutdownCoordinator` makes a shutdown finish the work it accepted.

## The sequence

1. **Readiness flips first.** `/readyz` starts answering not-ready, so the load balancer stops sending
   new work while the process is still able to serve what it has.
2. **New work is refused.** A request that arrives after the drain began gets
   `ShutdownInProgressError` rather than a half-served response.
3. **Accepted work finishes**, bounded by the coordinator's own deadline.
4. **A `ShutdownReport` says what happened** — what completed, what did not, and how long it took.

```python
from jdlib.reliability.lifecycle import ShutdownCoordinator, ShutdownReport

coordinator = ShutdownCoordinator(...)
report: ShutdownReport = await coordinator.drain()
```

## Why the order matters

The common failure is the reverse order: the process stops accepting, then closes its pools, then
discovers that in-flight work needed them. Draining exists to make "finish what you accepted" the
first rule instead of the last.

## What the report is for

It is the evidence a rolling deploy is judged by: a deploy that reports in-flight work abandoned is a
deploy that dropped requests, and the report is where that is visible rather than inferred from a
client-side error rate.

## Where it is tested

`tests/unit/` for the coordinator's ordering and refusal semantics; the examples' e2e layer for a
readiness probe flipping before the drain.
