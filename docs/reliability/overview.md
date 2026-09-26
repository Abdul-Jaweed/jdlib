# Reliability

The library's reliability primitives answer one question each, and none of them is a retry loop
someone wrote inside a handler. This section is how to use them; the
[reliability architecture](../architecture/reliability-architecture.md) is how they compose.

| Page | The primitive |
|---|---|
| [Timeouts and deadlines](timeouts.md) | the deadline a request carries, and what happens when it passes |
| [Retries and budgets](retries-and-backoff.md) | `jdlib.reliability.budget.RetryBudget` |
| [Circuit breakers](circuit-breakers.md) | `jdlib.reliability.breaker.CircuitBreaker` |
| [Rate limiting and admission](rate-limiting.md) | `jdlib.reliability.concurrency.ConcurrencyGate` |
| [Shutdown and draining](shutdown.md) | `jdlib.reliability.lifecycle.ShutdownCoordinator` |
| [Failure modes](failure-modes.md) | the table: what each dependency being down looks like from outside |

## The posture

* **Bounded, not best-effort.** Every primitive has an explicit limit: a budget, a gate size, a
  breaker threshold. A limit that is not written down is not a limit.
* **Refuse visibly.** A refusal is an envelope with a stable code, an audit event where a decision
  was involved, and a metric — never a silent drop.
* **Per process.** The breaker, the budget and the gate are per-process state. A fleet shares the
  dependency, not the counters; the deployment's own metrics are what make a fleet-wide view possible.
