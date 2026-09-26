# Circuit breakers

`jdlib.reliability.breaker.CircuitBreaker` stops attempting a dependency that is failing, so callers
fail fast instead of queueing behind it.

## The states

| State | Behaviour | How it leaves |
|---|---|---|
| `CLOSED` | calls pass; failures are counted | a threshold of failures opens it |
| `OPEN` | calls are refused **without an attempt** | after the cooldown, one trial call is allowed |
| `HALF_OPEN` | one trial call decides | success closes it; failure opens it again |

`BreakerPolicy` carries the thresholds, so the numbers are configuration rather than constants buried
in a call site.

## What "refused without an attempt" means for a client

A request that meets an open breaker fails *fast* — it does not wait for a timeout. That is the
property that keeps a slow dependency from consuming the application's concurrency: without it, every
request waits for the full timeout and the application's own capacity becomes the casualty.

## Tuning it

* **Open on failures that mean "down"**, not on every error: a validation refusal says nothing about
  the dependency's health.
* **The cooldown is a probe interval**, not a recovery guarantee: it is how often the process is
  willing to spend one call finding out.
* **One breaker per dependency**, not one per route: the question is whether the dependency is
  answering.

## Where it is tested

`tests/unit/` for the state machine (including the half-open trial and the open-circuit refusal), and
the examples' live layers for the composed behaviour.
