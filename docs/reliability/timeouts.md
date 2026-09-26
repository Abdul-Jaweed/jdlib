# Timeouts and deadlines

A request carries a deadline, and the deadline is part of the request identity rather than a value
each layer invents.

## Where it comes from

`jdlib.security.context.RequestIds` carries the request's identity — the request id, the trace id and
the deadline — and the middleware binds it before anything else runs. Downstream code reads the
deadline from the context instead of starting its own clock, so a chain of calls shares one budget
rather than multiplying it.

## The rule

* **One deadline per request.** A layer that needs to bound its own work *subtracts* from the
  remaining time rather than starting a fresh timeout.
* **An expired deadline is a refusal**, not a partial answer: the operation stops where it is and the
  failure is the canonical envelope.
* **The deadline travels.** The outbound calls the library makes (the policy engine, the graph, the
  audit sink) carry the request's identity so a slow dependency is attributable to the request that
  hit it.

## What is not a timeout

The **breaker** is not a timeout: it decides whether to attempt at all. The **gate** is not a
timeout: it decides whether the work is admitted. A timeout bounds one attempt; those two bound the
*set* of attempts, which is what protects a struggling dependency.

## Where it is tested

`tests/unit/security/` for the context's deadline semantics, and the library's integration suites for
the outbound calls carrying the request identity.
