---
page: connectors
sources:
  - src/jdlib/data
  - docs/jdlib/capabilities/connectors.md
---
# Connectors

A connector declares static capabilities (name, whether it writes, its dialect) and is built only
through the registry, which refuses a class that does not satisfy the contract. Full page:
[`capabilities/connectors.md`](capabilities/connectors.md).

## What the framework guarantees

- **Acquisition is the only path.** `ConnectorRegistry.build` is how a connector exists; a class
  in the registry has passed the contract suite.
- **The declared capability is enforced.** `writes=False` refuses a statement that is not a read.
- **The engine is built per open from the resolved target** and disposed on close; the context's
  tenant must match the target's or the connection refuses to open.
- **The policy is bounded.** `ConnectionPolicy` carries a statement timeout, a bounded retry that
  consults `is_retryable()`, and circuit breaking with half-open recovery.

## What exists

PostgreSQL, against a real server, six integration tests. **Snowflake, MongoDB, StarRocks and
BigQuery do not exist** - no module, no export - and a test asserts the absence, because a
connector class in the public surface is a claim that it works.

## Related

Storage backends are a separate protocol with their own page:
[`capabilities/storage.md`](capabilities/storage.md). Object storage has exactly one verified
backend for the same reason.
