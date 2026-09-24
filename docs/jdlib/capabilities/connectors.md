---
capability: connectors
namespace: jdlib.data
errors_module: jdlib.data.errors
modules:
  - src/jdlib/data/capabilities.py
  - src/jdlib/data/connector.py
  - src/jdlib/data/contract.py
  - src/jdlib/data/errors.py
  - src/jdlib/data/policy.py
  - src/jdlib/data/postgres.py
  - src/jdlib/data/registry.py
exports:
  - ConnectionPolicy
  - ConnectorCapabilities
  - ConnectorRegistry
  - DataConnector
  - PostgresConnector
  - assert_connector_contract
refusals:
  - AuthorizationRefusedError
  - CircuitOpenError
  - ConnectorError
  - ConnectorTimeoutError
test_files:
  - tests/unit/test_connector_framework.py
  - tests/integration/test_postgres_connector.py
test_functions: 19
---
# Connectors: framework, policy, and the PostgreSQL backend

## What it is

A connector declares static capabilities (its name, whether it writes, which dialect) and the
registry refuses to hold one that does not satisfy the contract. Acquisition goes through the
registry, so the framework is the only way a connector is built.

```python
registry = ConnectorRegistry(tracer=tracer, emitter=emitter)
registry.register(PostgresConnector)

async with registry.build("postgres").opened(target=config, context=context) as conn:
    rows = await conn.execute(statement=compiled.text,
                              params=tuple(compiled.parameters.items()))
```

## The decisions that carry weight

**`ConnectionPolicy` extends the adapter-local idiom rather than replacing it.** The reliability
inventory found timeouts and bounded retry already implemented per adapter, so the policy adds
only what was genuinely absent - circuit breaking and half-open recovery - and consults the
existing `is_retryable()` taxonomy, which finally gives that public contract a caller in `src/`.

**Declared capabilities are enforced, not decorative.** This connector says `writes=False` and
refuses a statement that is not a read; a declaration nothing acts on is a comment.

**The engine is built per open from the resolved target**, never from a stored DSN, because a
stored DSN is a credential that outlives its rotation. The tenant in the authorized context must
match the target's tenant or the connection refuses to open.

## Evidence

19 test functions across `tests/unit/test_connector_framework.py` and `tests/integration/test_postgres_connector.py`, run with the project gate:

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_connector_framework.py -q
.venv/Scripts/python.exe -m pytest tests/integration/test_postgres_connector.py -q
```

Parametrized cases expand these functions further; the counts here are
functions, which is what the documentation check verifies.

## Limits

PostgreSQL only. Snowflake, MongoDB, StarRocks and BigQuery have no module and no export - a
connector class in the public surface is a claim that it works, and the absence is asserted by a
test rather than promised in a roadmap. The retry budget, worker retry, dead-letter handling,
security-context preservation during retries and shutdown drain remain open (§06-reliability-inventory).
