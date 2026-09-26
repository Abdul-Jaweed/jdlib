---
guide: connectors
authority: docs/jdlib/connectors.md
modules:
  - src/jdlib/data/__init__.py
  - src/jdlib/data/capabilities.py
  - src/jdlib/data/connector.py
  - src/jdlib/data/contract.py
  - src/jdlib/data/errors.py
  - src/jdlib/data/policy.py
  - src/jdlib/data/postgres.py
  - src/jdlib/data/registry.py
exports:
  - DataConnector
  - ConnectorRegistry
  - PostgresConnector
  - ConnectionPolicy
  - ConnectorCapabilities
  - assert_connector_contract
example:
  - examples/enterprise/app/configuration/settings.py
test_files:
  - tests/unit/test_connector_framework.py
  - tests/integration/test_postgres_connector.py
---
# Connectors

> **Design authority:** [`docs/jdlib/connectors.md`](../connectors.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

The framework for reaching a data source that is not the application's own database: a connector interface, a registry that refuses a connector that has not declared what it can do, and a policy for how connections are held.

## Why it exists

A connector is where an application's guarantees stop being enforced by the database: the tenant filter, the timeout, the retry and the credential all become the connector's responsibility. The framework exists so those are declared once and checked, not re-remembered per source.

## When to use it

When an application must read from or write to another store (a warehouse, a tenant's own database, an analytics engine) as part of a tenant-scoped operation.

## When not to use it

For the application's own data -- that is the tenant plane's repository -- and for one-off operational scripts, which should not become a supported integration by accident.

## How it works

A connector declares its `ConnectorCapabilities` (what it can do, what it cannot), a `ConnectionPolicy` (timeouts, pooling, whether it may be reused), and implements the `DataConnector` interface; `ConnectorRegistry` refuses a registration that does not declare them. `PostgresConnector` is the reference implementation, and `assert_connector_contract` is the suite any new one must pass.

## Architecture

`data/connector.py` (the interface), `data/registry.py` (registration and refusal), `data/capabilities.py` and `data/policy.py` (declarations), `data/contract.py` (the shared test), `data/postgres.py` (the reference).

## Example

The example configures its connectors through settings; the framework's own tests and the PostgreSQL connector's integration test are the reference, and a deployment's connector should pass the same contract.

## Security

Credentials come from the credential seam, never from a call site; the tenant is part of the operation, and a connector that cannot be tenant-scoped declares that in its capabilities so the application can refuse to use it for tenant work.

## Reliability

`ConnectorTimeoutError` and `CircuitOpenError` are typed: a slow or failing source degrades one operation rather than the process, and the circuit breaker is the same primitive the graph and MCP paths use.

## Observability

Each connector call is a span with the connector's name, the operation and the outcome; the target's address is not an attribute (it can carry a credential).

## Audit

A connector that reads another system's data on a tenant's behalf is a privileged access: the trail records the connector, the tenant and the operation.

## Configuration

Per-connector settings (endpoint, pool, timeouts) are configuration; the capabilities are code, because they are claims about behaviour.

## Testing

`tests/unit/test_connector_framework.py` covers registration and refusal; `tests/integration/test_postgres_connector.py` runs the contract against a real database.

## Common mistakes

Registering a connector without capabilities; holding one connection for every tenant; retrying a non-idempotent write; letting a connector's own SQL bypass the tenant predicate.

## Production checklist

Run the connector contract in your gate; give each connector its own pool and timeout; declare honestly what it cannot do; and keep its credentials in the credential seam.
