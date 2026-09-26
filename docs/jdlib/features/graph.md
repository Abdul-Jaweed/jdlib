---
guide: graph
authority: docs/jdlib/capabilities/graph.md
modules:
  - src/jdlib/graph/__init__.py
  - src/jdlib/graph/client.py
  - src/jdlib/graph/config.py
  - src/jdlib/graph/errors.py
  - src/jdlib/graph/mapping.py
  - src/jdlib/graph/models.py
  - src/jdlib/graph/policy.py
  - src/jdlib/graph/query.py
  - src/jdlib/graph/repository.py
  - src/jdlib/graph/tenant.py
  - src/jdlib/graph/transaction.py
exports:
  - GraphClient
  - GraphConfig
  - GraphQuery
  - GraphRepository
  - GraphRunner
  - GraphPolicy
  - GraphCircuitBreaker
  - GraphTenantViolationError
  - GraphConflictError
  - GraphNotFoundError
example:
  - examples/enterprise/app/graph.py
  - examples/enterprise/tests/integration/test_graph_live.py
test_files:
  - tests/unit/test_graph_client.py
  - tests/unit/test_graph_errors.py
  - tests/unit/test_graph_observability.py
  - tests/unit/test_graph_adversarial.py
---
# The graph plane

> **Design authority:** [`docs/jdlib/capabilities/graph.md`](../capabilities/graph.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

A tenant-bound client for a graph database: a closed vocabulary of labels and relationships, queries built rather than written, and a repository that refuses to touch a node that is not the caller's tenant's.

## Why it exists

A graph database has no row-level security and no schema to constrain you: a label is a string and a traversal is a program. The library's job is to make the tenant a property of the client and the vocabulary a closed set, so neither is a call site's decision.

## When to use it

When a tenant's data is genuinely a graph (relationships that are traversed, not joined) and the graph is a *derived* plane beside the relational record of truth.

## When not to use it

As the system of record -- the relational plane stays the record -- and for anything a relational query answers in one join. If a deployment has no graph, the plane is simply absent.

## How it works

`GraphConfig` describes the connection; `GraphClient` binds a tenant to it; `GraphQuery` builds statements from a closed vocabulary (`mapping.py`); `GraphRepository` is the tenant-scoped data access; `GraphRunner` runs a statement for a tenant that is only known at call time -- which is what a surface serving every tenant needs. `GraphPolicy` and `GraphCircuitBreaker` are the shared reliability primitives.

## Architecture

`graph/client.py` (the connection), `graph/tenant.py` (the binding), `graph/query.py` (the builder), `graph/mapping.py` (the vocabulary), `graph/repository.py` (tenant-scoped access), `graph/transaction.py` (write scope), `graph/policy.py` and `graph/errors.py` (refusals and reliability).

## Example

`examples/enterprise/app/graph.py` is the example's projection of a relational write into the graph, with the tenant taken from the caller's `SecurityContext`; its live tests run against a real Neo4j and include a mutation check that a wrong vocabulary declaration fails.

## Security

The tenant is bound to the client, and `GraphTenantViolationError` is raised when a statement or a node would cross tenants -- a refusal rather than a filter. The vocabulary is closed: a label or relationship that is not declared is refused, which is what stops an injected string from becoming a traversal.

## Reliability

The graph is derived, so its availability is not the application's availability: `GraphCircuitBreaker` opens and the relational path keeps serving. Writes are idempotent by key (`GraphConflictError` on a real conflict), which is what makes a re-projection safe.

## Observability

Each statement is a span with the operation, the node count and the outcome; the tenant is an attribute, the statement text is not.

## Audit

Graph writes that mirror a relational write are audited by the operation that performs both, so the trail names the resource once -- not once per plane.

## Configuration

URI, database and credentials are configuration (`GraphConfig`); the vocabulary is code, because it is a claim about the model.

## Testing

The library's graph suites cover the client, the vocabulary, the errors and the observability; the example's live layer covers projection, reads, the identity constraint and a cross-tenant refusal against a real Neo4j.

## Common mistakes

Reaching the driver directly; interpolating a label from input; treating the graph as the record of truth; re-projecting without a conflict policy; letting a graph outage fail a request that the relational plane could answer.

## Production checklist

Declare the identity constraint the example declares; keep the vocabulary closed and reviewed; run the projection idempotently; watch the breaker; and keep the relational plane authoritative.
