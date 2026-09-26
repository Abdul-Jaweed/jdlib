---
guide: resource-management
authority: docs/jdlib/resource-management.md
modules:
  - src/jdlib/persistence/repository.py
  - src/jdlib/persistence/models.py
  - src/jdlib/persistence/uow.py
  - src/jdlib/resources/resolver.py
  - src/jdlib/resources/handle.py
  - src/jdlib/resources/connection.py
  - src/jdlib/resources/errors.py
exports:
  - TenantRepository
  - ResourceResolver
  - ResourceHandle
  - ConnectionConfig
  - ResourceHydrationError
example:
  - examples/enterprise/app/repositories/resources.py
  - examples/enterprise/app/services/resources.py
test_files:
  - tests/unit/test_resource_hydration.py
  - tests/unit/test_resource_types.py
  - tests/unit/test_persistence_models.py
---
# Resource management

> **Design authority:** [`docs/jdlib/resource-management.md`](../resource-management.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

The tenant plane's data access: a repository whose sessions are bound to one tenant, a unit of work that commits or rolls back as one, and a resolver that turns a stored reference into a live connection.

## Why it exists

Every tenant-scoped read or write has to open a session the right way. Putting that in one repository makes 'the tenant is bound' a property of the type rather than a habit of the caller.

## When to use it

For all tenant-plane data: application tables, their relationships, and the records a service exposes. Use it from services, not routes, so the transaction boundary is the operation.

## When not to use it

For the control plane (tenants, roles, keys), which is the registry's and the audit writer's business, and for schema work, which is the migration runner's.

## How it works

`TenantRepository` opens a session through the tenant's strategy, sets the tenant on the connection, and exposes the operations the application needs; the unit of work wraps a request's work so a failure rolls the whole thing back. `ResourceResolver` hydrates a `ResourceHandle` into a live connection, with `ConnectionConfig` describing how -- and refuses when the reference is not this tenant's.

## Architecture

`persistence/` holds the repository, models, session handling and strategies; `resources/` holds the reference types and their hydration; services own the transaction boundary; routes own nothing but the call.

## Example

`examples/enterprise/app/repositories/resources.py` and `app/services/resources.py` are the example's tenant plane: a repository over the example's models, and services that create, list, read and archive through it.

## Security

The repository's session is bound, so a query that forgets the tenant still cannot read another tenant's rows; references carry their tenant and `ResourceHydrationError` is raised when one does not belong. The write fence refuses a suspended tenant before the repository is reached.

## Reliability

A unit of work commits once: a partial write is not a state the application can be in. Connections are per-tenant and disposed with the plane, and a failure surfaces as a typed error rather than a leaked session.

## Observability

Repository operations run inside the request's span, so a slow query is attributable to the operation that ran it; the resource's id and kind are the span's attributes.

## Audit

Writes that matter are audited by the operation that performs them, so the trail names the resource, not the table.

## Configuration

The DSN and the placement strategy are configuration; the models are the application's own. Nothing in the repository reads the environment.

## Testing

The library tests the models, the repository and the resolver; the example's live layer drives create/read/list/archive against a real PostgreSQL as the constrained role.

## Common mistakes

Opening a session outside the repository; committing per statement; passing a session across tenants; treating a stored reference as a connection; doing tenant work in a route handler.

## Production checklist

Run the runtime role (not the owner) so the policies constrain you; keep the migration runner separate from serving; size the pool per tenant; check `/readyz` against the database the application actually uses.
