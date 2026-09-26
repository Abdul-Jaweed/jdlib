---
guide: tenancy
authority: docs/jdlib/tenancy.md
modules:
  - src/jdlib/tenancy/resolution.py
  - src/jdlib/tenancy/middleware.py
  - src/jdlib/context.py
  - src/jdlib/control/registry.py
  - src/jdlib/persistence/strategies/rls.py
exports:
  - RequestInfo
  - TenantResolver
  - ResolverChain
  - build_chain
  - TenantMiddleware
  - PrincipalProvider
  - TenantContext
  - TenantRegistry
  - RegistryWriteFence
  - install_rls
  - inspect_rls
  - verify_rls
example:
  - examples/enterprise/app/dataplane.py
  - examples/enterprise/app/main.py
test_files:
  - tests/integration/test_registry.py
  - tests/unit/test_context_factory.py
  - tests/unit/test_rls_policies.py
  - tests/integration/test_adversarial_tenant_isolation.py
---
# Tenancy and isolation

> **Design authority:** [`docs/jdlib/tenancy.md`](../tenancy.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

Deciding which tenant a request belongs to, binding that decision to the request, and making the data path incapable of reading another tenant's rows.

## Why it exists

Multi-tenancy is a property of the whole path, not of a query: the tenant is resolved once, carried everywhere, and enforced where the data is -- otherwise one forgotten filter is a cross-tenant read.

## When to use it

For every request that touches tenant data, every background job, and every tool call. If a deployment serves one tenant, tenancy still applies: it is what makes the second tenant a configuration change rather than a rewrite.

## When not to use it

For platform operations that are deliberately tenant-agnostic (a migration, a purge) -- those run under an operator identity with their own audit, not by widening the tenant path.

## How it works

`TenantMiddleware` builds a `RequestInfo` (headers, path, host, query) and asks the `ResolverChain` (`JwtClaimResolver`, `SubdomainResolver`, `PathResolver`, `HeaderResolver`, `ApiKeyResolver`) which tenant it is; the context factory then builds the `TenantContext` and binds it. The data path opens sessions through a strategy that sets the tenant on the connection, and row-level security is what the database enforces when a filter is forgotten.

## Architecture

`tenancy/resolution.py` (who), `tenancy/middleware.py` (when), `context.py` (the value and its scope), `control/registry.py` (tenants as records), `persistence/strategies/rls.py` (the database's own enforcement).

## Example

`examples/enterprise/app/dataplane.py` builds the plane with the shared strategy and installs RLS through the documented operator step; the live tests create two tenants and check that one cannot read the other's rows by any path, over both surfaces.

## Security

The tenant is never a request parameter: it comes from a verified credential or a configured resolver, and a header claiming a tenant is ignored. RLS is the second line: `install_rls` emits policies per eligible table, `inspect_rls`/`verify_rls` check them, and an unbound session reads nothing.

## Reliability

Resolution failures are refusals (no tenant, no data), not defaults. A suspended tenant is refused by the fence rather than by every handler remembering to check.

## Observability

The tenant is an attribute of every span and every audit event, and the request/correlation ids come from the same context, so a trail reads per tenant.

## Audit

Tenant lifecycle events (`tenant.created`, `tenant.activated`, `tenant.migration.succeeded`) are in the platform trail, and the audit writer records the tenant on every row.

## Configuration

Placement strategy per tenant is data (`PlacementStrategy`), not code; the resolvers a deployment uses are configuration (`config.resolvers`).

## Testing

The library covers the registry, the context factory and the RLS emitter; the example's live layer covers two tenants, the two-role lab, and cross-tenant invisibility.

## Common mistakes

Taking the tenant from a parameter or header; resolving it twice; relying on application filters alone; treating a missing tenant as a default tenant; letting a job run without a tenant context.

## Production checklist

Keep RLS installed and verified in CI against a real database; make the runtime role the one the policies constrain; provision tenants through the registry; and give each tenant's data a placement strategy you have tested.
