---
page: architecture
sources:
  - src/jdlib/context.py
  - src/jdlib/tenancy
  - src/jdlib/security
  - src/jdlib/persistence
  - src/jdlib/control
  - docs/jdlib/02-relational-schema.md
---
# Architecture

JDLib is a multi-tenant library, not a framework: it owns the boundaries a request crosses and
leaves the application's shape alone. The layering below is the order in which a request is
processed, and each layer can refuse.

## Layers

| Layer | Owns | Refuses with |
|---|---|---|
| Context (`jdlib.context`, `jdlib.tenancy`) | Who is calling, for which tenant, with what privilege | `MissingTenantContext`, `TenantNotFound`, `UnknownPrincipal`, `TenantSuspended` |
| Authentication (`jdlib.security.authn`) | Whether an identity is real and current | `AuthenticationUnavailable`, `ExpiredToken`, `InvalidToken` |
| Authorization (`jdlib.security.authz`) | Whether this identity may do this, here | `AuthorizationError` (403), degraded decision (503) |
| Persistence (`jdlib.persistence`) | The tenant plane: schema routing, RLS, the raw-SQL guard | `TenantIsolationError`, raw-SQL refusals |
| Control plane (`jdlib.control`) | Tenants, placements, migrations, lifecycle | `TenantNotFound`, provisioning refusals |
| Capabilities (§2–§12) | Credentials, cache, hydration, connectors, query, storage, jobs | see each page |

## The two planes

The **control plane** holds the library's own tables in one schema: tenants, placements, users,
identity links, memberships, roles, audit. The **tenant plane** is one schema per tenant, reached
only through `TenantRepository` and protected by row-level security bound to the application role.

That separation is why the query compiler refuses tenant-plane tables rather than filtering them:
one path to tenant rows is a boundary, two paths are a policy someone will get wrong.

## The successor capabilities

§2 credentials → §3 cache → §4 hydration → §5 delegation → §6/§7 connectors → §8 query → §9
storage → §10 jobs → §11 observability → §12 audit. Each arrow is a dependency, not a preference:
hydration resolves credentials and caches targets; the connector framework precedes the connector;
a job envelope revalidates the tenancy chain.

Capability pages, each with its own evidence: [`capabilities/`](capabilities/README.md).

## Where the boundaries are asserted

Every refusal above has a named test, and the adversarial suite
(`tests/unit/security/test_adversarial_successor.py`) attacks them by name rather than by API.
`docs/jdlib/production-readiness.md` carries the numbers and the commands that produced them.
