# Project Overview

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

## What jdlib is

jdlib is a Python library ("reusable multi-tenant foundation") that supplies the
tenancy plumbing for a SaaS backend built on PostgreSQL and async SQLAlchemy.
It is not an application and not a web framework: it ships the machinery that
every multi-tenant service would otherwise re-implement — request-scoped tenant
identity, three physical isolation strategies behind one data-access API,
fail-closed row scoping, RBAC authorization, authentication adapters, audit,
tenant lifecycle management, and a consumer test kit.

- Package name / version: `jdlib` `0.1.0` (`pyproject.toml`)
- Python: `>=3.12` (uses `StrEnum`, PEP 695 generics — `class TenantRepository[ModelT]`)
- Database: PostgreSQL (uses `citext`, `jsonb`, `inet`, array columns, partial
  and `NULLS NOT DISTINCT` indexes, RLS, advisory locks, transactional DDL)
- Build: hatchling, wheel packages `src/jdlib`
- Runtime shape: async-first (`AsyncSession`/`asyncpg`); synchronous code is
  confined to Alembic invocation and the CLI.

## The problem it solves

Multi-tenant SaaS backends re-solve the same problems repeatedly and usually
fail closed on some of them: deriving tenant identity per request, preventing
tenant A from reading or writing tenant B's rows, providing a common data-access
API while some tenants live in a shared schema and others get their own schema
or database, migrating all of those targets, suspending tenants without deleting
data, deleting tenants completely, and proving to an auditor that privileged
access was justified and recorded. jdlib turns each of those into a small,
tested primitive.

## Capability inventory (each backed by code)

| Capability | Where | Summary |
|---|---|---|
| Tenant context | `context.py`, `tenancy/` | `TenantContext` value object, `contextvars`-based accessors, resolver chain (JWT claim, subdomain, path, header, API key), HMAC-signed envelope for async hops. |
| Request pipeline | `tenancy/middleware.py` | Pure-ASGI middleware: authenticate → resolve tenant → build context → install `contextvar` → call app; maps `JdlibError` to HTTP. |
| One data-access API | `persistence/` | `UnitOfWork`, `TenantSession`, `TenantRepository` work identically for shared / schema / database placements. |
| Fail-closed scoping | `persistence/session.py` | SQLAlchemy event handlers auto-scope reads, stamp/reject writes, reject unscoped bulk DML, validate raw SQL structurally (`pglast`). |
| Isolation strategies | `persistence/strategies/` | `shared` (+ optional RLS), `schema` (per-tenant schema + `search_path`), `database` (per-tenant DB with bounded engine cache). |
| Authorization | `authz/` | Permission catalog, `ResourceTypeRegistry`, `DefaultPDP` with frozen gate precedence, request-scoped `AuthzCache`, `Enforcer`/`requires`/`authorize`. |
| Access administration | `authz/access.py` | Roles, bindings, resource grants, invitations, ownership transfer/team move, with anti-escalation rules. |
| Authentication | `authn/` | OIDC (JWKS cache, token verification, user linking) and API keys (Argon2id), composed by `CompositeAuthenticator`. |
| Tenant lifecycle | `control/registry.py` | Create → provision → migrate → suspend/resume/archive → deprovision (`archive`/`purge`/`destroy`), all under per-tenant advisory locks. |
| Audit | `control/audit.py`, `models/audit.py` | Platform audit sink (control plane, transactional) and tenant `AuditEvent` recorder (tenant transaction), plus privilege audit adapter. |
| Migrations | `migrations/` | Programmatic Alembic with no `alembic.ini`; control-plane chain and tenant-plane chain. |
| Schema lint | `lint.py` | L1–L19 metadata invariants; `jdlib schema lint` fails the build on violations. |
| Integrations | `integrations/` | FastAPI `install`/`require`/`get_uow`/`get_context`; Typer CLI (`tenant`, `db`, `rls`, `schema` groups). |
| Test kit | `testing/` | Isolation assertions + autoloaded pytest fixtures. |

## Who consumes it

An application that already has (or wants) PostgreSQL + SQLAlchemy async models.
The consumer:

1. Subclasses `jdlib.models.base.TenantBase` for its own tenant-plane models and
   mixes in `TenantRouted`, `Timestamped`, `SoftDelete`, `OwnableByOrg`,
   `OwnableByTeam`.
2. Registers resource types and extra permissions.
3. Installs the FastAPI integration (or uses middleware/dependencies directly)
   or drives the CLI for operator tasks.
4. Supplies the deployment-specific collaborators: session factories,
   `SecretProvider` for database-per-tenant DSNs, an operator directory, a
   `SeedHook`.

jdlib never opens a tenant-plane session on the consumer's behalf except through
the documented entry points (`UnitOfWork`, `TenantSession`, strategy
`session()`), and never exposes a raw control-plane session publicly
(`ControlPlaneSession` is framework-internal).

## Design principles visible in the code

- **Ports and adapters.** External concerns enter through `Protocol`s
  (`IsolationStrategy`, `Authenticator`, `TenantResolver`, `PolicyDecisionPoint`,
  `PlatformAudit`, `WriteFence`, `SecretProvider`, `SeedHook`, `ScopeLookup`,
  `ResourceLookup`, `RawSqlAuditor`, `Clock`). One concrete implementation ships
  per port in v1.
- **Fail closed, never fall back.** Missing context, missing placement, missing
  handle, missing RLS policy, missing audit sink, unknown relation, unknown
  permission — all raise. There is no default tenant and no silent fallback to
  the shared target.
- **One creator per authoritative object.** `ContextFactory` is the only
  sanctioned creator of `TenantContext`; `SessionRouter`/strategies are the only
  creators of routed sessions.
- **Placement is data.** Which isolation a tenant uses is a row
  (`tenant_placements.strategy` + `target_handle`), not a code path.
- **Additive, allow-only authorization.** No deny rules; absence of an allow is
  a denial; privileges are explicit capability-bearing contexts, not flags.
- **Enforcement at the persistence boundary.** Scoping is implemented with
  SQLAlchemy session events inside `TenantSession`, so it applies to repositories,
  ad-hoc ORM queries, relationship loads, and bulk helpers alike.

## Status

- Shipped as an installable package layout (`pip install -e ".[dev]"`), but the
  version is a pre-1.0 `0.1.0`; the FastAPI and CLI integrations are optional
  extras.
- Test suite: 568 passing tests (268 unit test functions, 259 integration test
  functions, expanded by parametrization) including a 4-way strategy matrix
  (`shared`, `shared-rls`, `schema`, `database`).
- Known gaps (consolidated in
  [limitations_and_edge_cases.md](limitations_and_edge_cases.md)): relocation is
  a manual procedure with only the *gating* parts implemented, `L5/L10/L18` lint
  rules from `docs/jdlib/02` are not implemented, some design-doc APIs
  (`TenantRegistry.relocate`, `MigrationRunner.upgrade_all`, `jdlib.audit`
  package) do not exist.

## Non-goals (evidenced by absence)

- No DI container, service locator, event bus, or global mutable state beyond
  the fail-closed `contextvars` contextvar (`docs/jdlib/07` §1, confirmed by
  reading `context.py`).
- No cross-request authorization cache in v1 (`authz/cache.py` is explicitly
  request-scoped; `authz/pdp.py` docstring).
- No application HTTP layer of its own: FastAPI support is an adapter
  (`integrations/fastapi.py`), and Starlette/FastAPI are optional extras.
- No automatic tenant relocation service (`control/registry.py` only *gates*
  serving/writes while a relocation row exists; the procedure itself is manual —
  `docs/jdlib/05` §6).

## Where to go next

- New to the code: [architecture.md](architecture.md) then
  [modules/README.md](modules/README.md).
- Building an app on jdlib: [api/public_api.md](api/public_api.md),
  [examples.md](examples.md), [api/fastapi.md](api/fastapi.md).
- Debugging isolation or authorization: [data_flow.md](data_flow.md),
  [execution_flows.md](execution_flows.md),
  [reference/invariants_and_lint.md](reference/invariants_and_lint.md).
- Trusting the docs: [reference/design_docs_map.md](reference/design_docs_map.md).
