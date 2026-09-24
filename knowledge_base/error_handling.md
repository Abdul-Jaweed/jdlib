# Error Handling

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

All failures are typed: the library raises only subclasses of
`jdlib.errors.JdlibError`, and only two adapter modules know about HTTP. Raise
sites below were extracted by scanning `src/jdlib` for each class name (counts are
per-file occurrences including imports/docstrings, so treat them as an
indication of where a class is *decided on*, not an exact call count).

## Hierarchy

```
JdlibError
├── MissingTenantContext
├── TenantNotFound
├── TenantAccessDenied
├── TenantSuspended
├── TenantNotWritable
├── CrossTenantReferenceError(reference, expected_tenant, actual_tenant)
├── UnscopedBulkOperation
├── UnscopedRawSql
├── InvalidReference
├── InvalidResourcePermission
├── UnknownResourceType
├── UnknownPermission
├── RoleScopeMismatch
├── StrategyCapabilityError
├── PoolCapacityError
├── TenantOperationInProgress
├── RelocationPhaseError          ← defined, never raised (no relocation service)
├── SchemaLintError(issues: list[str])   .issues carries the per-rule messages
├── ProvisioningError
├── MigrationError                ← defined, never raised
├── AuthenticationError
│   ├── InvalidToken
│   ├── ExpiredToken
│   └── UnknownPrincipal
└── AuthorizationError
    ├── PermissionDenied
    └── RoleEscalationBlocked
```

`JdlibError` itself is exported from `jdlib/__init__.py`; `errors.__all__` lists
the 27 subclasses (and deliberately not the base class).

## Where each error comes from

| Error | Decided in | Typical trigger |
|---|---|---|
| `MissingTenantContext` | `persistence/session.py` (4), `authz/pdp.py`, `context.py`, `control/audit.py` | building a `TenantSession`/`UnitOfWork` without a context; evaluating a decision without a session; reading `current_tenant()` outside a context. |
| `TenantNotFound` | `control/registry.py`, `tenancy/middleware.py`, `context.py`, `tenancy/jobs.py` | unknown slug/id from a resolver, factory, registry lookup or job envelope. |
| `TenantAccessDenied` | `context.py`, `tenancy/jobs.py`, `tenancy/middleware.py` | inactive principal, service-account pin mismatch, no entitlement. Also the reason an unentitled principal sees 404 rather than 423. |
| `TenantSuspended` | `control/registry.py`, `tenancy/middleware.py` | suspended tenant or a relocation in flight, seen through the factory/middleware/servability check. |
| `TenantNotWritable` | `control/registry.py`, `integrations/fastapi.py`, `tenancy/middleware.py` | `RegistryWriteFence.assert_writable` denied (suspended, archiving, deprovisioning, mid-relocation). |
| `CrossTenantReferenceError` | `authz/access.py` (5), `persistence/session.py` (3), `testing/assertions.py` | stamping/altering `tenant_id`, cross-tenant scope or principal reference, the isolation assertion. |
| `UnscopedBulkOperation` | `persistence/session.py` | ORM-enabled INSERT/UPDATE/DELETE against a tenant table without `jdlib_scoped`/`jdlib_raw_sql`. |
| `UnscopedRawSql` | `persistence/rawsql.py` (24), `persistence/session.py` (7) | the raw-SQL validator's rejects; `TextClause` through `execute`; table-level aliases; `from_statement`; literals. |
| `InvalidReference` | `authz/access.py` (24), `tenancy/middleware.py` | polymorphic scope/resource/role reference that is missing, soft-deleted or unusable. |
| `InvalidResourcePermission` | `authz/access.py`, `authz/resource_types.py` | permission code namespace ≠ resource type namespace. |
| `UnknownResourceType` | `authz/resource_types.py` | resource type not registered. |
| `UnknownPermission` | `authz/permissions.py` | permission code not in the catalog. |
| `RoleScopeMismatch` | `authz/access.py` (4) | binding a role at a scope its permissions do not allow (rule L16). |
| `AuthenticationError` | `tenancy/middleware.py`, `authn/oidc.py` | no credentials presented, or an authn failure surfaced as 401. |
| `InvalidToken` | `authn/oidc.py` (9), `context.py` (5), `authn/apikey.py` | malformed API key, JWT verification failure, unparsable/forged envelope. |
| `ExpiredToken` | `authn/oidc.py`, `context.py` | `exp` in the past (JWT or envelope), with leeway applied. |
| `UnknownPrincipal` | `context.py`, `tenancy/jobs.py` | principal referenced by a job envelope no longer active. |
| `AuthorizationError` | `authz/access.py` (12), `context.py` (9), `persistence/session.py` (6) | guard failures, privileged-context gates, hard delete without privilege, `tenant_id` assignment via `update_where`, missing `scope_lookup`. |
| `PermissionDenied` | `authz/guards.py` | `Enforcer.require` denial (`"<permission>: <reason>"`). |
| `RoleEscalationBlocked` | `authz/access.py` | `_require_subset` / owner-role rule. |
| `StrategyCapabilityError` | `persistence/strategies/database.py` (7), `rls.py` (6), `schema.py` (6), `control/registry.py` (4), `shared.py` (3) | schema/handle validation, missing engine or secret, unknown placement, RLS emission/verification failure, invalid deprovision mode. |
| `PoolCapacityError` | `persistence/strategies/database.py` | `max_targets` reached with no idle engine to evict. |
| `TenantOperationInProgress` | `control/registry.py` | illegal status transition (`_require_transition`), `provision` called on a tenant that is not `provisioning`, or a `deprovision` whose `deprovisioning` state was superseded. |
| `SchemaLintError` | `lint.py` | `lint_metadata` found rule violations; `SchemaLintError.issues` has them. |
| `ProvisioningError` | `control/registry.py` (14), `migrations/runner.py` (3) | slug/handle validation, duplicate placement, missing placement/migration state, version mismatch after migration, missing purger for a shared deprovision. |

## HTTP mapping (only adapters know it)

`tenancy/middleware.py::http_status_for` — first match wins:

| Error | Status |
|---|---|
| `AuthenticationError` | 401 |
| `AuthorizationError` | 403 |
| `TenantNotFound` | 404 |
| `TenantAccessDenied` | 404 |
| `TenantSuspended` | 423 |
| `TenantNotWritable` | 423 |
| `CrossTenantReferenceError` | 409 |
| `InvalidReference` | 409 |
| any other `JdlibError` | 500 |

Non-`JdlibError` exceptions are never converted; they keep FastAPI's (or your
server's) default behaviour. `integrations/fastapi.py` reuses the same mapping
through its `JdlibError` exception handler.

## Cross-cutting rules

1. **No driver exceptions escape.** Driver/ORM errors are mapped at the boundary
   (e.g. `KeyError` from a `SecretProvider` ⇒ `StrategyCapabilityError`; Argon2
   verification failure ⇒ `False` from `verify_api_key_secret`; `IntegrityError`
   in a linking race ⇒ retry-read). The CLI additionally catches
   `SQLAlchemyError` to print `error: …` and exit 1.
2. **`ValueError`/`TypeError` are reserved for programmer error**, not policy:
   `ScopeRef(ORG, None)` (`ValueError`), `TenantRepository.soft_delete` on a model
   without `deleted_at` (`TypeError`), `UnknownResourceType`-style registry misses
   use typed errors instead.
3. **Messages name the sanctioned alternative**: "use `raw_sql` for text
   statements", "aliases of tenant tables must be entity-derived; use
   `aliased(Entity)`", "use `update_where`/`delete_where`". Error text is treated
   as developer documentation.
4. **Never include secret material.** Auth failures are audited with the exception
   class name (`InvalidToken`, `invalid_api_key`), never the token; `SecretStr`
   protects DSNs and signing keys from `repr`.
5. **Two unused classes are intentional placeholders.** `RelocationPhaseError`
   and `MigrationError` have no raise site: relocation is modelled in the schema
   (`tenant_relocations` with a phase check constraint and a partial unique index)
   and the registry *gates* serving on critical relocation phases, but no
   relocation service exists; migrations report failures as
   `ProvisioningError`/`StrategyCapabilityError`. Do not assume catching them will
   ever fire — see
   [limitations_and_edge_cases.md](limitations_and_edge_cases.md).
6. **Retryability.** `PoolCapacityError` is transient (retry after a session
   closes); `TenantOperationInProgress`/`TenantNotWritable` are transient
   (lifecycle operation in flight); `Unscoped*`/`CrossTenantReferenceError`/
   `RoleEscalationBlocked` are **not** retryable — they indicate a code or policy
   bug and should fail the request.
