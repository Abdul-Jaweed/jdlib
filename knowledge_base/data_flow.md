# Data Flow

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

How a value travels from the outside world to a PostgreSQL row, and back. Every
arrow below is a real call in the shipped code, not a conceptual sketch.

## 1. Request context (control-plane reads)

```
HTTP request
  │
  ├─ TenantMiddleware (tenancy/middleware.py)
  │    1. principal_provider(request)      → Principal | None          [401 if None]
  │    2. ResolverChain.resolve(request, principal) → TenantRef | None [404 if None]
  │    3. request_id / correlation_id / trace_id (uuid4 / header / traceparent)
  │    4. ContextFactory.for_principal(...) → TenantContext            [403/409/423/404]
  │         ├─ PrincipalDirectory.is_active          (control-plane read)
  │         ├─ TenantDirectory.get(TenantRef)        (control-plane read)
  │         ├─ EntitlementChecker.can_act            (control-plane read)
  │         └─ ServabilityChecker.assert_servable    (control-plane read)
  │    5. context_scope(context) → app(scope, receive, send)
  │
  ├─ Depends(get_uow) → UnitOfWork(session_factory, context, fence=…)
  │         └─ fence.assert_writable(tenant_id)      (control-plane read, skipped for relocation.manage)
  │
  └─ TenantSession(session, context)
```

All five context gates read the **control plane** (`jd_control`); the tenant
plane is not touched to authorize a request.

## 2. A scoped read

```
select(Invoice).where(Invoice.status == "draft")
  │
  ├─ TenantSession.execute()
  │    └─ SessionEvents.do_orm_execute  (session.py:130)
  │         ├─ reject TextClause / literals / from_statement / non-entity aliases
  │         ├─ trusted mappers = TenantRouted entities in FROM (+ aliases)
  │         └─ with_loader_criteria(Entity, Entity.tenant_id == ctx.tenant_id,
  │                                 include_aliases=True)
  │
  └─ PostgreSQL: SELECT … FROM invoices WHERE status = $1 AND tenant_id = $2
                 (schema/search_path or database chosen by the SessionRouter strategy)
```

The `tenant_id` predicate is added by the library, never by application code.
Row-level security, when enabled for a shared placement, is a *second* net:
`app.tenant_id` is set per transaction by the strategy's `after_begin` listener.

## 3. A scoped write

```
repo.add(Invoice(number="INV-1"))
  │
  ├─ session.add(obj)                          (no SQL yet)
  └─ flush / commit
       └─ SessionEvents.before_flush           (session.py:226)
            ├─ new TenantRouted, tenant_id is None  → stamp ctx.tenant_id
            ├─ new TenantRouted, tenant_id != ctx   → CrossTenantReferenceError
            ├─ dirty tenant_id changed               → CrossTenantReferenceError
            └─ SoftDelete in session.deleted, no privilege → AuthorizationError
```

Bulk writes bypass the ORM flush path, so they are gated separately:
`update_where`/`delete_where` add the predicate and mark the statement
`jdlib_scoped`; anything else raises `UnscopedBulkOperation`.

## 4. Raw SQL

```
session.raw_sql(text("SELECT … WHERE tenant_id = :tid"), {"tid": ctx.tenant_id})
  │
  ├─ compile with the session dialect            → SQL text + bound values
  ├─ pglast.parse_sql                            → AST (exactly one statement)
  ├─ RawSqlValidator.validate_tenant_bound       → per-relation tenant_id = ctx proof
  └─ execute with jdlib_raw_sql=True             → do_orm_execute bulk guard skipped
```

`mode=RawSqlMode.PRIVILEGED` additionally checks the context capability and
records the statement via `RawSqlAuditor`.

## 5. Control-plane writes (lifecycle & authorization)

```
TenantRegistry.create/provision/suspend/…            AccessControl.create_role/bind_role/…
  │                                                    │
  ├─ ControlPlaneSession (jd_control tables)           ├─ ControlPlaneSession
  ├─ platform audit row (control_audit_events)         ├─ AuthzCache.invalidate()
  └─ one commit per operation                          └─ audit row + business row, one commit
```

Tenant-plane effects happen only in two lifecycle operations, both under a
system privilege: `provision` (DDL + migrations + seed hook) and `deprovision`
(architecture B: drop schema/database, or purge tenant-plane rows for a shared
placement via `TenantPlanePurger`).

## 6. Tenant-plane cross-tenant maintenance (`TenantPlanePurger`)

```
TenantRegistry.deprovision(mode=purge|destroy)
  │
  ├─ status → deprovisioning, commit, re-lock, re-read (else TenantOperationInProgress)
  ├─ control-plane access rows deleted in a fixed order (_ACCESS_ROW_DELETION_ORDER)
  │    api_keys → service_accounts → invitations → role_bindings → resource_grants
  │    → role_permissions → roles → memberships
  ├─ strategy.deprovision(record, mode)   (schema/database: DDL drop; shared: no-op)
  ├─ shared placement: TenantPlanePurger.purge
  │    ├─ resolve placement → TenantRecord
  │    ├─ for_system capability "tenant.purge" → TenantSession
  │    └─ delete_where() per TenantRouted table in reverse dependency order
  └─ transition → deleted
```

## 7. Fail-closed defaults, collectivised

| Failure | Where it stops |
|---|---|
| no credentials | middleware → 401 before any DB access |
| unresolvable tenant | middleware → 404 |
| inactive/absent principal, pin mismatch, no entitlement | `ContextFactory` → 403/404 |
| suspended tenant or relocation | factory / fence → 423 |
| no context at all | `TenantSession`/`TenantRepository` → `MissingTenantContext` |
| cross-tenant reference | `before_flush` / scope validation → 409 |
| unprovable raw SQL | validator → `UnscopedRawSql` |
| missing secret for a database handle | strategy → `StrategyCapabilityError` (never a shared fallback) |
| unknown JWKS `kid`, JWKS outage, malformed token | authenticator returns `None` ⇒ 401 |
| RLS not enforced on a table | `verify_rls` → `StrategyCapabilityError` |
| unknown placement strategy | registry/session → `StrategyCapabilityError` |
