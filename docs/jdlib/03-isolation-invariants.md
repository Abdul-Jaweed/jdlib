# jdlib — Isolation Invariants

Companion to the design spec (rev 2). These invariants are the security
contract. Each is executable: the test column is mandatory for the phase that
introduces the mechanism. `jdlib.testing` re-exports them so consuming
applications can enforce the same contract over their own resource tables.

## 1. Invariants

### I1 — No tenant context, no tenant data

Statement: any access to a tenant-plane model without an active `TenantContext`
raises `MissingTenantContext`; no default tenant exists.

Enforcement: `TenantSession` constructor requires a context; `with_loader_criteria`
and `before_flush` handlers look up the contextvar and fail closed if absent.
Control-plane access is framework-internal only.

Tests: session construction without context raises; repository call without
context raises; a context cleared mid-request raises on next access; background
task started without an envelope raises.

### I2 — Tenant A context cannot read or write Tenant B data

Statement: every tenant-plane read, write, relationship load, bulk operation,
and raw SQL path is scoped to `ctx.tenant_id`.

Enforcement: automatic read criteria; automatic write stamping; scoped bulk
helpers; `raw_sql` boundary rule.

Tests (per strategy in the matrix): seeded tenants A and B; every read path
returns only A rows; `get(B_id)` returns None; update/delete by B_id affects zero
rows and raises `CrossTenantReferenceError` on references; relationship loads
(`project.resources`, `resource.team`) never cross; bulk update/delete scoped;
raw SQL without tenant boundary rejected.

### I3 — Tenant-scoped rows always carry tenant ownership

Statement: `tenant_id` is NOT NULL, immutable after insert, and present in the
primary key of every tenant-scoped table.

Enforcement: schema (`PK (tenant_id, id)`, `NOT NULL`), `before_flush` stamping,
`immutable` mapper setting on `tenant_id`.

Tests: metadata lint `L1`/`L5`; insert without tenant_id stamped; attempt to
mutate `tenant_id` raises; direct SQL insert lacking `tenant_id` fails (NOT NULL).

### I4 — Cross-tenant references are rejected

Statement: a row in tenant A cannot reference a row in tenant B, at any layer.

Enforcement: composite FKs `(tenant_id, ...)` in all strategies, plus
write-time validation for logical references (`RoleBinding.scope_id`,
`ResourceGrant.resource_id`, ownership columns).

Tests: composite FK violation raises integrity error; framework maps it to
`CrossTenantReferenceError`; logical-reference validation rejects a scope or
resource id that does not resolve inside the active tenant; metadata lint `L2`
and `L3`.

### I5 — Tenant switching requires a new authorized context

Statement: a context and its session are immutable; changing tenant means a new
authenticated, authorized context.

Enforcement: `TenantContext` is frozen; sessions bind one `tenant_id`; no setter.

Tests: mutating any context field raises; creating a session for tenant B while
holding A's context is impossible through public API; two sequential requests
with different resolved tenants get separate sessions.

### I6 — Privileged access is explicit and audited

Statement: cross-tenant reads/writes, operator data access, and system
operations only occur with a factory-issued privileged context and always emit a
`PlatformAuditEvent` (and `AuditEvent` when a tenant is in scope).

Enforcement: private constructor + capability token; a `PrivilegeContext`
descriptor (`kind`, `capability`, `justification`, `actor`, `issued_at`,
`expires_at`) is attached to privileged contexts; every privileged context
creation and use audited; operator tenant-data access is a distinct, time-boxed
capability with a justification field.

Tests: application code cannot construct a privileged context through public
API; operator context creation without capability raises; audit row written for
each privileged operation; audit write failure rolls back the operation.

### I7 — Background work carries tenant identity explicitly

Statement: every asynchronous boundary transfers a signed
`TenantContextEnvelope`; no `contextvar` is assumed to survive; workers reload
statuses and re-evaluate authorization.

Enforcement: envelope verification (HMAC + TTL); status/membership reload;
execution-time authorization; queue payloads include envelope fields.

Tests: worker with no envelope fails closed; tampered signature rejected; expired
envelope rejected; suspended membership between enqueue and execution denies at
execution; envelope carrying an invented permission field has no effect.

### I8 — External state is tenant-scoped

Statement: caches, queues, object storage keys, search/vector indexes never mix
tenants.

Enforcement: documented convention and `scoped_key(namespace, *parts)`
producing `jdlib:v1:{tenant_id}:{namespace}:{part}:...` where every part is
RFC 3986 percent-encoded (so separators can never appear inside a part, and
`("a:b", "c")` cannot collide with `("a", "b:c")`); event envelopes carry tenant
identity; extension points receive the context.

Tests: `scoped_key` output format and collision cases; contract tests in
`jdlib.testing` that consumer cache adapters must pass; events emitted by
framework services include tenant identity.

### I9 — Database-per-tenant still validates tenant context

Statement: physical separation never removes logical checks. `tenant_id` is
stamped, predicates applied, and context validated in every strategy.

Enforcement: uniform code paths; router validates context tenant against the
target handle before opening a session.

Tests: strategy matrix runs the identical suite; a session opened for tenant A's
target with tenant B's context raises; rows are stamped even in `database` mode.

### I10 — Physical isolation never replaces authorization

Statement: even inside the correct tenant, every operation passes the PEP →
PDP flow; no path assumes that being in the right database implies permission.

Enforcement: guards on endpoints and services; `TenantRepository` does not
imply authorization; `authorize()` required before mutations that are not
self-scoped reads.

Tests: a member without `invoice:approve` in the correct tenant is denied; a
service account without a binding is denied; operator without
`platform.tenant.access` is denied even though privileged.

### I11 — Polymorphic references are tenant-validated

Statement: every polymorphic reference (`RoleBinding.scope_id`,
`ResourceGrant.resource_id`, `AuditEvent.target_id`, ownership columns)
validates three things at write time: the referenced object **exists**, it
**belongs to `ctx.tenant_id`**, and it is in an **allowed state**
(not deleted/archived when the reference requires an active target).

Enforcement: `AccessControl` validates through the `ResourceTypeRegistry`
(resource types) and tenant-plane lookups (org/team scopes); violations raise
`CrossTenantReferenceError` or `InvalidReference`. Reads treat dangling
references as invalid and never as allow.

Tests: grant to a resource id from another tenant rejected; binding to a team of
another tenant rejected; binding/grant to a soft-deleted or archived target
rejected; unknown `resource_type` rejected by the registry; dangling reference
created out-of-band is ignored by the PDP and reported by a consistency check.

## 2. Isolation matrix

| Mechanism | Shared | Schema | Database |
|---|---|---|---|
| `tenant_id` predicate (auto) | ✓ | ✓ | ✓ |
| Write stamping + validation | ✓ | ✓ | ✓ |
| Composite PK / composite FK | ✓ | ✓ | ✓ (redundant but uniform) |
| Context ↔ target validation | ✓ | ✓ | ✓ |
| RLS (`FORCE`, `NOBYPASSRLS`, `SET LOCAL`) | optional | n/a | n/a |
| Logical reference validation | ✓ | ✓ | ✓ |
| Envelope signature on async boundaries | ✓ | ✓ | ✓ |

## 3. Failure semantics

| Condition | Result |
|---|---|
| No context | `MissingTenantContext` |
| Unknown tenant | 404 to caller; `platform_audit_events` reason |
| Known tenant, principal not a member | 404 to caller; audit reason |
| Suspended tenant / membership / user | `TenantSuspended` (423) or `TenantAccessDenied`; disclosed only to entitled principals, 404 to strangers |
| Cross-tenant FK in shared/schema mode | DB integrity error mapped to `CrossTenantReferenceError` (409) |
| Cross-tenant reference in database mode | `CrossTenantReferenceError` from write validation |
| RLS policy violation (should be unreachable) | DB error surfaced as `CrossTenantReferenceError`; alert, never swallowed |
| Privileged use without token | `AuthorizationError` |
| RLS `app.tenant_id` unset or empty | zero rows, zero writes (policy predicate evaluates to NULL → no allow) |
| Mandatory audit event cannot be durably recorded | operation fails closed (401/403/503 as appropriate for authn/resolution/privileged paths) |

## 4. Test suite shape

```
tests/isolation/
├── conftest.py            # tenants A/B seeded; fixture parametrizes strategy × rls
├── test_reads.py          # I1, I2
├── test_writes.py         # I3, I4
├── test_relationships.py  # I2 (lazy, eager, joins, subqueries)
├── test_bulk_ops.py       # I2 (update/delete helpers; unsupported API rejects)
├── test_raw_sql.py        # I2, I6
├── test_context.py        # I1, I5
├── test_envelope.py       # I7
├── test_external_keys.py  # I8
├── test_polymorphic.py    # I11 (grants, scopes, dangling references)
├── test_strategy_matrix.py# I9; pool-leakage test (A → checkout → B → checkout)
├── test_pool_eviction.py  # P1.15: never evict a pool with checked-out connections
├── test_rls_app_tables.py # P0.2: consumer TenantOwned table under RLS; unset setting → zero rows/writes
├── test_constraints.py    # NULLS NOT DISTINCT bindings; partial uniques; CHECKs; cross-tenant insert
├── test_authorization.py  # I10 (delegates to the 04 matrix)
└── test_schema_lint.py    # L1–L14
```

Every test in this directory runs unchanged under `{shared, schema, database} ×
{rls on, rls off}` (RLS cases only meaningful for shared). This suite is the
strategy-independence proof.
