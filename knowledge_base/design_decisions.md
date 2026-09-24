# Design Decisions

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

Each entry states the decision, the alternative it replaces, and where the code
or docs justify it. Sources: the implementation itself, the repository
`README.md`, and `docs/jdlib/03-isolation-invariants.md`,
`04-authorization-model.md`, `05-tenant-lifecycle.md`, `07-implementation-design.md`.

## D1. Enforce tenancy at the session layer, not the strategy layer

*Decision*: one `TenantSession` API for every placement; the strategy only
supplies a connection whose schema/database/search_path is already correct.

*Alternative*: a `SharedSession`/`SchemaSession`/`DatabaseSession` hierarchy where
each class knows its own scoping rules.

*Why*: scoping rules are the invariant; placement is deployment detail. Three
session classes would mean three chances to forget `with_loader_criteria`, and
application code would have to know which one it got. With strategy-specific
scoping, the strategy matrix tests would need three different behavioural suites
instead of one parametrized suite
(`tests/integration/test_strategy_matrix.py`).

## D2. Use SQLAlchemy events for enforcement, not a query builder

*Decision*: `do_orm_execute` + `before_flush` on the session
(`persistence/session.py:130-253`).

*Alternative*: a jdlib-owned query wrapper ("always call `repo.scoped_select()`").

*Why*: a wrapper only covers statements built through it — lazy relationship
loads, `selectinload`, secondary-table access and ORM-enabled bulk DML all bypass
it. Events see every ORM statement, including loader-generated ones, and
`with_loader_criteria(..., include_aliases=True)` propagates the predicate into
joins and eager loads automatically. The cost is that the handler must recognise
statements it cannot reason about (table-level aliases, `from_statement`,
literals) and reject them — hence the `UnscopedRawSql`/`UnscopedBulkOperation`
errors.

## D3. Fail closed, always

*Decision*: every ambiguous condition denies: no credentials ⇒ 401, unresolvable
tenant ⇒ 404, inactive principal/membership ⇒ deny, JWKS outage ⇒ deny, missing
tenant-DB secret ⇒ `StrategyCapabilityError`, unknown placement strategy ⇒ error,
RLS not verifiable ⇒ error, missing `scope_lookup` ⇒ `AuthorizationError`
(instead of skipping validation).

*Alternative*: opportunistic fallbacks ("if the secret is missing, use the shared
target"; "if the resolver fails, use the header").

*Why*: a fallback in a tenancy library is a cross-tenant data leak waiting for its
trigger. Absence of an allow is a denial by construction (additive model), and the
tests assert each denial path explicitly (e.g.
`test_database_strategy.py::test_missing_secret_fails_closed`).

## D4. Placement is data

*Decision*: `tenant_placements(strategy, target_handle, region, desired_version)`
plus a registry of `IsolationStrategy` objects; the session factory is chosen per
tenant from that row.

*Alternative*: separate tenant tables per placement, or a hard-coded choice at
deploy time.

*Why*: it makes placement observable, auditable and migratable (a tenant can move
from shared to schema-per-tenant as a data change), and it keeps the request path
free of deployment knowledge — `SessionRouter` is the only place that consults it.

## D5. Architecture B: purge, don't pretend to drop, in shared placements

Verified from code and `docs/jdlib/05` §5 (see
[limitations_and_edge_cases.md](limitations_and_edge_cases.md)): a shared
`SharedSchemaStrategy.deprovision()` is a no-op for **every** mode, and
`TenantRegistry.deprovision` compensates with
`TenantPlanePurger.purge(...)` — a system-privileged, RLS-bound,
`delete_where`-driven row deletion in reverse dependency order.

*Why*: in a shared schema there is no per-tenant object to drop; claiming
"purged" without deleting the rows would be a false erasure guarantee. The purger
makes the cost and the mechanism explicit, and it runs under
`tenant.purge` capability so it is audited.

*Consequence*: `purge` and `destroy` are behaviourally identical at the strategy
layer; the distinction is preserved in the enum for policy/marketing reasons but
is not implemented differently (a real difference would need, e.g., S3 object
deletion, which is out of scope).

## D6. Two declarative bases, two Alembic trees

*Decision*: `ControlBase` (`jd_control` schema, control chain) and `TenantBase`
(one schema per tenant, tenant chain), with the naming convention and schema
constants defined in `control/base.py` and imported by `models/base.py`.

*Alternative*: one `Base` and one migration chain with schema selection by
runtime parameter.

*Why*: the control plane is a single, cluster-wide schema that must never be
per-tenant; the tenant plane must be identical across tenants so one migration
chain can fan out. Two bases make that structural, and `include_schemas=True`
(the control `env.py`) plus `version_table_schema` (both `env.py`s) keep
`alembic_version` in the right place. The inward import
(`models/base.py` → `control/base.py`) is the price for a single naming
convention.

## D7. Baselines are metadata-driven (`create_all`), not explicit DDL

*Decision*: `0001_*_baseline` revisions call
`Base.metadata.create_all(bind, checkfirst=True)`.

*Alternative*: hand-written `op.create_table(...)` for all 20 tables.

*Why*: for a library whose model set *is* the product, hand-written DDL drifts
from the models the moment a column changes; `create_all` cannot drift. The cost
is real and documented: any schema evolution after `0001` still needs a manual
revision (there are none in the repo), and the baseline is only "correct" for
fresh installs.

## D8. Privilege is an explicit, audited, non-serializable capability

*Decision*: `PrivilegeContext(kind, capability, justification, actor,
issued_at, expires_at)`; issued only through `ContextFactory.for_operator`
(operator kind + justification + TTL ≤ max + operator authorizer),
`for_system`/`for_test` (require the in-process `PRIVILEGE_ISSUER` sentinel), and
always audited via `PrivilegeAudit.record_privilege` → `privilege.<kind>`.

*Alternative*: "admin" roles, a debug flag, a `SUPERUSER` tenant context.

*Why*: privilege is the one thing that can step outside tenant scoping
(hard deletes, privileged raw SQL, the write-fence bypass for `relocation.manage`),
so it is modelled as a capability with a justification and an expiry, never as an
identity attribute. `ContextPropagator` never re-creates privilege from an
envelope, and there is no "silently escalate" path: the caller must name the
capability, and `PRIVILEGE_ISSUER` (a module-private sentinel object) keeps
`for_system`/`for_test` out of reach of application code that merely imports
`ContextFactory`.

## D9. Envelopes carry no authority

*Decision*: `TenantContextEnvelope` = tenant id, principal type/id, request ids,
`issued_at` + HMAC + TTL. Reconstruction re-reads the control plane every time.

*Alternative*: serialize permissions/scopes into the job payload for speed.

*Why*: (invariant I7 in `docs/jdlib/03`, plus
`tests/unit/test_envelope.py::test_token_does_not_contain_permissions_or_scopes`)
a queued job may run minutes or days after a revocation; re-derivation is the only
way to make revocation immediate. The token is a *hint of who and where*, not a
grant.

## D10. Authorization is additive, allow-only, with ACL-style grants

*Decision*: roles → permissions (catalog-validated) → bindings at scope types
(tenant/org/team) → scope chain matching; plus `ResourceGrant` rows for
per-resource sharing. No deny rules; empty/no match = deny; API-key `scopes`
intersect and never widen.

*Alternative*: deny rules, wildcard permissions, hierarchical role inheritance.

*Why*: `docs/jdlib/04` §2 fixes the precedence order
(principal → tenant status → membership → bindings → grants → key scopes) so that
"why is this allowed?" has one answer and `Decision.matched` can explain it. A
deny rule would make every allow conditional on every other rule; the additive
model makes the allow set computable and auditable. Denials that must exist
(last-owner removal, role escalation, system-role immutability) are enforced as
guards in `AccessControl`, where they belong.

## D11. Administrative authority is tenant-scope only

*Decision*: `AccessControl.actor_permissions()` counts **tenant-scope** bindings
only; org/team-scoped authority does not administer roles, bindings or grants.

*Alternative*: let an org-level `role:manage` manage org-scoped bindings.

*Why*: it removes a whole class of escalating recursion ("who may grant
`team:manage` at team scope?") at the cost of some flexibility. The role's own
`allowed_scopes` still governs where it may be *bound* (rule L16 /
`RoleScopeMismatch`), which is a separate question from who may bind it.

## D12. Request-scoped authorization cache with invalidate-before-write

*Decision*: `AuthzCache` is created per request (per PDP), `invalidate()` is
called before every mutation and is one-way for the life of the request.

*Alternative*: a shared, TTL-based authz cache.

*Why*: v1 optimizes for "never stale" over "never slow": a shared cache would
need cross-process invalidation (pg NOTIFY, a bus) that the library deliberately
does not own, and a TTL creates a window where a revoked permission still allows.
The public API therefore expects the consumer to build a fresh PDP per evaluation
(the README's `RequestScopedEnforcer` does exactly that).

## D13. Raw SQL is proven, not pattern-matched

*Decision*: `raw_sql` compiles the statement with the session dialect, parses it
with `pglast`, and proves structural properties (single statement, no CTE, no
subquery, no schema qualification, unknown relations rejected, AND-only
conjuncts, per-relation `tenant_id = <context tenant>` with the *bound value*
compared to `context.tenant_id`, no `tenant_id` assignments, INSERT must name
`tenant_id` explicitly).

*Alternative*: string matching for `tenant_id`, or trusting the caller /
code review.

*Why*: string matching is bypassable (`/*tenant_id*/`, a CTE alias named
`tenant_id`) and gives false confidence. A parse with bound-value comparison
cannot be fooled by formatting, and the rejects are enumerated in one function
where they can be tested rule by rule (`tests/unit/test_rawsql.py`). The
`PRIVILEGED` mode still keeps the structural rejects — privilege waives the
predicate, not the sanity.

## D14. Typed errors in the core, HTTP mapping in one adapter

*Decision*: everything raises `JdlibError` subclasses; only
`tenancy/middleware.py` and `integrations/fastapi.py` know statuses
(`http_status_for`, a frozen first-match-wins table).

*Alternative*: an HTTP-aware core with `status_code` attributes.

*Why*: the library is used from CLI, background jobs and Faust-style consumers
where HTTP statuses are meaningless; and the ordering of the mapping is a
security-relevant decision (unentitled principal on a suspended tenant must be 404,
not 423) that deserves to live next to a test.

## D15. Standard library over helper packages for security primitives

*Decision*: envelopes = `hmac` + `hashlib` + `base64` + `json`; ids = `uuid` with
a hand-rolled `uuid7()`; context propagation = `contextvars`; time = an injected
`Clock`.

*Alternative*: `itsdangerous`, `python-ulid`/`uuid6`, `structlog`-style context,
`freezegun`.

*Why*: fewer transitive dependencies in the security-critical path, deterministic
tests without monkeypatching (`FrozenClock`), and no third-party API surface to
audit. The cost is that jdlib owns its own token format (no JWE/JWS interop) and
its `uuid7()` is a prefix-scheme, not a monotonic RFC 9562 implementation (see
[limitations_and_edge_cases.md](limitations_and_edge_cases.md)).

## D16. Idempotent, resumable lifecycle operations

*Decision*: `create` is idempotent for the same slug+placement; `provision` returns
immediately for an already-active tenant; `deprovision` re-validates the state
machine on entry (`_require_transition`) and the purge step is re-runnable.

*Why*: lifecycle operations are driven by operators, CI and retries; a crash
between "DDL applied" and "status committed" must be repairable by re-running the
command. The design makes that state visible instead of hiding it: a failed
provision leaves `TenantMigrationState.status = 'failed'` with `last_error` and the
tenant still in `provisioning` (so `provision` can be retried), while a failed
`migrate` on an `active` tenant suspends it with `suspended_reason =
'migration_failed'` so it stops serving. The advisory lock
(`pg_advisory_xact_lock(hashtext('jdlib.tenant_write'))`) makes concurrent
lifecycle calls serialize instead of racing, and `deprovision` re-checks
`deprovisioning` after its own commit.

## D17. Thin adapters; optional dependencies stay out of the core

*Decision*: `integrations/*` are the only modules importing FastAPI/Typer, and
`jdlib/__init__.py` exports 13 names with no adapter imports.

*Why*: installing the library must not force a web framework on a job worker, and
the public surface should be small enough to test with an equality assertion
(`test_all_is_exactly_the_public_surface`).

## D18. Tests are the specification

*Decision*: contract tests for each invariant
(`assert_tenant_isolated`, `assert_cross_tenant_write_rejected`), a strategy
matrix that runs the same behavioural suite over four placements, and a
role × action permission matrix.

*Why*: the library's value proposition is "you cannot leak across tenants", which
is only credible as an executable claim. The matrices exist so that adding a
placement or a permission does not silently reduce coverage.
