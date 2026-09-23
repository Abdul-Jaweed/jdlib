# Reference: Invariants and Lint Rules

Two rule families describe jdlib's guarantees. `I#` are behavioural invariants
(`docs/jdlib/03-isolation-invariants.md`); `L#` are structural rules
(`docs/jdlib/02-relational-schema.md` §6), split into rules the metadata linter in
`src/jdlib/lint.py` enforces and rules enforced on the write path or at runtime.
Only the linter subset is machine-checkable today — the gap list is at the bottom.

## Behavioural invariants (I1–I13)

| # | Invariant (from `docs/jdlib/03`) | Enforced by (code) | Covered by tests |
|---|---|---|---|
| I1 | No tenant context, no tenant data | `TenantSession.__init__` raises `MissingTenantContext`; `current_tenant()` raises the same; `Enforcer` requires a context. | `tests/unit/test_session.py`, `test_context_factory.py`, `test_guards.py` |
| I2 | Tenant A cannot read or write tenant B data | `do_orm_execute` → `with_loader_criteria`; RLS policies for shared placements; `raw_sql` validator. | `tests/integration/test_session_isolation.py`, `test_rls_db.py`, `tests/unit/test_rawsql.py`, `test_strategy_matrix.py` |
| I3 | Tenant rows always carry tenant ownership, immutably | `before_flush` stamps `tenant_id`; a change to a loaded `tenant_id` raises `CrossTenantReferenceError`. | `tests/unit/test_session.py` |
| I4 | Cross-tenant references are rejected | Same `before_flush` check plus composite FKs; `AccessControl._validate_scope_placement` / `_validate_principal` / `_validate_resource`. | `tests/unit/test_session.py`, `tests/integration/test_access_*.py`, `jdlib.testing.assert_cross_tenant_write_rejected` |
| I5 | Tenant switching requires a new authorized context | Contexts are immutable dataclasses built only by `ContextFactory` (or re-derived by `ContextPropagator`); no mutator exists. | `tests/unit/test_context_values.py`, `test_context_factory.py` |
| I6 | Privileged access is explicit and audited | `for_operator` gates + `PrivilegeAudit.record_privilege` → `privilege.<kind>`; `raw_sql(PRIVILEGED)` capability checks + `RawSqlAuditor`. | `tests/unit/test_context_factory.py`, `test_platform_audit_sinks.py`, `test_rawsql.py` |
| I7 | Background work carries tenant identity explicitly, with no embedded authority | `TenantContextEnvelope` + `ContextPropagator.reconstruct` re-derives everything. | `tests/unit/test_envelope.py`, `test_jobs.py` |
| I8 | External state is tenant-scoped (object keys, cache keys) | Convention + `context.tenant_id`/`slug` availability; the library does not own external stores. | n/a (documentation-level; see limitations) |
| I9 | Database-per-tenant still validates tenant context | `DatabasePerTenantStrategy` is just a session factory; scoping still comes from `TenantSession`. | `tests/integration/test_database_strategy_db.py`, `test_strategy_matrix.py` |
| I10 | Physical isolation never replaces authorization | PDP gates (principal/tenant/membership) run before any placement is consulted. | `tests/integration/test_role_action_matrix.py`, `tests/unit/test_pdp.py` |
| I11 | Polymorphic references are tenant-validated | `AccessControl._validate_scope_placement` / `_validate_resource` / `_validate_principal` (`InvalidReference`, `CrossTenantReferenceError`). | `tests/integration/test_access_grants.py`, `test_access_bindings.py`, `test_scopes.py` |
| I12 | Resource ownership hierarchy is consistent | `ownership_constraints()` CHECK + composite FK to `teams(tenant_id, id, organization_id)`; `move_team` cascades. | `tests/integration/test_access_roles.py`, `tests/support/invoice.py` |
| I13 | Raw SQL fails closed | `RawSqlValidator` (pglast proof) + `UnscopedRawSql` for `TextClause`/literals/table-level aliases. | `tests/unit/test_rawsql.py` |

## Structural rules (L1–L19) and where they are enforced

Legend: **lint** = implemented in `lint_metadata()` (`src/jdlib/lint.py`);
**write** = enforced by the write path (a service raising a typed error);
**runtime** = enforced by the ORM/session machinery; **doc** = stated in the docs
but not implemented in shipped code.

| # | Rule (condensed) | Status | Implementation detail |
|---|---|---|---|
| L1 | Tenant-scoped table PK includes `tenant_id` | lint | `LintIssue("L1", …)`. |
| L2 | FK between tenant-scoped tables includes `tenant_id` | lint | Fires when `tenant_id` is not in `constraint.column_keys`. |
| L3 | No FK between control and tenant planes | lint | `table.schema != target.schema`. |
| L4 | PK leads with `tenant_id` | lint | `pk_names[0] != "tenant_id"`. |
| L5 | `tenant_id` NOT NULL; only `platform_audit_events` (and `tenants.parent_tenant_id`) may be nullable | lint (as **L9**) | The docs list L5 and L9 as the same rule checked twice; the linter only emits **L9** (`table.columns["tenant_id"].nullable`) and exempts `platform_audit_events` via `TENANT_ID_REFERENCE_ONLY`. |
| L6 | No `ON DELETE CASCADE` path from `tenants` | lint | `_cascade_reachable()` walks CASCADE edges and reports each reachable table. |
| L7 | `permission_code` values validated against the catalog | write | `PermissionCatalog.validate` (`UnknownPermission`); role writes validate every code. |
| L8 | `tenant_id` immutable after insert | runtime | `before_flush` dirty check → `CrossTenantReferenceError`. |
| L9 | `tenant_id` NOT NULL on tenant-scoped models | lint | See L5. |
| L10 | Every tenant-scoped FK column set contains `tenant_id` (per-constraint) | lint (as **L2**) | Same implementation as L2; no separate L10 issue is emitted. |
| L11 | Tenant-plane models built on `TenantOwned` | lint | Fire only for unschematised (tenant-plane) tables whose model is not a `TenantOwned` subclass. |
| L12 | Uniques on tenant-scoped models include `tenant_id` | lint | Covers `UniqueConstraint` **and** unique indexes; whitelisted globals: `api_keys.uq_api_keys_key_prefix`, `invitations.uq_invitations_token_id`, `tenants.uq_tenants_slug` (`GLOBAL_UNIQUE_WHITELIST`). |
| L13 | With RLS enabled, every tenant-routed table is RLS-eligible | lint | Only when `rls_enabled=True`; also enforced at deployment time by `verify_rls` (`StrategyCapabilityError`). |
| L14 | Polymorphic references validated (existence, tenant, state) | write | `AccessControl` validators (see I11). |
| L15 | `team_id` rows declare the `(team_id ⇒ organization_id)` CHECK and the composite FK to `teams` | lint | Fires when either is missing. |
| L16 | Role binding validates permission ↔ scope; grant validates permission ↔ resource namespace | write | `RoleScopeMismatch` / `InvalidResourcePermission`. |
| L17 | Every tenant-plane model is `TenantRouted` | lint | Fire for schemaless tables whose model is not `TenantRouted`. |
| L18 | Application-plane models registered in `ResourceTypeRegistry` are `TenantRouted` | doc | Not checked by the linter; `ResourceTypeDefinition.__post_init__` validates the definition's own shape (`tenant_routed ⇒ tenant_owned`, `organization_id`/`team_id` presence). |
| L19 | No control-plane model inherits `TenantRouted` | lint | Fire for `table.schema == "jd_control"` + `TenantRouted`. |

### Lint implementation notes

- `lint_metadata(controls: list[MetaData], rls_enabled: bool = False) ->
  list[LintIssue]`; `LintIssue(rule, table, message)` is a frozen dataclass, so
  issues are trivially assertable (`tests/unit/test_lint.py`).
- `assert_clean(...)` raises `SchemaLintError` with `"L<n> <table>: <message>"`
  strings — that is what `jdlib schema lint` reports to stderr with exit 1.
- Tables named `alembic_version*` are skipped.
- Model discovery is two-pronged: `table.info["jdlib_model"]` first, then a walk of
  `ControlBase`/`TenantBase`/`TenantOwned` subclasses (`_model_tables`). A model
  that is never imported is invisible to the linter — `jdlib schema lint` imports
  the framework model modules first for exactly this reason, and consumer projects
  must import theirs.
- CASCADE detection uses `tenants` as the root by name, in every metadata passed
  in, so a consumer metadata that references a `tenants` table is checked too.

## Machine-checked vs documented

| Status | Rules |
|---|---|
| Emitted by the linter today | L1, L2, L3, L4, L6, L9, L11, L12, L13 (with `--rls`), L15, L17, L19 |
| Enforced on the write path (typed errors, no lint) | L7, L8, L14, L16 |
| Documented but not implemented | L5/L10 (folded into L9/L2), L18 (resource-type registration shape only) |
| Covered by runtime verification instead of lint | L13 (deployment: `verify_rls`), plus the RLS policy emission itself |

If you extend the model set, run `jdlib schema lint --rls` (or
`lint_metadata([...], rls_enabled=True)`) in CI: it is the cheapest way to catch a
composite-PK or tenant-scoping mistake before it becomes a data leak.
