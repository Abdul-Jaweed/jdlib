# Module: Tenant-Plane Models (`src/jdlib/models/`)

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

The tenant-plane ORM toolkit: two declarative bases for two planes, the mixins
that give resource models their tenancy shape, four framework models, and the
tenant-side audit recorder. Consumer applications extend this package; they do
not modify it.

## `models/base.py` — bases and mixins

```python
class TenantBase(DeclarativeBase):                    # unqualified schema (search_path decides)
    metadata = MetaData(naming_convention=NAMING_CONVENTION)   # shared with ControlBase

class TenantOwned:      tenant_id: Mapped[uuid.UUID]  # PK part, sort_order=-1 (first in DDL)
class TenantRouted(TenantOwned): pass                 # marker: physical routing + RLS eligible
class Timestamped:      created_at, updated_at        # server_default now(), onupdate now()
class SoftDelete:       deleted_at: Mapped[datetime | None]
class OwnableByOrg:     organization_id: Mapped[uuid.UUID | None]
class OwnableByTeam:    team_id: Mapped[uuid.UUID | None]
def ownership_constraints() -> tuple[Constraint, ...]
```

- `tenant_id` uses `sort_order=-1` so it is the first column in generated DDL —
  required by lint rule L4 ("primary key leads with `tenant_id`").
- `TenantRouted` adds no columns; it is a *classification* marker consumed by
  `tenant_table_map()`, `rls_eligible_tables()`, the lint rules and the
  `with_loader_criteria` scoping. `TenantRouted ⊂ TenantOwned`, and lint L11/L17
  make "tenant-plane model that is not routed" a build failure.
- `ownership_constraints()` returns the pair required by every ownable model:
  - `CHECK (team_id IS NULL OR organization_id IS NOT NULL)` named
    `team_requires_org`;
  - `FOREIGN KEY (tenant_id, organization_id) → organizations(tenant_id, id)`
    named `organization`, `ON DELETE RESTRICT`;
  - `FOREIGN KEY (tenant_id, team_id, organization_id) →
    teams(tenant_id, id, organization_id)` named `team`, `ON DELETE RESTRICT`.

  Model authors spread it into `__table_args__` together with their own indexes
  (canonical example: `tests/support/invoice.py`).

Naming convention (shared with the control plane, defined in
`control/base.py:8`): `ix_%(table_name)s_%(column_0_N_name)s`,
`uq_…`, `ck_%(table_name)s_%(constraint_name)s`, `fk_…`, `pk_%(table_name)s` —
deterministic names so alembic diffs and lint messages are stable.

## `models/org.py` — ownership tree

| Model | Table | Key columns | Constraints |
|---|---|---|---|
| `Organization` | `organizations` | `(tenant_id, id)`, `parent_organization_id`, `name`, `slug`, `Timestamped`, `SoftDelete` | self-FK `(tenant_id, parent_organization_id) → organizations(tenant_id, id)` RESTRICT; partial unique `uq_organizations_tenant_id_slug` where `deleted_at IS NULL`; index on `(tenant_id, parent_organization_id)` |
| `Team` | `teams` | `(tenant_id, id)`, `organization_id` (not null), `name`, `slug`, `Timestamped`, `SoftDelete` | FK `(tenant_id, organization_id)`; **`UNIQUE (tenant_id, id, organization_id)`** (the target of the ownable composite FK — this is what makes I12 checkable); partial unique `uq_teams_tenant_id_organization_id_slug` |

`ScopeResolver._org_chain` walks `parent_organization_id` upwards with a `seen`
set, so a corrupt cycle cannot hang a request — it silently stops.

## `models/settings.py` — `TenantSetting`

`tenant_settings` with a **composite primary key `(tenant_id, key)`**, a JSONB
`value`, `updated_at`, `updated_by`. Natural fit for `ON CONFLICT (tenant_id,
key) DO UPDATE` upserts.

## `models/audit.py` — `AuditEvent`

`audit_events`: `(tenant_id, id)` PK, `actor_type` CHECK over `ActorType`,
`actor_id`, `action`, `target_type`, `target_id`, JSONB `metadata` (column name
`metadata`, attribute `metadata_json`), `ip INET`, `request_id`,
`correlation_id`, `trace_id`, `occurred_at`; two indexes
(`tenant_id+occurred_at`, `tenant_id+target_type+target_id`).

## `models/audit_recorder.py` — `TenantAuditRecorder`

```python
recorder = TenantAuditRecorder(session)          # any object with .add()
event = recorder.record(action="invoice.approved", target_type="invoice",
                        target_id=invoice.id, metadata={...})
```

Reads `current_tenant()` (raising `MissingTenantContext` when absent, which is
asserted by `tests/unit/test_audit_recorder.py`), stamps tenant, actor
(`principal.kind.value` / `principal.id`), request/correlation/trace ids, and
adds the `AuditEvent` to the passed session — i.e. the audit row commits or rolls
back **with the business transaction**. The recorder is synchronous by design:
it only enqueues into the session; the caller flushes/commits.

## How the tenant plane is discovered at runtime

`persistence/models.py::tenant_table_map()` imports the framework model modules
(`jdlib.models.org`, `jdlib.models.settings`, `jdlib.models.audit`) and walks
`TenantRouted.__subclasses__()` recursively, collecting `{table_name: model}` for
every subclass whose `__table__` belongs to `TenantBase.metadata`. Consumers get
their own tables included automatically as long as they subclass
`TenantRouted` from `TenantBase`.

Consumers of that map: `TenantSession` (which tables are tenant tables),
`RawSqlValidator` (which relations are valid + tenant-bound),
`TenantPlanePurger` (delete order) and `rls_eligible_tables()`.

## Rules to follow when adding a model (enforced, not just advisory)

1. Inherit `TenantBase` **and** `TenantRouted` (L17 fires otherwise).
2. Keep `tenant_id` first in the PK and never nullable (L1/L4/L9). In practice:
   inherit `TenantOwned` (L11 fires otherwise).
3. Give every FK to another tenant-scoped table a composite `(tenant_id, …)`
   target (L2 fires on a single-column FK between tenant tables).
4. Scope unique constraints with `tenant_id`, or add the name to
   `GLOBAL_UNIQUE_WHITELIST` and justify it (L12).
5. If the model has `team_id`, use `ownership_constraints()` (L15 fires
   otherwise), and register it in a `ResourceTypeRegistry` if authorization needs
   to resolve its ownership (`ResourceTypeDefinition` requires `organization_id`
   **and** `team_id` on the model when `tenant_routed=True`).
6. Never add a `ON DELETE CASCADE` path from `tenants` (L6) and never an FK
   across planes (L3).
