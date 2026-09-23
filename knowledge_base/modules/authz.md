# Module: Authorization (`src/jdlib/authz/`)

Two halves that are easy to confuse:

- **Decisioning** — `permissions.py`, `resource_types.py`, `scopes.py`,
  `reader.py`, `pdp.py`, `cache.py`, `guards.py`: *may this principal do this?*
- **Administration** — `access.py` (`AccessControl`): *changing roles, bindings,
  grants, invitations and ownership*, with anti-escalation guards.

The model is additive and allow-only: no deny rules exist, absence of an allow is
a denial, and every mutation authority check routes through the same
`actor_permissions()` helper.

## `permissions.py` — the catalog

`Permission(code, namespace, allowed_scopes: frozenset[ScopeType], description)`.
`PermissionCatalog.register` rejects duplicates; `validate(code)` raises
`UnknownPermission`; `with_builtins()` loads the 13 builtins:

| Code | Namespace | Allowed binding scopes |
|---|---|---|
| `tenant:read`, `tenant:manage` | `tenant` | tenant |
| `member:invite`, `member:manage` | `member` | tenant |
| `role:manage` | `role` | tenant |
| `audit:read` | `audit` | tenant |
| `org:manage` | `org` | tenant, org |
| `team:manage` | `team` | tenant, org, team |
| `resource:read`, `resource:create`, `resource:update`, `resource:delete`, `resource:share` | `resource` | tenant, org, team |

`allowed_scopes` governs **binding scope compatibility only** (rule L16): a role
containing `tenant:manage` can be bound at tenant scope only
(`RoleScopeMismatch` otherwise). Resource-level authority is a separate mechanism
(`ResourceGrant`, one exact resource).

## `resource_types.py` — resource registry

```python
ResourceTypeDefinition(resource_type, model, tenant_owned, tenant_routed, permission_namespace)
```

`__post_init__` validates: non-empty `resource_type` and namespace;
`tenant_routed` ⇒ `tenant_owned`; `tenant_routed` ⇒ the model exposes both
`organization_id` and `team_id` (`ScopeResolver` reads both). `ResourceTypeRegistry`
rejects duplicates, raises `UnknownResourceType` on lookup misses, and
`validate_permission(resource_type, permission_code, catalog)` raises
`InvalidResourcePermission` when the code's namespace ≠ the definition's
namespace.

The registry is the single source of truth for "what is a resource", used by
`AccessControl.grant_resource` / `transfer_resource` / `move_team` and
`ScopeResolver`.

## `scopes.py` — targets and chains

```python
ScopeRef(type: ScopeType, id: UUID | None)
ResourceRef(resource_type: str, resource_id: UUID)
Target = ScopeRef | ResourceRef
```

`ScopeResolver(registry).chain(session: TenantSession, target)` produces the
ancestor chain used to match bindings:

| Target | Chain |
|---|---|
| `ScopeRef(TENANT, None)` | `(tenant,)` |
| `ScopeRef(ORG, id)` | `(tenant, org, parent org, …, root)` — walked via `parent_organization_id` with a cycle guard |
| `ScopeRef(TEAM, id)` | `(tenant, …org chain of the team's organization…, team)`; a missing team degrades to `(tenant,)` (deny by default) |
| `ResourceRef(type, id)` | `(tenant[, …org chain…][, team])` read from the model's `organization_id`/`team_id`; a missing row degrades to `(tenant,)` |
| `ScopeRef(ORG|TEAM, None)` | `ValueError` — a scope target without an id is a programming error |

The resolver runs **inside the tenant session**, so tenant scoping applies to the
lookup itself.

## `reader.py` — how state is read

`Binding(role_id, scope_type, scope_id)` namedtuple and the `AccessReader`
protocol (`tenant_status_of`, `principal_active`, `service_account_active`,
`membership_active`, `bindings_for`, `permissions_by_role`, `grants_for`).

`ControlAccessReader(session_factory)` reads the control plane:

- `principal_key(principal)`: USER with `user_id` set → `user_id`; otherwise
  `id`. Every principal-owned lookup (bindings, grants, activity, membership) is
  keyed through this one helper.
- `principal_active` denies `PLATFORM_OPERATOR` **without touching the database**
  (operators are never tenant-PDP principals — `docs/jdlib/04` §6).
- `membership_active` returns `True` for service accounts (their pin plus
  `service_account_active` is the real gate) and checks `Membership.status` for
  users.
- `bindings_for` filters rows against the supplied scope chain in Python (the
  query fetches all of the principal's bindings in the tenant, then intersects).
- `grants_for` returns the `permission_code` set for exactly one resource.

## `pdp.py` — `DefaultPDP`

`evaluate(principal, permission, target, context, *, session) -> Decision(allowed,
reason, matched)` runs the frozen precedence order
(`docs/jdlib/04` §2), returning on the first failure:

| # | Gate | Denial reason |
|---|---|---|
| 0 | `catalog.validate(permission)` | raises `UnknownPermission` |
| 1 | `reader.principal_active(principal)` | `principal_inactive` |
| 2 | `reader.tenant_status_of(tenant_id) == "active"` | `tenant_suspended` |
| 3 | `reader.membership_active(principal, tenant_id)` | `membership_inactive` |
| — | `session is None` | raises `MissingTenantContext` |
| 4 | scope chain → bindings → role permissions | `no_allow` |
| 5 | grants (`ResourceRef` only) merged into the base set | `no_allow` |
| 6 | API-key `principal.scopes is not None` ⇒ permission must be in scopes and the base set is intersected with them | `outside_key_scopes` |
| 7 | `permission in base` | `allowed` |

`matched` records provenance as `MatchedRule(kind, detail)` entries —
`("binding", "role <id> at <scope_type>:<scope_id>")` and
`("grant", "<resource_type>:<resource_id>")` — so an allow can be explained.

Narrowing rules (integration-tested in `tests/unit/test_pdp.py` and
`tests/integration/test_access_roles.py`): scopes **never widen** bindings or
grants, they constrain both; an empty `scopes` set denies everything; `scopes is
None` leaves authority untouched.

Memoization (see `cache.py`) uses these keys: `("principal_active", principal)`,
`("tenant_status", tenant_id)`, `("membership_active", principal, tenant_id)`,
`("scope_chain", target)`, `("bindings", tenant_id, principal, scope_chain)`,
`("role_permissions", tenant_id, role_ids)`, `("grants", tenant_id, principal,
resource_type, resource_id)`.

## `cache.py` — `AuthzCache`

```python
invalidate()  # sets a dirty flag and clears the memo (one-way)
get(key)      # returns None while dirty
put(key, value)
```

Semantics that matter: the cache is **request-scoped only**; after `invalidate()`
it stays empty for the rest of that request's life (a rolled-back mutation
therefore costs a refetch rather than risking a stale allow); there is no
cross-request cache in v1. Consumers must hand `AccessControl` and the PDP the
**same** cache instance per request — the README shows a request-scoped
`Enforcer` subclass that builds a fresh PDP (and therefore a fresh cache) per
evaluation.

## `guards.py` — enforcement points

```python
tenant_target() -> ScopeRef                    # ScopeRef(TENANT, None)

class Enforcer:
    async def require(permission, target, *, session) -> Decision   # raises PermissionDenied

def requires(permission, *, enforcer, target_factory=None) -> decorator
async def authorize(permission, target, *, enforcer, session) -> Decision
```

- `Enforcer.require` reads `current_tenant()` (so a guard outside a context fails
  closed with `MissingTenantContext`) and raises `PermissionDenied("<permission>:
  <reason>")` on a denial.
- `requires(...)` wraps an async function; the target is `tenant_target()` unless
  a `target_factory` is provided, in which case the factory receives the same
  `*args`/`**kwargs` as the call and must return a `Target`. The guard always runs
  **before** the wrapped function, and it looks for the session in
  `kwargs["session"]` — decorator users must pass the session as a keyword
  argument.
- `authorize(...)` is the imperative equivalent for jobs, CLI and service code.

There are exactly two supported enforcement points (guard decorator,
`authorize`) plus the FastAPI `require` dependency, which calls the same
`Enforcer` ([api/fastapi.md](../api/fastapi.md)).

## `access.py` — `AccessControl` (administration)

```python
AccessControl(*, session_factory, catalog, reader, cache, audit,
              registry: ResourceTypeRegistry | None = None,
              scope_lookup: ScopeLookup | None = None,
              resource_lookup: ResourceLookup | None = None)
```

Authority checks use `actor_permissions(tenant_id, principal)`, which counts
**tenant-scope bindings only** (`{(ScopeType.TENANT, None)}`) and intersects with
`principal.scopes` when set. So administrative mutations require tenant-scope
authority, even when the object being managed is org- or team-scoped.

Every mutating method invalidates the `AuthzCache` **before** writing, writes
platform audit rows in the same transaction, and commits once.

| Method | Gate(s) | Notes |
|---|---|---|
| `create_role(tenant_id, name, permissions, *, actor_id, actor_principal, is_system=False)` | `role:manage` + codes validated + `_require_subset` | Duplicate name ⇒ `AuthorizationError`; `RolePermission` rows inserted per code. |
| `update_role(tenant_id, role_id, permissions, *, …)` | `role:manage`, `_require_subset` | `is_system` roles are immutable; audit `role.permissions_changed` with `added`/`removed` diff. |
| `delete_role(tenant_id, role_id, *, …)` | `role:manage` | Refuses system roles and roles with existing bindings or invitations; deletes `RolePermission` rows then the role; audit `role.deleted`. |
| `bind_role(tenant_id, role_id, *, principal_type, principal_id, scope_type, scope_id, actor_id, actor_principal)` | `role:manage`, scope placement validation, **`RoleScopeMismatch`** check per permission, `_validate_principal`, `_require_subset` on the role's codes | Assigning the `owner` role requires the actor to hold the **entire catalog**; the principal must be an active membership (user) or active service account in the same tenant. |
| `unbind_role(tenant_id, binding_id, *, …)` | `role:manage` | Takes the tenant advisory lock, then refuses to remove the **last** owner binding. |
| `grant_resource(tenant_id, *, resource_type, resource_id, principal_type, principal_id, permission, actor_id, actor_principal)` | must hold `resource:share` **and** the granted permission; namespace check (`InvalidResourcePermission`); resource validation | Insert is `INSERT … ON CONFLICT DO NOTHING RETURNING id` on the unique key — idempotent and race-safe; a conflict without a stored row raises. |
| `revoke_grant(tenant_id, grant_id, *, …)` | `resource:share` | Deletes the row; audit `grant.revoked`. |
| `transfer_resource(session, *, resource_type, resource_id, to_organization_id, to_team_id, actor_id, actor_principal, revoke_grants=False)` | `resource:share`, destination scopes validated | Runs **on the tenant session** (writes the tenant row directly); team ownership requires an org; optional grant revocation; audit `resource.owner_changed` with `from`/`to`. |
| `move_team(session, *, team_id, to_organization_id, …, revoke_grants=False)` | `team:manage`, destination org validated | Rewrites `teams.organization_id` and cascades `organization_id` for every registered resource type that has `team_id`, using one statement with a CTE per model (deduplicated by table); optional `_revoke_team_grants`; audit `team.moved`. |
| `invite(tenant_id, *, email, role_id, scope_type, scope_id, invited_by, actor_principal, ttl=7 days)` | `member:invite`, scope placement, role-scope compatibility, `_require_subset`, owner-role rule | Builds `inv_<token_id>_<secret>`, stores `token_id` + Argon2id hash of the secret, revokes any existing **pending** invitation for the same `(email, scope)` (audited), returns `(invitation, token)`. |
| `accept_invitation(token, *, user_id)` | none (the token is the credential) | Verifies the token shape/hash, requires `status == "pending"` and unexpired, **claims it with `UPDATE … WHERE status='pending'` and requires `rowcount == 1`** (race-safe), re-validates scope + role-scope compatibility, reuses or creates the `Membership`, creates the `RoleBinding` if absent, audits `invitation.accepted`, commits. |

Validation helpers shared by the above:

- `_validate_scope_placement(tenant_id, scope_type, scope_id)` — `tenant` must
  have `scope_id is None`, `org`/`team` must have one, and the referenced row is
  resolved through `scope_lookup` (null ⇒ `InvalidReference`, other tenant ⇒
  `CrossTenantReferenceError`, soft-deleted ⇒ `InvalidReference`). A missing
  `scope_lookup` raises `AuthorizationError` — validation is never skipped.
- `_validate_resource(...)` — same three checks through `resource_lookup`.
- `_validate_principal(session, tenant_id, principal_type, principal_id)` — an
  active `ServiceAccount` or active `Membership` **in this tenant**, else
  `CrossTenantReferenceError`.

## Invariants and anti-escalation summary

1. No principal can create/assign authority it does not hold: `_require_subset`
   covers role permissions, binding of a role, and (with `resource:share`) the
   granted permission.
2. The `owner` role is special-cased twice: only a full-catalog actor may assign
   it, and the last owner binding cannot be removed.
3. System roles are immutable; roles with dependants cannot be deleted.
4. Every polymorphic reference is validated for existence, tenant, and state
   (invariant I11).
5. Every mutation invalidates the request-scoped cache before it commits.
6. Audit and business row share one transaction per control-plane mutation.
