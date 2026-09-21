# jdlib — Authorization Model

Companion to the design spec (rev 2). Freezes the evaluation algorithm, the
status precedence chain, anti-escalation rules, ownership transfer semantics,
platform operator capabilities, and the role × action test matrix.

## 1. Principals

| Kind | Source | Tenant relationship | Notes |
|---|---|---|---|
| `user` | OIDC `(issuer, subject)` → `IdentityLink` | active `Membership` required | Global identity |
| `service_account` | API key | pinned by `api_keys` row | Tenant-owned machine principal |
| `platform_operator` | OIDC + `platform_operators.level` | capabilities, never membership | Not a `role_bindings` principal |

`role_bindings.principal_type ∈ {user, service_account}`. Platform operators do
not receive bindings; their authority is capability-based and evaluated
separately.

## 2. Status precedence chain

All gates must pass, in order; the first failure denies with that reason:

```
1. Principal status        user.status = active | service_account.status = active
2. Tenant status           tenants.status = active
3. Membership status       membership.status = active (users only)
4. Binding validity        role exists; scope resolves inside the tenant
5. Permission              permission ∈ effective permissions (section 3)
```

- Suspending a membership denies immediately even if bindings remain.
- Suspending a user denies in every tenant.
- Suspending a tenant denies every principal.
- `deleted` acts as permanent suspension.
- Dangling bindings (scope deleted) are invalid at gate 4 and removed by the
  lifecycle service with an audit event.

Gate ordering vs. disclosure: entitlement is established **before** statuses
are disclosed. Unknown tenant, non-member, and unauthorized probe all return 404;
only a principal entitled to know the tenant exists (active or suspended member,
operator with `platform.tenant.read`) receives `TenantSuspended` (423). The
decision gates below still run in the order shown; the HTTP layer just refuses
to confirm existence to strangers.

## 3. Effective permissions algorithm

For principal `P`, tenant `T`, target `X` (resource | team | org | tenant):

```
1. Run the precedence chain (section 2).
2. scope_chain(X) =
     {tenant T}
     ∪ ancestors(org(X))        # org of team/resource, including itself, up to root
     ∪ {team(X)}                # only if X is a team or a team-owned resource
3. bindings = role_bindings
     WHERE tenant_id = T
       AND (principal_type, principal_id) = P
       AND (scope_type='tenant' AND scope_id IS NULL
            OR (scope_type, scope_id) ∈ scope_chain(X))
4. perms = ∪ role_permissions(role_id of bindings)
5. grants = resource_grants
     WHERE tenant_id = T AND resource_type = type(X) AND resource_id = id(X)
       AND (principal_type, principal_id) = P
6. effective = perms ∪ {grant.permission_code for grant in grants}
7. allowed = requested_permission ∈ effective
```

Properties:

- Inheritance is **downward only**: tenant bindings see everything in the
  tenant; org bindings see the org's teams and their resources; team bindings
  see only that team's resources plus resources explicitly owned by the team.
- A team binding does **not** see resources owned by the organization but no
  team (there is no upward inheritance).
- Grants are exact-resource and do not cascade to child resources; ownership
  determines visibility, grants patch exceptions.
- Additive, allow-only. Absence of allow = deny. No deny rules exist in v1.

Examples (tenant A, org X → team Y → resource R):

| Binding / grant | `project:read` on R |
|---|---|
| tenant A → role with `project:read` | allowed |
| org X → role with `project:read` | allowed |
| team Y → role with `project:read` | allowed |
| team Z (sibling) → role with `project:read` | denied |
| grant on R → user → `project:read` | allowed |
| org X → role without `project:read` | denied |
| membership suspended | denied (gate 3) |
| user has no binding, holds a grant on R only | allowed for R, denied for any other resource |

## 4. Anti-escalation rules

Enforced inside `AccessControl`, not per endpoint:

1. `permission_code` values are validated against the code catalog; unknown
   codes are rejected (`UnknownPermission`).
2. A principal may create or update a role only with permissions it currently
   holds; otherwise `RoleEscalationBlocked`.
3. A principal may create a binding only for a role whose permissions are a
   subset of its own effective permissions in that tenant (owners hold the full
   catalog by definition of the seeded `owner` role).
4. System roles (`is_system = true`) cannot be renamed, edited, or deleted.
5. A role with existing bindings cannot be deleted until bindings are removed.
6. Changing a role's permissions is re-validated against rule 2 and emits
   `role.permissions_changed` with the diff.
7. The `owner` role may be assigned only by an existing owner or a platform
   operator; a tenant must always retain at least one active owner (the last
   owner cannot be unbound).
8. Grants (`resource:share`) require holding the permission being granted, plus
   `resource:share`.

## 5. Ownership transfer

Ownership is explicit (`organization_id`, `team_id` on resources; organization
tree for teams).

- Authorization is always evaluated against the **current** hierarchy.
- `AccessControl.transfer_resource(resource, to_org=None, to_team=None)` and
  `move_team(team, to_org)` update ownership and emit
  `resource.owner_changed` / `team.moved` with `from`/`to` in `metadata`.
- Existing `resource_grants` **remain valid** unless the operation passes
  `revoke_grants=True`.
- Principals depending on the previous scope lose access immediately;
  principals in the new scope gain it immediately.
- Moving a team to another organization does not modify its bindings; bindings
  scoped to the old ancestry stop applying, bindings scoped to the team persist.
- Deleting an organization or team is blocked while resources reference it
  (`ON DELETE RESTRICT`); the lifecycle service requires transfer or explicit
  cascade with audit.
- There is no cross-request permission cache in v1, so no cache invalidation is
  required for transfers. Any future cache must invalidate on access-control
  table changes.

## 6. Platform operator capabilities

Levels are code-mapped capability sets; there is no blanket bypass.

| Capability | support | operator | admin |
|---|---|---|---|
| `platform.audit.read` | ✓ | ✓ | ✓ |
| `platform.tenant.read` (metadata only) | ✓ | ✓ | ✓ |
| `platform.tenant.manage` (lifecycle) | | ✓ | ✓ |
| `platform.migration.execute` | | ✓ | ✓ |
| `platform.operator.manage` | | | ✓ |
| `platform.tenant.access` (read-only, time-boxed, justified) | | ✓ | ✓ |
| `platform.tenant.access.write` | | | ✓ |

Rules:

- Tenant **administration** is distinct from tenant **data access**.
- `platform.tenant.access` opens a privileged `TenantContext` with a mandatory
  `justification` and a TTL (default 30 minutes); every use writes
  `platform_audit_events` with `context.privileged_used`.
- Tenant data access never inherits tenant permissions: an operator cannot
  approve an invoice unless `platform.tenant.access.write` is held; the action
  is still audited as operator-originated in the tenant `AuditEvent`.
- Support-level operators can read platform audit but not tenant data.
- `platform.operator` rows cannot be created or changed except by `admin`.

## 7. PDP contract

```python
class PolicyDecisionPoint(Protocol):
    async def evaluate(self, principal, permission, target, context) -> Decision

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str                  # "no_binding" | "membership_suspended" | "grant" | ...
    matched: tuple[MatchedRule, ...]   # scope, role, grant that produced the allow
```

- Guards: `@requires("invoice:approve", scope=ResourceScope())` for endpoints;
  `authorize(principal, permission, target)` for jobs, CLI, and service code.
- Every decision carries its reasoning; denials and allows on sensitive actions
  are auditable.
- Resolution is memoized **per request** (scope chain, bindings, role
  permissions). No cross-request cache in v1.
- `Decision` is advisory to the PEP; the framework guards and `AccessControl`
  are the only supported enforcement points.

## 8. Role templates and action matrix

Built-in templates seeded per tenant (`is_system = true`). Applications may add
custom roles; they cannot exceed the catalog.

Framework catalog (apps register additional `resource:action` codes):

`tenant:read`, `tenant:manage`, `member:invite`, `member:manage`, `role:manage`,
`org:manage`, `team:manage`, `audit:read`, `resource:read`, `resource:create`,
`resource:update`, `resource:delete`, `resource:share`

| Action → | tenant:read | resource:read | resource:create | resource:update | resource:delete | resource:share | member:invite | member:manage | role:manage | tenant:manage |
|---|---|---|---|---|---|---|---|---|---|---|
| `owner` (tenant scope) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `admin` (tenant scope) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `org_manager` (org scope) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| `member` (team scope) | ✓ | ✓ | ✓ | ✓ | | | | | | |
| `viewer` (any scope) | ✓ | ✓ | | | | | | | | |
| `resource grantee` (resource) | | ✓ | | | | | | | | |
| `service_account` (binding-defined) | | | | | | | | | | |
| `platform_operator` (no binding) | | | | | | | | | | |

Service accounts have no implicit permissions: their row shows no action until
bindings are created, and then only what the bound role grants.
Platform operators show no tenant action by design: tenant data access is an
explicit capability (section 6), never an implicit allow.

The integration test matrix exercises each row against each column and asserts
allow/deny, including scope placement (tenant vs org vs team) and the precedence
chain.
