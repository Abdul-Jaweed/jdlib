# Execution Flows

Step-by-step sequences for the operations that matter, with the exact state
transitions, locks, audit actions and failure modes. States come from
`control/enums.py:TenantStatus`; audit actions are the `action=` strings passed
to the control audit sink.

## 1. `TenantRegistry.create(slug, name, strategy=SHARED, target_handle="default")`

```
1. validate slug     ^[a-z0-9][a-z0-9-]{1,62}$                          → ProvisioningError
2. validate handle   shared: non-empty; schema: ^t_[a-z0-9][a-z0-9_]{0,50}$;
                     database: ^[a-z0-9][a-z0-9-]{0,50}$                 → ProvisioningError
3. place_tenant(session, …)  ← runs inside ControlPlaneSession.__aenter__,
   which takes pg_advisory_xact_lock(hashtext('jdlib.tenant_write')) on enter
   ├─ registry.find(TenantRef(slug)) → existing?
   │    ├─ same placement  → return (idempotent, no audit)
   │    └─ different       → ProvisioningError("tenant already exists with a different placement")
   └─ handle owned by another tenant → ProvisioningError("target handle … already owned by tenant …")
4. insert Tenant(status=PROVISIONING) + TenantPlacement(strategy, target_handle, region)
5. audit "tenant.created" (actor operator/system, metadata strategy+handle)
6. commit (releases the advisory lock)
```

`provision(tenant_id)` — the real sequence (`registry.py:270-365`):

```
1. lock; load tenant
   ├─ ACTIVE                  → return unchanged (idempotent, no audit)
   └─ anything but PROVISIONING → TenantOperationInProgress
2. load placement + migration state      → ProvisioningError when either is missing
3. resolve strategy for the placement    → StrategyCapabilityError if unregistered
4. try:
     strategy.provision(record)          CREATE SCHEMA / CREATE DATABASE (shared: no-op)
     state.status = RUNNING ; flush      (visible to concurrent readers)
     strategy.migrate(record, runner)    alembic upgrade head for the tenant chain
     seeder.seed(record)                 seed hook gets the TenantRecord
     runner.tenant_version(strategy.migration_schema(record)) must equal
       state.desired_version             → else ProvisioningError
     state.current_version = desired ; status = SUCCESS ; last_error = None
     audit "tenant.migration.succeeded"
   except Exception as exc:
     state.status = FAILED ; state.last_error = str(exc)
     audit "tenant.migration.failed" (metadata {"error": ...})
     commit ; raise                     ← the tenant stays PROVISIONING, the
                                          caller decides what to do next
5. tenant.status = ACTIVE ; clear suspended_reason/suspended_at
6. audit "tenant.activated" ; commit
```

Note what the fence does **not** do here: there is no enqueue/drain step. Writes
are blocked for a provisioning tenant because `RegistryWriteFence.assert_writable`
re-checks servability on every unit of work — status `provisioning` is not `active`,
so writes are refused until step 5 commits.

## 2. Lifecycle transitions (all through the same guard)

`_ALLOWED_TENANT_TRANSITIONS` (`control/registry.py:51`) is the only source of
truth; `_require_transition` raises
`TenantOperationInProgress("tenant transition <a> -> <b> is not allowed")` for
anything else.

| From | Allowed to |
|---|---|
| `provisioning` | `active`, `deleted` |
| `active` | `suspended`, `archived` |
| `suspended` | `active`, `archived` |
| `archived` | `active`, `deprovisioning` |
| `deprovisioning` | `deleted`, `archived` |
| `deleted` | — (terminal) |

- `suspend(tenant_id, reason, actor_id=None)` — `active`→`suspended`; audit
  `tenant.suspended` with `{"reason": reason}`; stamps `suspended_at`.
- `resume(tenant_id, actor_id=None)` — `suspended`→`active`; audit
  `tenant.resumed`; clears `suspended_at`/`suspended_reason`.
- `archive(tenant_id, actor_id=None)` — `active`/`suspended`→`archived`; audit
  `tenant.archived`; `archived_at` is stamped. Writes stop immediately afterwards
  because the fence re-derives servability per unit of work (there is no
  "fence the in-flight sessions" call).
- `migrate(tenant_id)` — runs `strategy.migrate` for the tenant's placement; on
  failure it marks the migration state `failed` + `last_error`, and **if the tenant
  was `active` it is suspended with `suspended_reason="migration_failed"`** before
  the error is re-raised (invariant I10: a broken tenant is fenced, not
  failed-open). Success sets `current_version = desired_version`, status
  `success`, and audits `tenant.migration.succeeded`.
- Servability: `assert_servable(tenant_id)` returns the `TenantRecord` only when
  all three hold — status is `active`, the `TenantMigrationState` is `success`
  **and** `current_version == desired_version`, and no `tenant_relocations` row is
  in a critical phase (`copying`, `verifying`, `flipping`, `post_flip_verification`,
  `control/registry.py:44`). Any failure raises `TenantSuspended("<which condition>")`;
  the write fence reuses the same predicate to raise `TenantNotWritable`.

## 3. `deprovision(tenant_id, mode, actor_id=None, detach_children=False)`

`mode=ARCHIVE` is a lifecycle transition, not a teardown:

```
1. lock; load tenant
   ├─ already ARCHIVED → return unchanged
   └─ _require_transition(current, ARCHIVED)   → ProvisioningError if illegal
2. children = SELECT id FROM tenants WHERE parent_tenant_id = tenant_id
   └─ children and not detach_children → ProvisioningError("tenant has children; detach them explicitly")
3. if children: UPDATE tenants SET parent_tenant_id = NULL WHERE parent_tenant_id = :id
4. status → ARCHIVED ; audit "tenant.deprovisioned" (metadata: mode, detach_children,
   detached_children) ; commit
```

`mode=PURGE|DESTROY` is the teardown (`registry.py:465-553`):

```
1. lock; load tenant
   ├─ already DELETED → return unchanged
   ├─ already DEPROVISIONING → continue (resumable)
   └─ else _require_transition(current, DEPROVISIONING)   → TenantOperationInProgress unless ARCHIVED
2. children check as above (ProvisioningError, then re-checked as
   TenantOperationInProgress after the commit below if the set changed)
3. load placement → ProvisioningError if missing
4. purge_required = placement.strategy == "shared"
   ├─ purge_required and self._purger is None → ProvisioningError(
   │     "shared purge/destroy requires a tenant-plane purger")
   └─ purger = self._purger or None
5. status → DEPROVISIONING ; audit is NOT written yet ; commit
6. re-lock; re-read the tenant
   └─ status != DEPROVISIONING → TenantOperationInProgress("<slug> deprovision was
        superseded by state <status>")   ← the "operation in progress" race guard
7. _delete_access_rows(session, tenant_id): one DELETE per entry of
   _ACCESS_ROW_DELETION_ORDER (registry.py:60), counting rowcounts:
   api_keys → service_accounts → invitations → role_bindings → resource_grants
   → role_permissions → roles → memberships
8. strategy.deprovision(record, mode)
   ├─ shared   : no-op  (the purger does the work in step 9)
   ├─ schema   : purge/destroy → DROP SCHEMA IF EXISTS <quoted> CASCADE
   └─ database : purge/destroy → drop cached engine, terminate other backends, DROP DATABASE
9. if purger: metadata["tenant_counts"] = await purger.purge(record)
   (system context with capability "tenant.purge"; delete_where per TenantRouted
    table in reverse `TenantBase.metadata.sorted_tables` order)
10. tenant.status = DELETED ; audit "tenant.deprovisioned" with
    metadata {"mode", "counts", optional "detach_children"/"detached_children",
    optional "tenant_counts"} ; commit
```

Failure modes: a shared placement without a configured `TenantPlanePurger` raises
`ProvisioningError("shared purge/destroy requires a tenant-plane purger")` because
a shared strategy can purge nothing; `mode` is coerced through `DeprovisionMode`
so an unknown value is a typed error; a tenant that gains children between the two
checks raises `TenantOperationInProgress`.

## 4. Request authorization

```
principal                Identity / API key resolved (authn)
   │
tenant_ref               ResolverChain: claims → subdomain → path → header → api key
   │
ContextFactory.for_principal
   ├─ principal_active          false → TenantAccessDenied("principal is not active")
   ├─ tenant lookup             miss  → TenantNotFound
   ├─ pin check (service acct)  mismatch → TenantAccessDenied
   ├─ entitlement               false → TenantAccessDenied
   └─ servability               suspended/relocating → TenantSuspended
   │
Enforcer.require(permission, target, session=…)
   └─ DefaultPDP.evaluate
        ├─ catalog.validate                     → UnknownPermission (raises)
        ├─ principal_inactive / tenant_suspended / membership_inactive
        ├─ scope chain → bindings → role permissions
        ├─ grants (resource targets) merged
        ├─ key scopes intersect (never widen)
        └─ allowed | no_allow | outside_key_scopes
```

`PermissionDenied("<permission>: <reason>")` is what the caller sees; the
`Decision.matched` list explains which binding or grant allowed it.

## 5. An administrative mutation, e.g. `bind_role`

```
1. actor_permissions(tenant_id, actor_principal)  ← TENANT-SCOPE bindings only
2. require "role:manage"                          → PermissionDenied
3. load the role                                   → InvalidReference if absent/soft-deleted
4. _validate_scope_placement(tenant_id, scope)     → InvalidReference / CrossTenantReferenceError
5. per role permission: scope_type ∈ allowed_scopes → RoleScopeMismatch
6. _validate_principal(...)                        → CrossTenantReferenceError
7. _require_subset(actor_permissions, role permissions) → RoleEscalationBlocked
   owner role: actor must hold the entire permission catalog
8. cache.invalidate(); insert RoleBinding; audit "binding.created"; commit
```

`unbind_role` first takes the tenant advisory lock
(`pg_advisory_xact_lock(hashtext('jdlib.tenant_write'))`) so two concurrent
unbinds cannot race past the last-owner check.

## 6. Invitation flow

```
invite(…)                        accept_invitation(token, user_id=…)
  ├─ gates (member:invite …)       ├─ parse token: "inv_<token_id>_<secret>"
  ├─ revoke pending duplicate      ├─ row by token_id            → InvalidToken
  ├─ token = inv_<id>_<secret>     ├─ argon2 verify secret       → InvalidToken
  ├─ store token_id + hash,        ├─ status expired/revoked     → ExpiredToken/…
  │    expires_at = now + 7d       ├─ UPDATE … WHERE status='pending' (rowcount==1 else InvalidToken)
  ├─ audit "invitation.created"    ├─ re-validate scope + role-scope compatibility
  └─ return (invitation, token)    ├─ Membership: reuse or create (conflict-tolerant)
                                   ├─ RoleBinding: create if absent
                                   ├─ audit "invitation.accepted"; commit
```

## 7. Privileged contexts

| Entry | Gates | Lifetime | Audit |
|---|---|---|---|
| `for_operator(operator, tenant_ref, capability, justification, ttl=…, …)` | operator kind → non-blank justification → `0 < effective_ttl ≤ config.operator_ttl` (default `config.operator_ttl`) → operator authorizer capability check → tenant exists → servability | `expires_at = now + effective_ttl` | `PrivilegeAudit.record_privilege(kind=OPERATOR, capability, justification, actor, tenant_id)` → control audit action `privilege.operator` |
| `for_system(tenant, purpose=…, issuer=PRIVILEGE_ISSUER)` | issuer token must be `PRIVILEGE_ISSUER` (required kwarg, no default) | none (`expires_at=None`) | `PrivilegeAudit.record_privilege(kind=SYSTEM, capability=purpose, actor=…)` → control audit action `privilege.system` |
| `for_test(tenant, principal=…, issuer=PRIVILEGE_ISSUER)` | issuer token **and** `allow_test_contexts` | none | control audit action `privilege.test` |

Privileged contexts are never serialized into envelopes (`ContextPropagator`
always rebuilds `privilege=None`), and they do not widen tenant scoping — they
only unlock the write fence (`privileged_bypass` for `relocation.manage`) and the
hard-delete / privileged-raw-SQL paths.

## 8. Job execution

```
producer: envelope = ContextFactory… → EnvelopeCodec.encode(context)   (HMAC, TTL)
queue:    token
consumer: tenant_job(propagator) → reconstruct(token)
             decode → principal → is_active → tenants.get → can_act → assert_servable
          with context_scope(context): await fn(token, …)
```

Reconstruction re-reads the control plane on **every** job, so revoking a
membership or suspending a tenant takes effect for queued work immediately
(invariant I7, `docs/jdlib/03`).
