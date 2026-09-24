# API: Extension Points

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

jdlib is built around small protocols; every one of them is satisfied in the
tests by a hand-written fake, which makes them the intended seams for consumer
code. Nothing here requires subclassing a library class.

## Configuration-level seams

| Seam | Protocol | When you implement it |
|---|---|---|
| `SecretProvider.resolve(handle) -> str` | `persistence/secrets.py` | `database` placement: map a tenant handle to a DSN from Vault/KMS/your config service. `EnvSecretProvider` and `MemorySecretProvider` ship as examples. |
| `WriteFence.assert_writable(tenant_id)` | `persistence/models.py` | Cache the servability result instead of hitting the control plane per request. `RegistryWriteFence` (control plane) and `NullWriteFence` ship. |
| `RawSqlAuditor.record(statement, mode, context, params)` | `persistence/rawsql.py` | Route privileged raw-SQL usage to your SIEM. Default is a no-op. |
| `JwksFetcher(url) -> dict` | `authn/oidc.py` | Pin TLS, add caching, or stub the IdP in tests (`wiring.fetch_jwks` is the default). |
| `Clock.now()` | `context.py` | Deterministic time in tests; `FrozenClock` in `tests/support` is the reference fake. |
| `Migrator` (duck-typed: `upgrade_tenant`, `upgrade_tenant_url`, `tenant_version`, `tenant_version_url`) | `persistence/strategies/*` | Substitute a custom migration engine; the tests use a `SchemaRunner` stand-in. |

## Data & identity seams

| Seam | Protocol | Notes |
|---|---|---|
| `PrincipalProvider` (`async __call__(request) -> Principal | None`) | `tenancy/middleware.py` | Compose your own authenticators with `CompositeAuthenticator`, or bridge an existing session/JWT pipeline. |
| `TenantResolver` (`async resolve(request, principal) -> TenantRef | None`) | `tenancy/resolution.py` | Add a resolver (a cookie, a path scheme, a header of your own) and put it anywhere in the chain. |
| `PrincipalDirectory.is_active(principal)` | `context.py` | Wire to your user store. |
| `TenantDirectory.get(ref)` | `context.py` | Wire to `TenantRegistry` (shipped) or your own cache. |
| `ServabilityChecker.assert_servable(tenant_id) -> TenantRecord` | `context.py` | `TenantRegistry` satisfies it; keep entitlement/servability policy in one place. |
| `EntitlementChecker.can_act(principal, tenant_id)` | `context.py` | Decide what "may act" means for users, service accounts and operators. |
| `OperatorAuthorizer.is_operator(principal, capability)` | `context.py` | Your break-glass policy: who may call `ContextFactory.for_operator`, for which capability. |
| `PrivilegeAudit.record_privilege(*, kind, capability, justification, actor, tenant_id)` | `context.py` | Where privileged-context issuance is recorded; `PrivilegeAuditAdapter` (control/audit.py) fans it out to your `PlatformAudit` sink as action `privilege.<kind>` (`privilege.operator` / `privilege.system` / `privilege.test`). |

## Authorization seams

| Seam | Protocol | Notes |
|---|---|---|
| `AccessReader` | `authz/reader.py` | `ControlAccessReader` ships; a read-through cache is the obvious alternative. |
| `ScopeResolver` | `authz/scopes.py` | Ships; extend or replace if your hierarchy has more levels (the decisioning code only consumes `ScopeRef`/`Target`). |
| `ResourceTypeRegistry` | `authz/resource_types.py` | Register every resource type you own; unregistered ⇒ `UnknownResourceType`. |
| `PermissionCatalog` | `authz/permissions.py` | Add namespaced permissions with their allowed binding scopes (`catalog.register(...)`); builtins cover the framework surface. |
| `ScopeLookup` / `ResourceLookup` | `authz/access.py` | Validates polymorphic references during administration (`get(tenant_id, id)` → row or `None`). |
| `AuthzCache` | `authz/cache.py` | The shipped cache is request-scoped; a shared cache is a deliberate, non-default extension. |
| `PDP` (duck-typed: `evaluate(...)`) | `authz/pdp.py` | Replace the decision engine (e.g. an external policy service) while keeping guards and `AccessControl` unchanged. |

## Lifecycle seams

| Seam | Signature | Notes |
|---|---|---|
| Seed hook | `await seed(session, tenant)` | Run inside provisioning to insert initial tenant rows (e.g. a default organization). |
| `MigrationRunner` | `migrations/runner.py` | Construct with a control DSN; replaceable for other engines. |
| Directories for jobs | `jobs.py` ports | `ContextPropagator` needs `EnvelopeCodec`, `PrincipalDirectory`, `TenantDirectory`, `ServabilityChecker`, `EntitlementChecker` — the same objects the factory uses, which is what makes re-derivation consistent. |
| Audit sink | `PlatformAudit.record(*, action, tenant_id, actor_id, metadata=None, session=None, actor_type=None)` (control/audit.py) | `NullPlatformAudit`, `RecordingPlatformAudit`, `DatabaseAuditSink` ship; `CompositeAuditSink` fans out to several sinks. |

## Registries you fill (not protocols)

| Registry | Filled with | Failure if not |
|---|---|---|
| `TenantRegistry(strategies={...})` | `IsolationStrategy` instances keyed by `PlacementStrategy` | `StrategyCapabilityError` on create/provision/migrate for that strategy. |
| `ResourceTypeRegistry` | `ResourceTypeDefinition`s | `UnknownResourceType` in `AccessControl` and `ScopeResolver`. |
| `PermissionCatalog` | `Permission`s (13 builtins with `with_builtins()`) | `UnknownPermission` for anything else. |
| `SessionRouter({...})` | the same strategies | `StrategyCapabilityError` when routing a tenant. |
| `Tenant.registered_models()` / `tenant_table_map()` | automatic via `TenantRouted` subclasses | Scoping/raw-SQL validation for your tables only works if the classes are imported before use. |

## What is intentionally *not* a seam

- The scoping enforcement inside `TenantSession` — no hook, no "disable" flag, no
  no "return everything" escape hatch on the session. Cross-tenant work goes through the purger or
  `platform.raw_sql` (audited).
- `ContextFactory`'s gate order — it encodes the authorization precedence in
  `docs/jdlib/04`; changing it means changing the security model.
- Permission/scope semantics (`scopes` narrow, never widen; grants are exact
  resources) — these are invariants, not configuration.
