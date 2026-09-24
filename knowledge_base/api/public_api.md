# API: Public Surface (`jdlib.__all__`)

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

Exactly these 13 names are exported from `jdlib/__init__.py` (plus
`__version__ = "0.1.0"`); the set is frozen by
`tests/unit/test_public_api.py::test_all_is_exactly_the_public_surface`.

| Export | Defined in | Kind |
|---|---|---|
| `TenancyConfig` | `config.py` | pydantic-settings model |
| `TenantContext` | `context.py` | frozen dataclass |
| `ContextFactory` | `context.py` | service class |
| `current_tenant`, `current_principal` | `context.py` | functions |
| `UnitOfWork` | `persistence/uow.py` | async context manager |
| `TenantRepository` | `persistence/repository.py` | generic repository |
| `TenantRegistry` | `control/registry.py` | lifecycle service |
| `AccessControl` | `authz/access.py` | administration service |
| `requires`, `authorize` | `authz/guards.py` | guard decorator / function |
| `JdlibError` | `errors.py` | base exception |
| `errors` | `errors.py` | module (all exception classes) |

## `TenancyConfig`

```python
config = TenancyConfig()               # reads JDLIB_* env vars, fails fast without a signing key
config.control_dsn                     # SecretStr | None
config.context.signing_key.get_secret_value()
```

Full field list: [../configuration.md](../configuration.md). Every nested field is
settable with `JDLIB_<SECTION>__<FIELD>` (double underscore).

## `TenantContext` and the accessors

```python
from jdlib import current_tenant, current_principal

context = current_tenant()             # raises MissingTenantContext when no context is active
context.tenant_id, context.tenant_slug, context.strategy
context.principal, context.privilege, context.request_id, context.correlation_id, context.trace_id
principal = current_principal()
```

Construction is not part of the public contract — use `ContextFactory`
(below) or `jdlib.context.context_scope` when you must install a
previously-created context (e.g. inside a test or a worker).

## `ContextFactory`

```python
factory = ContextFactory(
    config=config.context,
    principals=PrincipalDirectoryAdapter(reader),
    tenants=TenantDirectoryAdapter(registry),
    servability=registry,
    entitlements=EntitlementAdapter(reader),
    operators=my_operator_authorizer,      # OperatorAuthorizer port
    audit=PrivilegeAuditAdapter(audit_sink),
)

context = await factory.for_principal(principal, TenantRef(slug="acme"),
                                      request_id="req-1")
```

| Method | Purpose | Gates (in order) |
|---|---|---|
| `for_principal(principal, tenant_ref, *, request_id, correlation_id=None, trace_id=None)` | normal request/job context | principal active → tenant exists → service-account pin match → entitlement → servability |
| `for_operator(operator, tenant_ref, capability, *, justification, ttl=None, request_id, …)` | time-boxed privileged tenant access | operator kind → justification → TTL bounds → capability → tenant exists → servability; audited |
| `for_system(tenant, *, purpose, issuer=PRIVILEGE_ISSUER)` | framework system context (purge, relocation control) | internal issuer token only; audited |
| `for_test(tenant, *, principal, issuer=PRIVILEGE_ISSUER)` | test/dev context | internal issuer token **and** `ContextConfig.allow_test_contexts`; audited |

Details and the exact failure modes: [../modules/foundation.md](../modules/foundation.md).

## `UnitOfWork` / `TenantRepository` (data access)

```python
async with UnitOfWork(session_factory, current_tenant(), fence=write_fence) as session:
    repo = TenantRepository(session, Invoice)
    await repo.add(Invoice(number="INV-1"))
    rows = await repo.list(Invoice.status == "draft", limit=50)
```

The full contract (scoping, stamping, soft delete, raw SQL, bulk helpers) lives
in [data_access.md](data_access.md).

## `TenantRegistry`

```python
registry = TenantRegistry(session_factory=control_sessions, strategies=strategies,
                          runner=runner, audit=audit_sink)

tenant = await registry.create(slug="acme", name="Acme Inc",
                               strategy=PlacementStrategy.SCHEMA, target_handle="t_acme")
tenant = await registry.provision(tenant.id)          # idempotent, resumable
record = await registry.assert_servable(tenant.id)    # TenantRecord used for routing
await registry.suspend(tenant.id, reason="non_payment", actor_id=operator_id)
await registry.resume(tenant.id)
await registry.archive(tenant.id)
await registry.deprovision(tenant.id, mode=DeprovisionMode.PURGE, actor_id=operator_id)
```

Method-by-method behaviour, the transition table and deprovision ordering:
[../modules/control_plane.md](../modules/control_plane.md).

## `AccessControl`

```python
access = AccessControl(session_factory=control_sessions, catalog=PermissionCatalog.with_builtins(),
                       reader=reader, cache=AuthzCache(), audit=audit_sink,
                       registry=resource_types, scope_lookup=my_scope_lookup,
                       resource_lookup=my_resource_lookup)

role = await access.create_role(tenant_id, "approver", ["resource:read", "resource:update"],
                                actor_id=user_id, actor_principal=principal)
await access.bind_role(tenant_id, role.id, principal_type="user", principal_id=user_id,
                       scope_type="tenant", scope_id=None, actor_id=user_id,
                       actor_principal=principal)
invitation, token = await access.invite(tenant_id, email="dev@acme.io", role_id=role.id,
                                        scope_type="tenant", scope_id=None,
                                        invited_by=user_id, actor_principal=principal)
membership = await access.accept_invitation(token, user_id=new_user_id)
```

Every method, its permission gates, and the anti-escalation rules:
[../modules/authz.md](../modules/authz.md).

## `requires` and `authorize`

```python
@requires("resource:read", enforcer=enforcer)
async def handler(*, session: TenantSession, **kwargs): ...

decision = await authorize("resource:update", ResourceRef("invoice", invoice_id),
                           enforcer=enforcer, session=session)
```

- `requires(permission, *, enforcer, target_factory=None)` — the target defaults
  to tenant scope; the session is read from `kwargs["session"]`.
- `authorize(permission, target, *, enforcer, session)` — imperative form for
  jobs/CLI/services; returns a `Decision` (raises `PermissionDenied` when denied).
- Both raise `MissingTenantContext` when called outside a tenant context.

## `JdlibError` and the `errors` module

```python
from jdlib import JdlibError, errors

try:
    ...
except errors.CrossTenantReferenceError as exc:
    ...
```

The hierarchy and where each class is raised: [../error_handling.md](../error_handling.md).

## Not exported (but stable enough to build on)

Frequently used names that live in submodules rather than `__all__`:

| Need | Import |
|---|---|
| Custom models | `jdlib.models.base` (`TenantBase`, `TenantRouted`, mixins, `ownership_constraints`) |
| Configuration sub-models | `jdlib.config` (`ContextConfig`, `ResolverConfig`, `OidcConfig`, `RlsConfig`, `ApiKeyConfig`) |
| Enums | `jdlib.control.enums` (`PlacementStrategy`, `TenantStatus`, `ScopeType`, `ActorType`, …) |
| Strategy wiring | `jdlib.persistence.strategies.{shared,schema,database,deprovision,rls}` |
| Authn wiring | `jdlib.authn.wiring` (`build_authenticator`, adapters) |
| Authz pieces | `jdlib.authz.{permissions,resource_types,scopes,reader,pdp,cache,guards}` |
| Guard/fence | `jdlib.control.registry.RegistryWriteFence`, `jdlib.persistence.models.NullWriteFence` |
| FastAPI/CLI | `jdlib.integrations.{fastapi,cli}` |
| Contract tests for consumers | `jdlib.testing` |
