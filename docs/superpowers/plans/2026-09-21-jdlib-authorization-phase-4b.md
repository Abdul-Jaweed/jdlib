# jdlib Authorization Evaluation (Phase 4b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the authorization evaluation core: the code-owned permission catalog, `ResourceTypeRegistry`, tenant-plane scope resolution (org ancestry + team + resource ownership), the request-scoped `AuthzCache`, the `DefaultPDP` implementing the frozen precedence chain and effective-permission algorithm, and the `Enforcer`/`requires`/`authorize` enforcement points.

**Architecture:** `jdlib.authz` reads control-plane access data through an `AccessReader` port (implemented over `ControlPlaneSession`) and tenant-plane ownership through `ScopeResolver` (using a `TenantSession`), so evaluation is a pure function of principal + target + both planes. `PermissionCatalog` and `ResourceTypeRegistry` are startup-validated code registries. No mutation lives here — `AccessControl` is Plan 4c.

**Tech Stack:** SQLAlchemy 2.0 async, Pydantic-free dataclasses, pytest + testcontainers PostgreSQL 16. No new dependencies.

**Specs (frozen):** `docs/jdlib/04-authorization-model.md` §1–§4, §7–§8; `docs/jdlib/03-isolation-invariants.md` I11–I12; `docs/jdlib/02-relational-schema.md` §3.10–3.13.

## Global Constraints

- Permission codes are `namespace:action`; the catalog is code-defined and unknown codes raise `UnknownPermission`; duplicate registration is an error.
- `ResourceTypeDefinition` requires `tenant_routed ⇒ tenant_owned`; unknown resource types raise `UnknownResourceType`; grants validate `permission.namespace == definition.permission_namespace` (`InvalidResourcePermission`).
- Precedence chain (first failure denies with its reason): principal active → tenant active → membership active → binding validity → permission. Effective permissions = `(role bindings at target scope and ancestors ∪ exact-resource grants)`, then `∩ api_key.scopes` when the principal has scopes.
- Inheritance is downward only; no deny rules; absence of allow = deny.
- `AuthzCache` is request-scoped only; `invalidate()` is called by access-control mutations (Plan 4c) and by the PDP itself on miss.
- Commands: `.venv/Scripts/python -m pytest ...`, `ruff check .`, `mypy src/jdlib`; integration tests need `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` and a fresh DB.
- No comments in source; docstrings only where shown; pristine test output; commit after every task.

---

### Task 1: Permission catalog

**Files:**
- Create: `src/jdlib/authz/__init__.py`
- Create: `src/jdlib/authz/permissions.py`
- Create: `tests/unit/test_permissions.py`

**Interfaces:**
- Consumes: `jdlib.control.enums.ScopeType`; `jdlib.errors.UnknownPermission`.
- Produces: `Permission(code, namespace, allowed_scopes, description)`; `PermissionCatalog` with `register`, `validate`, `all`, `with_builtins()`; `BUILTIN_PERMISSIONS`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_permissions.py`:

```python
import pytest

from jdlib.authz.permissions import BUILTIN_PERMISSIONS, Permission, PermissionCatalog
from jdlib.control.enums import ScopeType
from jdlib.errors import UnknownPermission


def test_builtin_catalog_codes_are_frozen():
    catalog = PermissionCatalog.with_builtins()
    codes = {permission.code for permission in catalog.all()}
    assert {
        "tenant:read",
        "tenant:manage",
        "member:invite",
        "member:manage",
        "role:manage",
        "org:manage",
        "team:manage",
        "audit:read",
        "resource:read",
        "resource:create",
        "resource:update",
        "resource:delete",
        "resource:share",
    } == codes


def test_allowed_scopes_match_the_frozen_matrix():
    catalog = PermissionCatalog.with_builtins()
    assert catalog.validate("tenant:manage").allowed_scopes == frozenset({ScopeType.TENANT})
    assert catalog.validate("org:manage").allowed_scopes == frozenset(
        {ScopeType.TENANT, ScopeType.ORG}
    )
    assert catalog.validate("team:manage").allowed_scopes == frozenset(
        {ScopeType.TENANT, ScopeType.ORG, ScopeType.TEAM}
    )
    assert catalog.validate("resource:read").allowed_scopes == frozenset(
        {ScopeType.TENANT, ScopeType.ORG, ScopeType.TEAM}
    )


def test_unknown_permission_raises():
    with pytest.raises(UnknownPermission):
        PermissionCatalog.with_builtins().validate("invoice:approve")


def test_duplicate_registration_raises():
    catalog = PermissionCatalog.with_builtins()
    with pytest.raises(ValueError):
        catalog.register(Permission("tenant:read", "tenant", frozenset({ScopeType.TENANT}), "dup"))


def test_custom_registration_and_namespace():
    catalog = PermissionCatalog.with_builtins()
    catalog.register(
        Permission(
            "invoice:approve",
            "invoice",
            frozenset({ScopeType.TENANT, ScopeType.ORG, ScopeType.TEAM}),
            "Approve an invoice",
        )
    )
    assert catalog.validate("invoice:approve").namespace == "invoice"
    assert "invoice:approve" in {permission.code for permission in catalog.all()}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_permissions.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.authz'`

- [ ] **Step 3: Implement `src/jdlib/authz/__init__.py` (empty) and `src/jdlib/authz/permissions.py`**

```python
from __future__ import annotations

from dataclasses import dataclass

from jdlib.control.enums import ScopeType
from jdlib.errors import UnknownPermission


@dataclass(frozen=True, slots=True)
class Permission:
    code: str
    namespace: str
    allowed_scopes: frozenset[ScopeType]
    description: str


def _permission(
    code: str, namespace: str, scopes: set[ScopeType], description: str
) -> Permission:
    return Permission(code, namespace, frozenset(scopes), description)


_TENANT = {ScopeType.TENANT}
_TENANT_ORG = {ScopeType.TENANT, ScopeType.ORG}
_ANY_SCOPE = {ScopeType.TENANT, ScopeType.ORG, ScopeType.TEAM}

BUILTIN_PERMISSIONS: tuple[Permission, ...] = (
    _permission("tenant:read", "tenant", _TENANT, "Read tenant metadata"),
    _permission("tenant:manage", "tenant", _TENANT, "Manage tenant lifecycle settings"),
    _permission("member:invite", "member", _TENANT, "Invite members"),
    _permission("member:manage", "member", _TENANT, "Manage memberships"),
    _permission("role:manage", "role", _TENANT, "Manage roles and bindings"),
    _permission("org:manage", "org", _TENANT_ORG, "Manage organizations"),
    _permission("team:manage", "team", _ANY_SCOPE, "Manage teams"),
    _permission("audit:read", "audit", _TENANT, "Read audit events"),
    _permission("resource:read", "resource", _ANY_SCOPE, "Read resources"),
    _permission("resource:create", "resource", _ANY_SCOPE, "Create resources"),
    _permission("resource:update", "resource", _ANY_SCOPE, "Update resources"),
    _permission("resource:delete", "resource", _ANY_SCOPE, "Delete resources"),
    _permission("resource:share", "resource", _ANY_SCOPE, "Share resources"),
)


class PermissionCatalog:
    def __init__(self, permissions: tuple[Permission, ...] = ()) -> None:
        self._by_code: dict[str, Permission] = {}
        for permission in permissions:
            self.register(permission)

    @classmethod
    def with_builtins(cls) -> PermissionCatalog:
        return cls(BUILTIN_PERMISSIONS)

    def register(self, permission: Permission) -> None:
        if permission.code in self._by_code:
            raise ValueError(f"permission already registered: {permission.code}")
        self._by_code[permission.code] = permission

    def validate(self, code: str) -> Permission:
        permission = self._by_code.get(code)
        if permission is None:
            raise UnknownPermission(code)
        return permission

    def all(self) -> tuple[Permission, ...]:
        return tuple(self._by_code.values())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_permissions.py -v -W error`
Expected: PASS (5 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authz tests/unit/test_permissions.py
git commit -m "feat: permission catalog with frozen builtin matrix"
```

---

### Task 2: Resource type registry

**Files:**
- Create: `src/jdlib/authz/resource_types.py`
- Create: `tests/unit/test_resource_types.py`

**Interfaces:**
- Consumes: `PermissionCatalog`, `Permission`; `jdlib.models.base.TenantRouted`; errors `UnknownResourceType`, `InvalidResourcePermission`.
- Produces: `ResourceTypeDefinition(resource_type, model, tenant_owned, tenant_routed, permission_namespace)` with validation (routed ⇒ owned; a routed model must expose `organization_id` and `team_id`); `ResourceTypeRegistry` with `register`, `get`, `all`, `validate_permission(resource_type, permission_code, catalog)`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_resource_types.py`:

```python
import pytest

from jdlib.authz.permissions import Permission, PermissionCatalog
from jdlib.authz.resource_types import ResourceTypeDefinition, ResourceTypeRegistry
from jdlib.control.enums import ScopeType
from jdlib.errors import InvalidResourcePermission, UnknownResourceType
from jdlib.models.settings import TenantSetting
from tests.support.invoice import Invoice


def _definition(**overrides: object) -> ResourceTypeDefinition:
    base = {
        "resource_type": "invoice",
        "model": Invoice,
        "tenant_owned": True,
        "tenant_routed": True,
        "permission_namespace": "invoice",
    }
    base.update(overrides)
    return ResourceTypeDefinition(**base)  # type: ignore[arg-type]


def test_definition_rejects_routed_without_owned():
    with pytest.raises(ValueError):
        _definition(tenant_owned=False, tenant_routed=True)


def test_registry_rejects_routed_model_without_ownership_columns():
    with pytest.raises(ValueError):
        ResourceTypeRegistry().register(
            ResourceTypeDefinition(
                "tenant_setting",
                TenantSetting,
                tenant_owned=True,
                tenant_routed=True,
                permission_namespace="tenant_setting",
            )
        )


def test_registry_duplicate_and_unknown():
    registry = ResourceTypeRegistry()
    registry.register(_definition())
    assert registry.get("invoice").model is Invoice
    with pytest.raises(ValueError):
        registry.register(_definition())
    with pytest.raises(UnknownResourceType):
        registry.get("mystery")


def test_permission_namespace_must_match():
    registry = ResourceTypeRegistry()
    registry.register(_definition())
    catalog = PermissionCatalog.with_builtins()
    catalog.register(
        Permission(
            "invoice:approve",
            "invoice",
            frozenset({ScopeType.TENANT, ScopeType.ORG, ScopeType.TEAM}),
            "Approve",
        )
    )
    registry.validate_permission("invoice", "invoice:approve", catalog)
    with pytest.raises(InvalidResourcePermission):
        registry.validate_permission("invoice", "resource:read", catalog)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_resource_types.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.authz.resource_types'`

- [ ] **Step 3: Implement `src/jdlib/authz/resource_types.py`**

```python
from __future__ import annotations

from dataclasses import dataclass

from jdlib.authz.permissions import PermissionCatalog
from jdlib.errors import InvalidResourcePermission, UnknownResourceType


@dataclass(frozen=True, slots=True)
class ResourceTypeDefinition:
    resource_type: str
    model: type
    tenant_owned: bool
    tenant_routed: bool
    permission_namespace: str

    def __post_init__(self) -> None:
        if not self.resource_type or not self.permission_namespace:
            raise ValueError("resource_type and permission_namespace are required")
        if self.tenant_routed and not self.tenant_owned:
            raise ValueError("tenant_routed requires tenant_owned")
        if self.tenant_routed and not (
            hasattr(self.model, "organization_id") and hasattr(self.model, "team_id")
        ):
            raise ValueError(
                "tenant_routed requires a model with organization_id and team_id"
            )


class ResourceTypeRegistry:
    def __init__(self) -> None:
        self._by_name: dict[str, ResourceTypeDefinition] = {}

    def register(self, definition: ResourceTypeDefinition) -> None:
        if definition.resource_type in self._by_name:
            raise ValueError(f"resource type already registered: {definition.resource_type}")
        self._by_name[definition.resource_type] = definition

    def get(self, resource_type: str) -> ResourceTypeDefinition:
        definition = self._by_name.get(resource_type)
        if definition is None:
            raise UnknownResourceType(resource_type)
        return definition

    def all(self) -> tuple[ResourceTypeDefinition, ...]:
        return tuple(self._by_name.values())

    def validate_permission(
        self, resource_type: str, permission_code: str, catalog: PermissionCatalog
    ) -> None:
        definition = self.get(resource_type)
        permission = catalog.validate(permission_code)
        if permission.namespace != definition.permission_namespace:
            raise InvalidResourcePermission(
                f"{permission_code} is not valid for resource type {resource_type}"
            )
```

Note for the implementer: `tests/support/invoice.py` already defines `Invoice` on `TenantBase`; the registry does not require the model to be `TenantRouted` for the unit test, but the definition contract does (`tenant_routed=True` here). A `tenant_routed=True` definition additionally requires the model to expose `organization_id` and `team_id` because `ScopeResolver` reads those attributes when resolving resource ownership; `TenantSetting` (tenant-routed but not ownable) is the rejection counterexample. If importing `Invoice` into a unit test drags in SQLAlchemy metadata construction, that is acceptable (Phase 1 tests do the same). Remove the unused `Any` import if ruff flags it.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_resource_types.py -v -W error`
Expected: PASS (4 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authz/resource_types.py tests/unit/test_resource_types.py
git commit -m "feat: resource type registry with namespace validation"
```

---

### Task 3: Scope resolution

**Files:**
- Create: `src/jdlib/authz/scopes.py`
- Create: `tests/integration/test_scopes.py`

**Interfaces:**
- Consumes: `ScopeType`; `TenantSession`; `ResourceTypeRegistry`; `ScopeRef`, `ResourceRef` dataclasses (new, defined here).
- Produces: `ScopeRef(type: ScopeType, id: uuid.UUID | None)`; `ResourceRef(resource_type: str, resource_id: uuid.UUID)`; `Target = ScopeRef | ResourceRef`; `ScopeResolver(registry)` with `async chain(session, target) -> tuple[ScopeRef, ...]`.

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_scopes.py`:

```python
import uuid

from jdlib.authz.resource_types import ResourceTypeDefinition, ResourceTypeRegistry
from jdlib.authz.scopes import ResourceRef, ScopeRef, ScopeResolver
from jdlib.control.enums import ScopeType
from jdlib.models.org import Organization, Team
from tests.support.invoice import Invoice

TENANT_A = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _registry() -> ResourceTypeRegistry:
    registry = ResourceTypeRegistry()
    registry.register(
        ResourceTypeDefinition("invoice", Invoice, tenant_owned=True, tenant_routed=True,
                               permission_namespace="invoice")
    )
    return registry


async def _seed_org_tree(session):
    root, child, sibling = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    await session.add(Organization(id=root, name="Root", slug=f"root-{root.hex[:6]}"))
    await session.add(
        Organization(id=child, name="Child", slug=f"child-{child.hex[:6]}",
                     parent_organization_id=root)
    )
    await session.add(
        Organization(id=sibling, name="Sibling", slug=f"sib-{sibling.hex[:6]}")
    )
    team = uuid.uuid4()
    await session.add(Team(id=team, organization_id=child, name="Team", slug=f"t-{team.hex[:6]}"))
    await session.flush()
    return root, child, sibling, team


async def test_tenant_scope_chain_is_just_tenant(session_factory):
    from tests.integration.test_session_isolation import _context, _session

    resolver = ScopeResolver(_registry())
    async with await _session(session_factory, TENANT_A) as session:
        chain = await resolver.chain(session, ScopeRef(ScopeType.TENANT, None))
        assert chain == (ScopeRef(ScopeType.TENANT, None),)


async def test_org_chain_includes_ancestors(session_factory):
    from tests.integration.test_session_isolation import _context, _session

    resolver = ScopeResolver(_registry())
    async with await _session(session_factory, TENANT_A) as session:
        root, child, sibling, _ = await _seed_org_tree(session)
        chain = await resolver.chain(session, ScopeRef(ScopeType.ORG, child))
        assert chain == (
            ScopeRef(ScopeType.TENANT, None),
            ScopeRef(ScopeType.ORG, child),
            ScopeRef(ScopeType.ORG, root),
        )
        sibling_chain = await resolver.chain(session, ScopeRef(ScopeType.ORG, sibling))
        assert ScopeRef(ScopeType.ORG, root) not in sibling_chain


async def test_team_chain_includes_its_org_and_ancestors(session_factory):
    from tests.integration.test_session_isolation import _context, _session

    resolver = ScopeResolver(_registry())
    async with await _session(session_factory, TENANT_A) as session:
        root, child, _, team = await _seed_org_tree(session)
        chain = await resolver.chain(session, ScopeRef(ScopeType.TEAM, team))
        assert chain == (
            ScopeRef(ScopeType.TENANT, None),
            ScopeRef(ScopeType.ORG, child),
            ScopeRef(ScopeType.ORG, root),
            ScopeRef(ScopeType.TEAM, team),
        )


async def test_resource_chain_uses_ownership(session_factory):
    from tests.integration.test_session_isolation import _context, _session

    resolver = ScopeResolver(_registry())
    async with await _session(session_factory, TENANT_A) as session:
        root, child, _, team = await _seed_org_tree(session)
        invoice_id = uuid.uuid4()
        await session.add(
            Invoice(id=invoice_id, number=f"INV-{invoice_id.hex[:6]}",
                    organization_id=child, team_id=team)
        )
        await session.flush()
        chain = await resolver.chain(session, ResourceRef("invoice", invoice_id))
        assert chain == (
            ScopeRef(ScopeType.TENANT, None),
            ScopeRef(ScopeType.ORG, child),
            ScopeRef(ScopeType.ORG, root),
            ScopeRef(ScopeType.TEAM, team),
        )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_scopes.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.authz.scopes'`

- [ ] **Step 3: Implement `src/jdlib/authz/scopes.py`**

```python
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, cast

import sqlalchemy as sa

from jdlib.authz.resource_types import ResourceTypeRegistry
from jdlib.control.enums import ScopeType
from jdlib.models.org import Organization, Team
from jdlib.persistence.session import TenantSession


@dataclass(frozen=True, slots=True)
class ScopeRef:
    type: ScopeType
    id: uuid.UUID | None


@dataclass(frozen=True, slots=True)
class ResourceRef:
    resource_type: str
    resource_id: uuid.UUID


Target = ScopeRef | ResourceRef


class ScopeResolver:
    def __init__(self, registry: ResourceTypeRegistry) -> None:
        self._registry = registry

    async def chain(self, session: TenantSession, target: Target) -> tuple[ScopeRef, ...]:
        tenant = ScopeRef(ScopeType.TENANT, None)
        if isinstance(target, ScopeRef):
            if target.type is ScopeType.TENANT:
                return (tenant,)
            if target.id is None:
                raise ValueError(f"{target.type} scope requires a scope id")
            if target.type is ScopeType.ORG:
                return (tenant, *await self._org_chain(session, target.id))
            if target.type is ScopeType.TEAM:
                team = await session.get(Team, target.id)
                if team is None:
                    return (tenant,)
                return (
                    tenant,
                    *await self._org_chain(session, team.organization_id),
                    ScopeRef(ScopeType.TEAM, target.id),
                )
            raise ValueError(f"unsupported scope type: {target.type}")
        definition = self._registry.get(target.resource_type)
        model = cast(Any, definition.model)
        row = (
            await session.execute(
                sa.select(model.organization_id, model.team_id).where(
                    model.id == target.resource_id
                )
            )
        ).first()
        if row is None:
            return (tenant,)
        organization_id, team_id = row
        chain: list[ScopeRef] = [tenant]
        if organization_id is not None:
            chain.extend(await self._org_chain(session, organization_id))
        if team_id is not None:
            chain.append(ScopeRef(ScopeType.TEAM, team_id))
        return tuple(chain)

    async def _org_chain(self, session: TenantSession, org_id: uuid.UUID) -> list[ScopeRef]:
        chain: list[ScopeRef] = []
        seen: set[uuid.UUID] = set()
        current: uuid.UUID | None = org_id
        while current is not None and current not in seen:
            seen.add(current)
            organization = await session.get(Organization, current)
            if organization is None:
                break
            chain.append(ScopeRef(ScopeType.ORG, organization.id))
            current = organization.parent_organization_id
        return chain
```

Note for the implementer: the recursive CTE originally sketched here was replaced by tenant-scoped ORM traversal because tenant sessions reject raw text/table statements: `TenantSession.execute` raises on `sa.TextClause` and `raw_sql` refuses CTEs in tenant-bound mode. `_org_chain` therefore walks nearest→root with `session.get(Organization, current)` following `parent_organization_id`, guarded by a `seen` set against parent cycles; the team lookup uses `session.get(Team, ...)`; resource ownership reads `organization_id`/`team_id` off the registry model. Tenant scoping is enforced by the composite PKs rather than by `search_path`. Drop unused imports per ruff.

- [ ] **Step 4: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_scopes.py -v -W error`
Expected: PASS (4 passed)

- [ ] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authz/scopes.py tests/integration/test_scopes.py
git commit -m "feat: tenant-plane scope resolution with org ancestry and resource ownership"
```

---

### Task 4: AuthzCache, AccessReader, DefaultPDP

**Files:**
- Create: `src/jdlib/authz/cache.py`
- Create: `src/jdlib/authz/reader.py`
- Create: `src/jdlib/authz/pdp.py`
- Create: `tests/unit/test_pdp.py`
- Create: `tests/integration/test_pdp_control_reader.py`

**Interfaces:**
- Consumes: catalog, registry, scopes, `ControlPlaneSession`, `TenantSession`, `Principal`, `TenantContext`, `ScopeType`.
- Produces: `AuthzCache` (`invalidate`, memo accessors); `AccessReader` protocol; `ControlAccessReader(session_factory)`; `MatchedRule`, `Decision`, `PolicyDecisionPoint`, `DefaultPDP(catalog, reader, scopes, cache=None)` with `async evaluate(principal, permission, target, context, *, session)`.

- [ ] **Step 1: Write the unit tests**

`tests/unit/test_pdp.py`:

```python
import uuid

import pytest

from jdlib.authz.cache import AuthzCache
from jdlib.authz.pdp import DefaultPDP
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import Binding
from jdlib.authz.scopes import ResourceRef, ScopeRef
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy, ScopeType
from jdlib.errors import MissingTenantContext

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
USER_ID = uuid.uuid4()
RESOURCE_ID = uuid.uuid4()
_SESSION = object()
_TENANT_CHAIN = (ScopeRef(ScopeType.TENANT, None),)


def _context(principal: Principal) -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req",
        correlation_id="corr",
    )


class _Reader:
    def __init__(
        self,
        *,
        tenant_status: str = "active",
        principal_active: bool = True,
        membership_active: bool = True,
        role_permissions: dict[uuid.UUID, frozenset[str]] | None = None,
        bindings: list[tuple[uuid.UUID, ScopeType, uuid.UUID | None]] | None = None,
        grants: frozenset[str] | None = None,
    ) -> None:
        self.tenant_status = tenant_status
        self._principal_active = principal_active
        self._membership_active = membership_active
        self.role_permissions = role_permissions or {}
        self.bindings = bindings or []
        self.grants = grants or frozenset()

    async def tenant_status_of(self, tenant_id: uuid.UUID) -> str:
        return self.tenant_status

    async def principal_active(self, principal: Principal) -> bool:
        return self._principal_active

    async def membership_active(self, principal: Principal, tenant_id: uuid.UUID) -> bool:
        return self._membership_active

    async def bindings_for(self, principal, tenant_id, scope_chain):
        return [Binding(*b) for b in self.bindings if (b[1], b[2]) in scope_chain]

    async def permissions_for_roles(self, tenant_id, role_ids):
        return frozenset().union(
            *(self.role_permissions.get(role, frozenset()) for role in role_ids)
        )

    async def grants_for(self, principal, tenant_id, resource_type, resource_id):
        return self.grants


class _Scopes:
    def __init__(self, chain):
        self._chain = chain

    async def chain(self, session, target):
        return self._chain


def _pdp(reader, chain=_TENANT_CHAIN) -> DefaultPDP:
    return DefaultPDP(
        catalog=PermissionCatalog.with_builtins(),
        reader=reader,
        scopes=_Scopes(chain),
        cache=AuthzCache(),
    )


def _user(scopes: frozenset[str] | None = None) -> Principal:
    return Principal(kind=PrincipalKind.USER, id=USER_ID, user_id=USER_ID, scopes=scopes)


def test_cache_memoizes_until_invalidated():
    cache = AuthzCache()
    assert cache.get("k") is None
    cache.put("k", "v")
    assert cache.get("k") == "v"
    cache.invalidate()
    assert cache.get("k") is None
    cache.put("k", "v2")
    assert cache.get("k") is None


async def test_denies_when_tenant_not_active():
    decision = await _pdp(_Reader(tenant_status="suspended")).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=None,
    )
    assert decision.allowed is False
    assert decision.reason == "tenant_suspended"


async def test_denies_when_principal_inactive():
    decision = await _pdp(_Reader(principal_active=False)).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=None,
    )
    assert decision.reason == "principal_inactive"


async def test_denies_when_membership_inactive():
    decision = await _pdp(_Reader(membership_active=False)).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=None,
    )
    assert decision.reason == "membership_inactive"


async def test_allows_tenant_scope_binding():
    role_id = uuid.uuid4()
    reader = _Reader(
        bindings=[(role_id, ScopeType.TENANT, None)],
        role_permissions={role_id: frozenset({"resource:read"})},
    )
    decision = await _pdp(reader).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=_SESSION,
    )
    assert decision.allowed is True
    assert decision.matched[0].kind == "binding"


async def test_denies_without_session_for_scope_resolution():
    with pytest.raises(MissingTenantContext):
        await _pdp(_Reader()).evaluate(
            _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
            session=None,
        )


async def test_denies_without_allow():
    decision = await _pdp(_Reader()).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=_SESSION,
    )
    assert decision.allowed is False
    assert decision.reason == "no_allow"


async def test_grants_apply_only_to_the_exact_resource():
    reader = _Reader(grants=frozenset({"resource:read"}))
    decision = await _pdp(reader, chain=(ScopeRef(ScopeType.TENANT, None),)).evaluate(
        _user(),
        "resource:read",
        ResourceRef("invoice", RESOURCE_ID),
        _context(_user()),
        session=_SESSION,
    )
    assert decision.allowed is True
    assert any(rule.kind == "grant" for rule in decision.matched)


async def test_api_key_scopes_narrow_everything():
    role_id = uuid.uuid4()
    reader = _Reader(
        bindings=[(role_id, ScopeType.TENANT, None)],
        role_permissions={role_id: frozenset({"resource:read", "resource:delete"})},
        grants=frozenset({"resource:delete"}),
    )
    principal = Principal(
        kind=PrincipalKind.SERVICE_ACCOUNT,
        id=uuid.uuid4(),
        tenant_id=TENANT_ID,
        scopes=frozenset({"resource:read"}),
    )
    pdp = _pdp(reader)
    allowed = await pdp.evaluate(
        principal,
        "resource:read",
        ScopeRef(ScopeType.TENANT, None),
        _context(principal),
        session=_SESSION,
    )
    denied = await pdp.evaluate(
        principal,
        "resource:delete",
        ResourceRef("invoice", RESOURCE_ID),
        _context(principal),
        session=_SESSION,
    )
    assert allowed.allowed is True
    assert denied.allowed is False
    assert denied.reason == "outside_key_scopes"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pdp.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.authz.cache'`

- [ ] **Step 3: Implement `src/jdlib/authz/cache.py` and `src/jdlib/authz/reader.py`**

`cache.py`:

```python
from __future__ import annotations

from typing import Any


class AuthzCache:
    def __init__(self) -> None:
        self._dirty = False
        self._memo: dict[Any, Any] = {}

    def invalidate(self) -> None:
        self._dirty = True
        self._memo.clear()

    def get(self, key: Any) -> Any | None:
        return None if self._dirty else self._memo.get(key)

    def put(self, key: Any, value: Any) -> None:
        self._memo[key] = value
```

`reader.py`:

```python
from __future__ import annotations

import uuid
from collections.abc import Callable, Collection, Sequence
from typing import NamedTuple, Protocol

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import Principal, PrincipalKind
from jdlib.control.enums import ScopeType
from jdlib.control.models import Membership, ResourceGrant, RoleBinding, RolePermission
from jdlib.control.session import ControlPlaneSession


class Binding(NamedTuple):
    role_id: uuid.UUID
    scope_type: ScopeType
    scope_id: uuid.UUID | None


class AccessReader(Protocol):
    async def tenant_status_of(self, tenant_id: uuid.UUID) -> str: ...

    async def principal_active(self, principal: Principal) -> bool: ...

    async def membership_active(self, principal: Principal, tenant_id: uuid.UUID) -> bool: ...

    async def bindings_for(
        self,
        principal: Principal,
        tenant_id: uuid.UUID,
        scope_chain: Collection[tuple[ScopeType, uuid.UUID | None]],
    ) -> Sequence[Binding]: ...

    async def permissions_for_roles(
        self, tenant_id: uuid.UUID, role_ids: Collection[uuid.UUID]
    ) -> frozenset[str]: ...

    async def grants_for(
        self, principal: Principal, tenant_id: uuid.UUID, resource_type: str, resource_id: uuid.UUID
    ) -> frozenset[str]: ...


class ControlAccessReader:
    def __init__(self, session_factory: Callable[[], AsyncSession]) -> None:
        self._session_factory = session_factory

    async def _session(self) -> ControlPlaneSession:
        return ControlPlaneSession(self._session_factory())

    async def tenant_status_of(self, tenant_id: uuid.UUID) -> str:
        from jdlib.control.models import Tenant

        async with await self._session() as session:
            status = (
                await session.execute(sa.select(Tenant.status).where(Tenant.id == tenant_id))
            ).scalar_one_or_none()
        return status or "missing"

    async def principal_active(self, principal: Principal) -> bool:
        if principal.kind is PrincipalKind.USER:
            from jdlib.control.models import User

            user_id = principal.user_id if principal.user_id is not None else principal.id
            async with await self._session() as session:
                status = (
                    await session.execute(sa.select(User.status).where(User.id == user_id))
                ).scalar_one_or_none()
            return status == "active"
        from jdlib.control.models import ServiceAccount

        async with await self._session() as session:
            status = (
                await session.execute(
                    sa.select(ServiceAccount.status).where(ServiceAccount.id == principal.id)
                )
            ).scalar_one_or_none()
        return status == "active"

    async def membership_active(self, principal: Principal, tenant_id: uuid.UUID) -> bool:
        if principal.kind is PrincipalKind.SERVICE_ACCOUNT:
            return True
        user_id = principal.user_id if principal.user_id is not None else principal.id
        async with await self._session() as session:
            status = (
                await session.execute(
                    sa.select(Membership.status).where(
                        Membership.tenant_id == tenant_id,
                        Membership.user_id == user_id,
                    )
                )
            ).scalar_one_or_none()
        return status == "active"

    async def bindings_for(
        self,
        principal: Principal,
        tenant_id: uuid.UUID,
        scope_chain: Collection[tuple[ScopeType, uuid.UUID | None]],
    ) -> Sequence[Binding]:
        async with await self._session() as session:
            rows = (
                await session.execute(
                    sa.select(RoleBinding.role_id, RoleBinding.scope_type, RoleBinding.scope_id)
                    .where(
                        RoleBinding.tenant_id == tenant_id,
                        RoleBinding.principal_type == principal.kind.value,
                        RoleBinding.principal_id == principal.id,
                    )
                )
            ).all()
        chain = set(scope_chain)
        bindings: list[Binding] = []
        for role_id, scope_type, scope_id in rows:
            scope = ScopeType(scope_type)
            if (scope, scope_id) in chain:
                bindings.append(Binding(role_id, scope, scope_id))
        return bindings

    async def permissions_for_roles(
        self, tenant_id: uuid.UUID, role_ids: Collection[uuid.UUID]
    ) -> frozenset[str]:
        if not role_ids:
            return frozenset()
        async with await self._session() as session:
            rows = (
                await session.execute(
                    sa.select(RolePermission.permission_code).where(
                        RolePermission.tenant_id == tenant_id,
                        RolePermission.role_id.in_(list(role_ids)),
                    )
                )
            ).scalars().all()
        return frozenset(rows)

    async def grants_for(
        self, principal: Principal, tenant_id: uuid.UUID, resource_type: str, resource_id: uuid.UUID
    ) -> frozenset[str]:
        async with await self._session() as session:
            rows = (
                await session.execute(
                    sa.select(ResourceGrant.permission_code).where(
                        ResourceGrant.tenant_id == tenant_id,
                        ResourceGrant.resource_type == resource_type,
                        ResourceGrant.resource_id == resource_id,
                        ResourceGrant.principal_type == principal.kind.value,
                        ResourceGrant.principal_id == principal.id,
                    )
                )
            ).scalars().all()
        return frozenset(rows)
```

Note for the implementer: resolve the user id explicitly everywhere (`user_id = principal.user_id if principal.user_id is not None else principal.id`) and compare `principal.kind` against `PrincipalKind` from `jdlib.context` (`PrincipalType` is only the DB check-constraint enum; `is` across the two StrEnums is always false). `bindings_for` filters in Python against the chain; keep it (bindings per principal are few).

- [ ] **Step 4: Implement `src/jdlib/authz/pdp.py`**

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple, Protocol, cast

from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import AccessReader
from jdlib.authz.scopes import ResourceRef, ScopeResolver, Target
from jdlib.context import Principal, TenantContext
from jdlib.errors import MissingTenantContext
from jdlib.persistence.session import TenantSession


class MatchedRule(NamedTuple):
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    matched: tuple[MatchedRule, ...]


class PolicyDecisionPoint(Protocol):
    async def evaluate(
        self,
        principal: Principal,
        permission: str,
        target: Target,
        context: TenantContext,
        *,
        session: object,
    ) -> Decision: ...


class DefaultPDP:
    def __init__(
        self,
        *,
        catalog: PermissionCatalog,
        reader: AccessReader,
        scopes: ScopeResolver,
        cache: AuthzCache | None = None,
    ) -> None:
        self._catalog = catalog
        self._reader = reader
        self._scopes = scopes
        self._cache = cache or AuthzCache()

    async def evaluate(
        self,
        principal: Principal,
        permission: str,
        target: Target,
        context: TenantContext,
        *,
        session: object,
    ) -> Decision:
        self._catalog.validate(permission)
        tenant_id = context.tenant_id
        if await self._reader.tenant_status_of(tenant_id) != "active":
            return Decision(False, "tenant_suspended", ())
        if not await self._reader.principal_active(principal):
            return Decision(False, "principal_inactive", ())
        if not await self._reader.membership_active(principal, tenant_id):
            return Decision(False, "membership_inactive", ())
        if session is None:
            raise MissingTenantContext("PDP requires a tenant session for scope resolution")
        chain = await self._scopes.chain(cast(TenantSession, session), target)
        scope_chain = {(scope.type, scope.id) for scope in chain}
        bindings = await self._reader.bindings_for(principal, tenant_id, scope_chain)
        role_perms = await self._reader.permissions_for_roles(
            tenant_id, [binding.role_id for binding in bindings]
        )
        matched = [
            MatchedRule("binding", f"role {binding.role_id} at {binding.scope_type.value}")
            for binding in bindings
            if permission in role_perms
        ]
        granted: frozenset[str] = frozenset()
        if isinstance(target, ResourceRef):
            granted = await self._reader.grants_for(
                principal, tenant_id, target.resource_type, target.resource_id
            )
            if permission in granted:
                matched.append(
                    MatchedRule("grant", f"{target.resource_type}:{target.resource_id}")
                )
        base = role_perms | granted
        if principal.scopes is not None:
            if permission not in principal.scopes:
                return Decision(False, "outside_key_scopes", tuple(matched))
            base = base & principal.scopes
        if permission in base:
            return Decision(True, "allowed", tuple(matched))
        return Decision(False, "no_allow", tuple(matched))
```

- [ ] **Step 5: Run unit tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pdp.py -v -W error`
Expected: PASS (9 passed)

- [ ] **Step 6: Integration test for `ControlAccessReader`**

`tests/integration/test_pdp_control_reader.py`:

```python
import uuid

from jdlib.authz.reader import ControlAccessReader
from jdlib.context import Principal, PrincipalKind
from jdlib.control.enums import ScopeType
from jdlib.control.models import (
    Membership,
    ResourceGrant,
    Role,
    RoleBinding,
    RolePermission,
    ServiceAccount,
    Tenant,
    User,
)


async def test_control_reader_reads_status_bindings_and_permissions(
    control_session_factory,
):
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    role_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"authz-{tenant_id.hex[:8]}", name="A", status="active")
        )
        await session.commit()

    async with control_session_factory() as session:
        session.add(User(id=user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=role_id, name="member"))
        await session.flush()
        session.add(
            Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=user_id, status="active")
        )
        session.add(
            RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code="resource:read")
        )
        session.add(
            RoleBinding(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                role_id=role_id,
                principal_type="user",
                principal_id=user_id,
                scope_type="tenant",
            )
        )
        await session.commit()

    reader = ControlAccessReader(control_session_factory)
    principal = Principal(kind=PrincipalKind.USER, id=user_id, user_id=user_id)
    assert await reader.tenant_status_of(tenant_id) == "active"
    assert await reader.principal_active(principal) is True
    assert await reader.membership_active(principal, tenant_id) is True
    bindings = await reader.bindings_for(principal, tenant_id, {(ScopeType.TENANT, None)})
    assert [binding.role_id for binding in bindings] == [role_id]
    assert await reader.permissions_for_roles(tenant_id, [role_id]) == frozenset({"resource:read"})
    assert await reader.grants_for(principal, tenant_id, "invoice", uuid.uuid4()) == frozenset()


async def test_control_reader_handles_service_accounts_and_grants(control_session_factory):
    tenant_id = uuid.uuid4()
    account_id = uuid.uuid4()
    resource_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"authz-{tenant_id.hex[:8]}", name="B", status="active")
        )
        await session.commit()

    async with control_session_factory() as session:
        session.add(
            ServiceAccount(tenant_id=tenant_id, id=account_id, name="bot", status="active")
        )
        session.add(
            ResourceGrant(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                resource_type="invoice",
                resource_id=resource_id,
                principal_type="service_account",
                principal_id=account_id,
                permission_code="resource:read",
            )
        )
        await session.commit()

    reader = ControlAccessReader(control_session_factory)
    principal = Principal(kind=PrincipalKind.SERVICE_ACCOUNT, id=account_id, tenant_id=tenant_id)
    assert await reader.principal_active(principal) is True
    assert await reader.membership_active(principal, tenant_id) is True
    assert await reader.grants_for(principal, tenant_id, "invoice", resource_id) == frozenset(
        {"resource:read"}
    )
```

Note: the `control_session_factory` fixture creates the control tables; use a unique tenant id per test to stay idempotent. Commit the `Tenant` before inserting rows that reference it (control models declare bare FKs, so flush order is not dependency-sorted), and flush `User`/`Role` before their dependents. `DefaultPDP` asserts a session is present before scope resolution, so unit tests that reach the scope chain pass a non-`None` session stand-in while the precedence-denial tests keep `session=None` to prove no session is touched. `DefaultPDP.evaluate` keeps the `session: object` protocol signature and `cast`s to `TenantSession` after the guard.

- [ ] **Step 7: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authz tests/unit/test_pdp.py tests/integration/test_pdp_control_reader.py
git commit -m "feat: authz cache, control-plane access reader, and default PDP"
```

---

### Task 5: Enforcer, `requires`, `authorize`

**Files:**
- Create: `src/jdlib/authz/guards.py`
- Create: `tests/unit/test_guards.py`

**Interfaces:**
- Consumes: `DefaultPDP`, `Decision`, `ScopeRef`, `Target`, `TenantContext`, `current_tenant`, errors.
- Produces: `Enforcer(pdp)` with `async require(permission, target, *, session) -> Decision` (raises `PermissionDenied`); `requires(permission, *, target_factory=None)` decorator for async callables taking a `target` keyword or positional; `tenant_target()` helper.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_guards.py`:

```python
import uuid

import pytest

from jdlib.authz.guards import Enforcer, requires
from jdlib.authz.pdp import Decision
from jdlib.authz.scopes import ScopeRef
from jdlib.control.enums import ScopeType
from jdlib.errors import PermissionDenied


class _PDP:
    def __init__(self, allowed: bool) -> None:
        self.allowed = allowed
        self.calls: list[tuple[str, ScopeRef]] = []

    async def evaluate(self, principal, permission, target, context, *, session):
        self.calls.append((permission, target))
        return Decision(self.allowed, "allowed" if self.allowed else "no_allow", ())


async def test_require_raises_when_denied():
    enforcer = Enforcer(_PDP(False))
    with pytest.raises(PermissionDenied):
        await enforcer.require("resource:read", ScopeRef(ScopeType.TENANT, None), session=None)


async def test_require_returns_decision_when_allowed():
    enforcer = Enforcer(_PDP(True))
    decision = await enforcer.require(
        "resource:read", ScopeRef(ScopeType.TENANT, None), session=None
    )
    assert decision.allowed is True


async def test_requires_decorator_checks_before_calling():
    pdp = _PDP(True)
    enforcer = Enforcer(pdp)

    @requires("resource:read", enforcer=enforcer)
    async def handler(*, session=None) -> str:
        return "ok"

    assert await handler(session=None) == "ok"
    assert pdp.calls[0][0] == "resource:read"


async def test_requires_decorator_raises_when_denied():
    enforcer = Enforcer(_PDP(False))

    @requires("resource:read", enforcer=enforcer)
    async def handler(*, session=None) -> str:
        raise AssertionError("must not run")

    with pytest.raises(PermissionDenied):
        await handler(session=None)


async def test_target_factory_receives_kwargs():
    pdp = _PDP(True)
    enforcer = Enforcer(pdp)

    @requires(
        "resource:read",
        enforcer=enforcer,
        target_factory=lambda resource_id, **_: ScopeRef(ScopeType.TEAM, resource_id),
    )
    async def handler(*, resource_id: uuid.UUID, session=None) -> str:
        return "ok"

    await handler(resource_id=uuid.UUID(int=7), session=None)
    assert pdp.calls[0][1] == ScopeRef(ScopeType.TEAM, uuid.UUID(int=7))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_guards.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.authz.guards'`

- [ ] **Step 3: Implement `src/jdlib/authz/guards.py`**

```python
from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from jdlib.authz.pdp import Decision, PolicyDecisionPoint
from jdlib.authz.scopes import ScopeRef, Target
from jdlib.context import current_tenant
from jdlib.control.enums import ScopeType
from jdlib.errors import PermissionDenied

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


def tenant_target() -> ScopeRef:
    return ScopeRef(ScopeType.TENANT, None)


class Enforcer:
    def __init__(self, pdp: PolicyDecisionPoint) -> None:
        self._pdp = pdp

    async def require(self, permission: str, target: Target, *, session: object) -> Decision:
        context = current_tenant()
        decision = await self._pdp.evaluate(
            context.principal, permission, target, context, session=session
        )
        if not decision.allowed:
            raise PermissionDenied(f"{permission}: {decision.reason}")
        return decision


def requires(
    permission: str,
    *,
    enforcer: Enforcer,
    target_factory: Callable[..., Target] | None = None,
) -> Callable[[F], F]:
    def decorate(fn: F) -> F:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            if target_factory is None:
                target: Target = tenant_target()
            else:
                target = target_factory(*args, **kwargs)
            await enforcer.require(permission, target, session=kwargs.get("session"))
            return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate


async def authorize(
    permission: str, target: Target, *, enforcer: Enforcer, session: object
) -> Decision:
    return await enforcer.require(permission, target, session=session)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_guards.py -v -W error`
Expected: PASS (5 passed)

- [ ] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authz/guards.py tests/unit/test_guards.py
git commit -m "feat: authorization enforcer and guard decorator"
```

---

## Phase 4b Exit Criteria

- [ ] Full suite green on real PostgreSQL 16.
- [ ] Catalog and resource registry enforce unknown/duplicate/namespace rules.
- [ ] Scope chains: tenant; org ancestors via tenant-scoped ORM traversal (nearest→root, cycle-guarded); team → org → ancestors; resource → ownership chain.
- [ ] PDP precedence chain and effective-permission algorithm (bindings ∪ grants, ∩ key scopes) proven by tests, including the API-key narrowing case.
- [ ] `Enforcer`/`requires` raise `PermissionDenied` and never call the guarded function on denial.
- [ ] `ruff` and strict `mypy` clean.

## Plan Series (remaining)

- Plan 4c — access control management: `AccessControl` (roles, bindings, grants, invitations, ownership transfer) with L14/L16 validations, audit, and cache invalidation.
- Plan 4d — authentication adapters: OIDC/JWT and API keys, plus `ContextFactory` wiring.
- Plan 5 — Phases 7–9: schema and database strategies, RLS emission and tests.
- Plan 6 — Phase 10: audit sinks, `jdlib.testing`, FastAPI/CLI integrations, docs.
