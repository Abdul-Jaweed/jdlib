# jdlib Access Control Management (Phase 4c) Implementation Plan

**Status: complete — all steps executed, reviewed, merged to main.**

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Build `AccessControl`: role management, role bindings with scope compatibility, resource grants with namespace validation, invitations with hashed single-use tokens, ownership transfer, anti-escalation enforcement, mandatory audit, and conservative `AuthzCache` invalidation — plus the frozen role × action matrix test.

**Architecture:** `AccessControl` writes control-plane rows through `ControlPlaneSession`, reads the actor's own authority through the existing `AccessReader` (subset/anti-escalation checks), validates tenant-plane targets through a caller-supplied `TenantSession`, audits through `PlatformAudit`, and invalidates a shared `AuthzCache` **before** every mutation. No new dependencies.

**Specs (frozen):** `docs/jdlib/04-authorization-model.md` §4 (anti-escalation), §5 (ownership transfer), §8 (role templates + matrix); `docs/jdlib/02-relational-schema.md` §3.10–3.14; `03` I11; `05` §5.1 (audit ordering).

## Global Constraints

- All validations from `04` §4: catalog-validated codes; role subset rule; binding subset rule; system roles immutable; roles with bindings cannot be deleted; owner cannot be removed; grant requires the granted permission plus `resource:share`; namespace compatibility.
- `AccessControl` invalidates the shared `AuthzCache` **before** mutating; audit is recorded before commit (fail-closed); mutations are idempotent where the frozen docs say so (grants).
- Invitation tokens: `inv_<token_id>_<secret>`, single-use, Argon2id hash at rest, `token_id` deterministic lookup; acceptance creates `Membership` + `RoleBinding` atomically.
- Commands: `.venv/Scripts/python -m pytest ...`, `ruff check .`, `mypy src/jdlib`; integration tests need `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` and a fresh DB.
- No comments in source; pristine test output; commit after every task.

---

### Task 1: Roles with anti-escalation

**Files:**
- Create: `src/jdlib/authz/access.py`
- Create: `tests/integration/test_access_roles.py`

**Interfaces:**
- Consumes: `ControlPlaneSession`, `PermissionCatalog`, `AccessReader`, `AuthzCache`, `PlatformAudit`, `Role`, `RolePermission`, `RoleBinding`, `Invitation`.
- Produces: `AccessControl(session_factory, *, catalog, reader, cache, audit)`; `async create_role(tenant_id, name, permissions, *, actor_id, actor_principal, is_system=False) -> Role`; `async update_role(tenant_id, role_id, permissions, *, actor_id, actor_principal) -> Role`; `async delete_role(tenant_id, role_id, *, actor_id, actor_principal) -> None`; `async actor_permissions(tenant_id, principal) -> frozenset[str]`.

- [x] **Step 1: Write the failing tests**

`tests/integration/test_access_roles.py`:

```python
import uuid

import pytest

from jdlib.authz.access import AccessControl
from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.context import Principal, PrincipalKind
from jdlib.control.models import Membership, Role, RoleBinding, RolePermission, Tenant, User
from jdlib.errors import AuthorizationError, UnknownPermission


def _principal(role: str) -> Principal:
    return Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())


async def _tenant(control_session_factory) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"ac-{tenant_id.hex[:8]}", name="AC", status="active")
        )
        await session.commit()
    return tenant_id


async def _seed_actor(control_session_factory, tenant_id: uuid.UUID, permissions: set[str]):
    actor = _principal("owner")
    role_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=actor.user_id, status="active"))
        session.add(
            Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=actor.user_id, status="active")
        )
        session.add(Role(tenant_id=tenant_id, id=role_id, name=f"owner-{role_id.hex[:6]}"))
        for code in permissions:
            session.add(
                RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code=code)
            )
        session.add(
            RoleBinding(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                role_id=role_id,
                principal_type="user",
                principal_id=actor.user_id,
                scope_type="tenant",
            )
        )
        await session.commit()
    return actor


def _access(control_session_factory, catalog=None) -> tuple[AccessControl, RecordingPlatformAudit]:
    audit = RecordingPlatformAudit()
    cache = AuthzCache()
    control = AccessControl(
        session_factory=control_session_factory,
        catalog=catalog or PermissionCatalog.with_builtins(),
        reader=ControlAccessReader(control_session_factory),
        cache=cache,
        audit=audit,
    )
    return control, audit


async def test_create_role_requires_holding_every_permission(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(control_session_factory, tenant_id, {"resource:read"})
    control, audit = _access(control_session_factory)
    role = await control.create_role(
        tenant_id,
        "reader",
        {"resource:read"},
        actor_id=actor.user_id,
        actor_principal=actor,
    )
    assert role.name == "reader"
    assert audit.entries[-1]["action"] == "role.created"
    with pytest.raises(AuthorizationError):
        await control.create_role(
            tenant_id,
            "escalated",
            {"resource:read", "tenant:manage"},
            actor_id=actor.user_id,
            actor_principal=actor,
        )


async def test_create_role_rejects_unknown_permission(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(control_session_factory, tenant_id, {"resource:read"})
    control, _ = _access(control_session_factory)
    with pytest.raises(UnknownPermission):
        await control.create_role(
            tenant_id, "bad", {"mystery:do"}, actor_id=actor.user_id, actor_principal=actor
        )


async def test_update_role_revalidates_subset_and_invalidates_cache(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(
        control_session_factory, tenant_id, {"resource:read", "resource:update"}
    )
    control, _ = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "editor", {"resource:read"}, actor_id=actor.user_id, actor_principal=actor
    )
    updated = await control.update_role(
        tenant_id,
        role.id,
        {"resource:read", "resource:update"},
        actor_id=actor.user_id,
        actor_principal=actor,
    )
    assert updated.id == role.id
    with pytest.raises(AuthorizationError):
        await control.update_role(
            tenant_id,
            role.id,
            {"tenant:manage"},
            actor_id=actor.user_id,
            actor_principal=actor,
        )


async def test_delete_role_blocked_while_bindings_exist(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(control_session_factory, tenant_id, {"resource:read"})
    control, _ = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "temp", {"resource:read"}, actor_id=actor.user_id, actor_principal=actor
    )
    member = _principal("member")
    async with control_session_factory() as session:
        session.add(User(id=member.user_id, status="active"))
        session.add(
            Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=member.user_id, status="active")
        )
        await session.commit()
    await control.bind_role(
        tenant_id,
        role.id,
        principal_type="user",
        principal_id=member.user_id,
        scope_type="tenant",
        scope_id=None,
        actor_id=actor.user_id,
        actor_principal=actor,
    )
    with pytest.raises(AuthorizationError):
        await control.delete_role(tenant_id, role.id, actor_id=actor.user_id, actor_principal=actor)


async def test_system_roles_are_immutable(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(control_session_factory, tenant_id, {"resource:read"})
    control, _ = _access(control_session_factory)
    role = await control.create_role(
        tenant_id,
        "builtin",
        {"resource:read"},
        actor_id=actor.user_id,
        actor_principal=actor,
        is_system=True,
    )
    with pytest.raises(AuthorizationError):
        await control.update_role(
            tenant_id, role.id, {"resource:read"}, actor_id=actor.user_id, actor_principal=actor
        )
    with pytest.raises(AuthorizationError):
        await control.delete_role(tenant_id, role.id, actor_id=actor.user_id, actor_principal=actor)
```

- [x] **Step 2: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_access_roles.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.authz.access'`

- [x] **Step 3: Implement `src/jdlib/authz/access.py` (roles portion)**

```python
from __future__ import annotations

import uuid
from collections.abc import Callable, Collection
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import AccessReader
from jdlib.authz.resource_types import ResourceTypeRegistry
from jdlib.control.audit import PlatformAudit
from jdlib.control.models import (
    Invitation,
    Membership,
    Role,
    RoleBinding,
    RolePermission,
    ServiceAccount,
    User,
)
from jdlib.control.session import ControlPlaneSession
from jdlib.context import Principal
from jdlib.control.enums import PrincipalType
from jdlib.errors import AuthorizationError, InvalidReference, RoleEscalationBlocked


class AccessControl:
    def __init__(
        self,
        *,
        session_factory: Callable[[], AsyncSession],
        catalog: PermissionCatalog,
        reader: AccessReader,
        cache: AuthzCache,
        audit: PlatformAudit,
        registry: ResourceTypeRegistry | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._catalog = catalog
        self._reader = reader
        self._cache = cache
        self._audit = audit
        self._registry = registry or ResourceTypeRegistry()

    async def _session(self) -> ControlPlaneSession:
        return ControlPlaneSession(self._session_factory())

    async def actor_permissions(self, tenant_id: uuid.UUID, principal: Principal) -> frozenset[str]:
        from jdlib.control.enums import ScopeType

        bindings = await self._reader.bindings_for(
            principal, tenant_id, {(ScopeType.TENANT, None)}
        )
        by_role = await self._reader.permissions_by_role(
            tenant_id, [binding.role_id for binding in bindings]
        )
        return frozenset().union(*by_role.values()) if by_role else frozenset()

    async def _require_subset(
        self, tenant_id: uuid.UUID, permissions: Collection[str], principal: Principal
    ) -> None:
        held = await self.actor_permissions(tenant_id, principal)
        missing = set(permissions) - held
        if missing:
            raise RoleEscalationBlocked(f"missing permissions: {sorted(missing)}")

    def _validate_codes(self, permissions: Collection[str]) -> None:
        for code in permissions:
            self._catalog.validate(code)

    async def create_role(
        self,
        tenant_id: uuid.UUID,
        name: str,
        permissions: Collection[str],
        *,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
        is_system: bool = False,
    ) -> Role:
        self._validate_codes(permissions)
        await self._require_subset(tenant_id, permissions, actor_principal)
        self._cache.invalidate()
        async with await self._session() as session:
            existing = (
                await session.execute(
                    sa.select(Role).where(Role.tenant_id == tenant_id, Role.name == name)
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise AuthorizationError(f"role already exists: {name}")
            role = Role(tenant_id=tenant_id, name=name, is_system=is_system)
            session.add(role)
            await session.flush()
            for code in permissions:
                session.add(
                    RolePermission(
                        tenant_id=tenant_id, role_id=role.id, permission_code=code
                    )
                )
            await self._audit.record(
                action="role.created",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"role_id": str(role.id), "name": name},
            )
            await session.commit()
            return role

    async def update_role(
        self,
        tenant_id: uuid.UUID,
        role_id: uuid.UUID,
        permissions: Collection[str],
        *,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> Role:
        self._validate_codes(permissions)
        await self._require_subset(tenant_id, permissions, actor_principal)
        self._cache.invalidate()
        async with await self._session() as session:
            role = await session.get(Role, {"tenant_id": tenant_id, "id": role_id})
            if role is None:
                raise InvalidReference(f"role not found: {role_id}")
            if role.is_system:
                raise AuthorizationError("system roles are immutable")
            await session.execute(
                sa.delete(RolePermission).where(
                    RolePermission.tenant_id == tenant_id, RolePermission.role_id == role_id
                )
            )
            for code in permissions:
                session.add(
                    RolePermission(
                        tenant_id=tenant_id, role_id=role_id, permission_code=code
                    )
                )
            await self._audit.record(
                action="role.permissions_changed",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"role_id": str(role_id), "permissions": sorted(permissions)},
            )
            await session.commit()
            return role

    async def delete_role(
        self,
        tenant_id: uuid.UUID,
        role_id: uuid.UUID,
        *,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> None:
        self._cache.invalidate()
        async with await self._session() as session:
            role = await session.get(Role, {"tenant_id": tenant_id, "id": role_id})
            if role is None:
                raise InvalidReference(f"role not found: {role_id}")
            if role.is_system:
                raise AuthorizationError("system roles are immutable")
            bindings = (
                await session.execute(
                    sa.select(sa.func.count()).select_from(RoleBinding).where(
                        RoleBinding.tenant_id == tenant_id, RoleBinding.role_id == role_id
                    )
                )
            ).scalar_one()
            invitations = (
                await session.execute(
                    sa.select(sa.func.count()).select_from(Invitation).where(
                        Invitation.tenant_id == tenant_id,
                        Invitation.role_id == role_id,
                    )
                )
            ).scalar_one()
            if bindings or invitations:
                raise AuthorizationError("role has bindings or invitations")
            await session.execute(
                sa.delete(RolePermission).where(
                    RolePermission.tenant_id == tenant_id, RolePermission.role_id == role_id
                )
            )
            await session.delete(role)
            await self._audit.record(
                action="role.deleted",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"role_id": str(role_id)},
            )
            await session.commit()
```

Note for the implementer: `session.get(Role, {"tenant_id": ..., "id": ...})` is valid SQLAlchemy 2.0 composite-PK lookup; keep it. `bind_role` is referenced by the tests but implemented in Task 2 — add the full Task 2 method in this file in the same commit? No: implement `bind_role` in Task 2; for Task 1 tests, the delete test calls `bind_role`, so implement a minimal working `bind_role` in Task 1 (the Task 2 code) or move that test to Task 2. Simplest: include the Task 2 `bind_role` implementation in Task 1 as well (same file, same commit), and Task 2 focuses on scope compatibility and principal validation tests. Coordinate accordingly.

- [x] **Step 4: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_access_roles.py -v -W error`
Expected: PASS (5 passed)

- [x] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authz/access.py tests/integration/test_access_roles.py
git commit -m "feat: access control roles with anti-escalation"
```

**Review fixes applied (follow-up commit):**

- Key-scope narrowing: `actor_permissions` intersects the role-permission union with `principal.scopes` when scopes are set (04 §3 rule 7).
- Escalation errors: `_require_subset` raises `RoleEscalationBlocked` (message unchanged; existing `AuthorizationError` assertions hold by inheritance).
- Audit diff: `update_role` reads the existing codes before replacing and records `added`/`removed` in `role.permissions_changed`.
- Terminal invitations: `delete_role` blocks on any invitation row referencing the role (accepted/expired/revoked included), not only `pending`.
- Canonical principal id back-port: `ControlAccessReader` keys all principal-owned lookups (bindings, grants, activity, membership) through `principal_key()` — USER: `user_id if user_id is not None else id`; SERVICE_ACCOUNT: `id` — so envelope/job reconstruction, which carries only `id`, resolves via `id` today (carrying `user_id` on the envelope for USER principals whose `id` differs from their `user_id` is a future addition).

**Deferred (assigned, no code in Task 1):** rule 7 owner-only assignment and last-owner protection, plus the `role:manage` gate on role mutations, are Task 2 work; the `PlatformAudit` write sharing the mutation transaction is convention only (no same-transaction guarantee) — tracked for Plan 6 audit sinks.

---

### Task 2: Bindings with scope compatibility

**Files:**
- Modify: `src/jdlib/authz/access.py` (append `bind_role`, `unbind_role`)
- Create: `tests/integration/test_access_bindings.py`

> Authoritative implementation note: the shipped code and tests in commits
> `0bace18` and `b15ab8e` supersede the Step 1 snippet below wherever they
> differ (`AccessControl` gains `scope_lookup` and `_catalog_codes`; the team
> scope test seeds a real team; the file contains 14 tests). Regenerate from
> git, not from the stale snippet.

**Interfaces:**
- Produces: `bind_role(tenant_id, role_id, *, principal_type, principal_id, scope_type, scope_id, actor_id, actor_principal) -> RoleBinding`; `unbind_role(tenant_id, binding_id, *, actor_id, actor_principal) -> None`; optional `AccessControl(scope_lookup=ScopeLookup)` for org/team scope validation (I11/L14).

**Additional required work (from Task 1 review — spec-mandated, must be in this task):**
- `role:manage` gate: every role/binding mutation (`create_role`, `update_role`, `delete_role`, `bind_role`, `unbind_role`) must call a `_require_permission(tenant_id, "role:manage", actor_principal)` helper that raises `AuthorizationError` when the actor lacks it (seed `role:manage` in test harnesses accordingly; owner template includes it).
- Rule 7 (owner protection): `bind_role` may assign a role named `owner` only when the actor holds the full catalog (`len(actor_permissions) == len(catalog.all())`), else `AuthorizationError`; `unbind_role` must refuse to remove the tenant's last active `owner` binding (`AuthorizationError("cannot remove the last owner")`). Add tests for both.
- Task 1 review minors to close here: positive `delete_role` path test (no bindings/invitations; assert `role.deleted` audit); tighten the update-escalation test to `RoleEscalationBlocked`; qualify `07`'s envelope claim (USER `id != user_id` resolves via `id` today; envelope `user_id` is a future addition) or track it.
- Sync the Task 1 plan body with the shipped code (remove the stale `AuthorizationError("missing permissions…")` snippet and the `status == "pending"` filter) so regenerators get the fixed behavior.

- [x] **Step 1: Write the failing tests**

`tests/integration/test_access_bindings.py`:

```python
import uuid

import pytest

from jdlib.authz.access import AccessControl
from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.context import PrincipalKind
from jdlib.control.models import Membership, Role, RoleBinding, RolePermission, ServiceAccount, Tenant, User
from jdlib.context import Principal
from jdlib.errors import AuthorizationError, CrossTenantReferenceError, RoleScopeMismatch
from jdlib.models.org import Organization


def _access(control_session_factory) -> AccessControl:
    return AccessControl(
        session_factory=control_session_factory,
        catalog=PermissionCatalog.with_builtins(),
        reader=ControlAccessReader(control_session_factory),
        cache=AuthzCache(),
        audit=RecordingPlatformAudit(),
    )


async def _tenant(control_session_factory) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(Tenant(id=tenant_id, slug=f"bd-{tenant_id.hex[:8]}", name="BD", status="active"))
        await session.commit()
    return tenant_id


async def _owner(control_session_factory, tenant_id: uuid.UUID) -> tuple[Principal, uuid.UUID]:
    owner = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    role_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=owner.user_id, status="active"))
        session.add(Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=owner.user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=role_id, name=f"owner-{role_id.hex[:6]}"))
        for code in ("tenant:manage", "member:manage", "role:manage", "org:manage",
                     "team:manage", "resource:read", "resource:share"):
            session.add(RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code=code))
        session.add(
            RoleBinding(tenant_id=tenant_id, id=uuid.uuid4(), role_id=role_id,
                        principal_type="user", principal_id=owner.user_id, scope_type="tenant")
        )
        await session.commit()
    return owner, role_id


async def test_tenant_permission_cannot_be_team_scoped(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "tenant-admin", {"tenant:manage"},
        actor_id=owner.user_id, actor_principal=owner,
    )
    member = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    async with control_session_factory() as session:
        session.add(User(id=member.user_id, status="active"))
        session.add(Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=member.user_id, status="active"))
        await session.commit()
    with pytest.raises(RoleScopeMismatch):
        await control.bind_role(
            tenant_id, role.id, principal_type="user", principal_id=member.user_id,
            scope_type="team", scope_id=uuid.uuid4(), actor_id=owner.user_id,
            actor_principal=owner,
        )


async def test_binding_requires_active_membership_and_same_tenant(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    other_tenant = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "reader", {"resource:read"}, actor_id=owner.user_id, actor_principal=owner
    )
    stranger = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    async with control_session_factory() as session:
        session.add(User(id=stranger.user_id, status="active"))
        await session.commit()
    with pytest.raises(CrossTenantReferenceError):
        await control.bind_role(
            tenant_id, role.id, principal_type="user", principal_id=stranger.user_id,
            scope_type="tenant", scope_id=None, actor_id=owner.user_id, actor_principal=owner,
        )


async def test_bind_and_unbind_roundtrip(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "member", {"resource:read"}, actor_id=owner.user_id, actor_principal=owner
    )
    member = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    async with control_session_factory() as session:
        session.add(User(id=member.user_id, status="active"))
        session.add(Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=member.user_id, status="active"))
        await session.commit()
    binding = await control.bind_role(
        tenant_id, role.id, principal_type="user", principal_id=member.user_id,
        scope_type="tenant", scope_id=None, actor_id=owner.user_id, actor_principal=owner,
    )
    assert binding.scope_type == "tenant"
    await control.unbind_role(
        tenant_id, binding.id, actor_id=owner.user_id, actor_principal=owner
    )
    async with control_session_factory() as session:
        remaining = (
            await session.execute(
                sa.select(RoleBinding).where(RoleBinding.id == binding.id)
            )
        ).scalar_one_or_none()
    assert remaining is None


async def test_binding_requires_holding_the_role_permissions(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "manager", {"tenant:manage"},
        actor_id=owner.user_id, actor_principal=owner,
    )
    weak = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    weak_role = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=weak.user_id, status="active"))
        session.add(Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=weak.user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=weak_role, name=f"weak-{weak_role.hex[:6]}"))
        session.add(RolePermission(tenant_id=tenant_id, role_id=weak_role, permission_code="resource:read"))
        session.add(
            RoleBinding(tenant_id=tenant_id, id=uuid.uuid4(), role_id=weak_role,
                        principal_type="user", principal_id=weak.user_id, scope_type="tenant")
        )
        await session.commit()
    member = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    async with control_session_factory() as session:
        session.add(User(id=member.user_id, status="active"))
        session.add(Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=member.user_id, status="active"))
        await session.commit()
    with pytest.raises(AuthorizationError):
        await control.bind_role(
            tenant_id, role.id, principal_type="user", principal_id=member.user_id,
            scope_type="tenant", scope_id=None, actor_id=weak.user_id, actor_principal=weak,
        )
```

Add `import sqlalchemy as sa` at the top of the test file.

- [x] **Step 2: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_access_bindings.py -v`
Expected: FAIL (missing methods)

- [x] **Step 3: Implement `bind_role`/`unbind_role` in `src/jdlib/authz/access.py`**

```python
@dataclass(frozen=True, slots=True)
class ScopeRecord:
    """Ownership facts about an org/team scope row (tenant plane)."""

    tenant_id: uuid.UUID
    deleted: bool = False


class ScopeLookup(Protocol):
    """Resolves an org/team scope id to its owning tenant.

    Returns ``None`` when no row with the given id exists anywhere;
    otherwise the owning tenant and whether the row is soft-deleted.
    """

    async def __call__(
        self, tenant_id: uuid.UUID, scope_type: str, scope_id: uuid.UUID
    ) -> ScopeRecord | None: ...


    async def bind_role(
        self,
        tenant_id: uuid.UUID,
        role_id: uuid.UUID,
        *,
        principal_type: str,
        principal_id: uuid.UUID,
        scope_type: str,
        scope_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> RoleBinding:
        held = await self._require_permission(tenant_id, "role:manage", actor_principal)
        try:
            scope = ScopeType(scope_type)
        except ValueError as exc:
            raise InvalidReference(f"unsupported scope type: {scope_type}") from exc
        if scope is ScopeType.TENANT:
            if scope_id is not None:
                raise InvalidReference("tenant scope must not carry a scope id")
        elif scope_id is None:
            raise InvalidReference(f"{scope_type} scope requires a scope id")
        else:
            await self._validate_scope(tenant_id, scope.value, scope_id)
        async with await self._session() as session:
            role = await session.get(Role, {"tenant_id": tenant_id, "id": role_id})
            if role is None:
                raise InvalidReference(f"role not found: {role_id}")
            if role.name == "owner" and not self._catalog_codes <= held:
                raise AuthorizationError("only a full-catalog actor may assign the owner role")
            codes = (
                await session.execute(
                    sa.select(RolePermission.permission_code).where(
                        RolePermission.tenant_id == tenant_id, RolePermission.role_id == role_id
                    )
                )
            ).scalars().all()
            for code in codes:
                permission = self._catalog.validate(code)
                if scope not in permission.allowed_scopes:
                    raise RoleScopeMismatch(f"{code} cannot be bound at {scope_type} scope")
            await self._validate_principal(session, tenant_id, principal_type, principal_id)
        await self._require_subset(tenant_id, codes, actor_principal)
        self._cache.invalidate()
        async with await self._session() as session:
            binding = RoleBinding(
                tenant_id=tenant_id,
                role_id=role_id,
                principal_type=principal_type,
                principal_id=principal_id,
                scope_type=scope_type,
                scope_id=scope_id,
                created_by=actor_id,
            )
            session.add(binding)
            await self._audit.record(
                action="binding.created",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={
                    "role_id": str(role_id),
                    "principal_id": str(principal_id),
                    "scope": f"{scope_type}:{scope_id}",
                },
            )
            await session.commit()
            return binding

    async def _validate_principal(
        self,
        session: ControlPlaneSession,
        tenant_id: uuid.UUID,
        principal_type: str,
        principal_id: uuid.UUID,
    ) -> None:
        if principal_type == "service_account":
            account = await session.get(
                ServiceAccount, {"tenant_id": tenant_id, "id": principal_id}
            )
            if account is None or account.status != "active":
                raise CrossTenantReferenceError(
                    "service_account", str(tenant_id), str(principal_id)
                )
            return
        membership = (
            await session.execute(
                sa.select(Membership).where(
                    Membership.tenant_id == tenant_id,
                    Membership.user_id == principal_id,
                    Membership.status == "active",
                )
            )
        ).scalar_one_or_none()
        if membership is None:
            raise CrossTenantReferenceError("membership", str(tenant_id), str(principal_id))

    async def _validate_scope(
        self, tenant_id: uuid.UUID, scope_type: str, scope_id: uuid.UUID
    ) -> None:
        if self._scope_lookup is None:
            raise AuthorizationError(f"{scope_type} scope validation is not configured")
        record = await self._scope_lookup(tenant_id, scope_type, scope_id)
        if record is None:
            raise InvalidReference(f"{scope_type} scope not found: {scope_id}")
        if record.tenant_id != tenant_id or record.deleted:
            raise CrossTenantReferenceError(
                f"{scope_type} scope {scope_id}", str(tenant_id), str(record.tenant_id)
            )

    async def _lock(self, session: ControlPlaneSession, tenant_id: uuid.UUID) -> None:
        await session.execute(
            sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))").bindparams(
                key=f"jdlib:tenant:{tenant_id}"
            )
        )

    async def unbind_role(
        self,
        tenant_id: uuid.UUID,
        binding_id: uuid.UUID,
        *,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> None:
        await self._require_permission(tenant_id, "role:manage", actor_principal)
        self._cache.invalidate()
        async with await self._session() as session:
            await self._lock(session, tenant_id)
            binding = await session.get(
                RoleBinding, {"tenant_id": tenant_id, "id": binding_id}
            )
            if binding is None:
                raise InvalidReference(f"binding not found: {binding_id}")
            role = await session.get(Role, {"tenant_id": tenant_id, "id": binding.role_id})
            if role is not None and role.name == "owner":
                remaining = (
                    await session.execute(
                        sa.select(sa.func.count())
                        .select_from(RoleBinding)
                        .join(
                            Role,
                            sa.and_(
                                Role.tenant_id == RoleBinding.tenant_id,
                                Role.id == RoleBinding.role_id,
                            ),
                        )
                        .where(
                            RoleBinding.tenant_id == tenant_id,
                            Role.name == "owner",
                            RoleBinding.id != binding_id,
                        )
                    )
                ).scalar_one()
                if remaining == 0:
                    raise AuthorizationError("cannot remove the last owner")
            await session.delete(binding)
            await self._audit.record(
                action="binding.removed",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"binding_id": str(binding_id)},
            )
            await session.commit()
```

Note for the implementer: `ScopeType` is imported at module top; scope shape validation is hoisted. `bind_role` opens two sessions (validation then write) — accepted TOCTOU debt, see the review-fix block below. `scope_lookup` is an optional constructor collaborator: absent, org/team scopes fail closed. Add `sa` to test imports.

- [x] **Step 4: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_access_bindings.py -v -W error`
Expected: PASS (14 passed)

- [x] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authz/access.py tests/integration/test_access_bindings.py
git commit -m "feat: role bindings with scope compatibility and principal validation"
```

**Review fixes applied (follow-up commit):**

- **I11/L14 scope validation:** `bind_role` resolves org/team scopes through an injected `ScopeLookup` collaborator (`ScopeRecord` ownership facts). Missing row → `InvalidReference`; other tenant or soft-deleted → `CrossTenantReferenceError`; unknown scope type → `InvalidReference`; absent collaborator → `AuthorizationError` (fail closed). Tests cover nonexistent, other-tenant, soft-deleted, and a positive team binding; the tenant-scope compatibility test uses a real team.
- **Last-owner race:** `unbind_role` takes `pg_advisory_xact_lock(hashtextextended('jdlib:tenant:<id>', 0))` in the write session before reading the binding and counting owner bindings, so concurrent unbinds serialize. Covered by a white-box test that injects a competing deletion at lock time and proves the count observes it.
- **Rule 7 comparison:** full-catalog check is now `self._catalog_codes <= held` (set containment), replacing the count comparison.
- **Test gaps:** service-account principal path (active + suspended), active membership in another tenant, `binding.created`/`binding.removed` audit assertions, subset test tightened to `RoleEscalationBlocked`.
- **Accepted TOCTOU debt:** `bind_role` validates role/scope/subset in one transaction and inserts in a second; a concurrent role-permission change or scope soft-delete between them can commit a binding that was valid at validation time. Reads treat dangling/soft-deleted targets as invalid (I11), so the window is fail-closed at evaluation; revisit if single-transaction writes become necessary.

---

### Task 3: Resource grants and ownership transfer

**Files:**
- Modify: `src/jdlib/authz/access.py` (append `grant_resource`, `revoke_grant`, `transfer_resource`, `move_team`)
- Create: `tests/integration/test_access_grants.py`

**Interfaces:**
- Produces: `grant_resource(...)`, `revoke_grant(...)`, `transfer_resource(...)`, `move_team(...)`.

- [x] **Step 1: Write the failing tests**

`tests/integration/test_access_grants.py`:

```python
import uuid

import pytest
import sqlalchemy as sa

from jdlib.authz.access import AccessControl
from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import Permission, PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.authz.resource_types import ResourceTypeDefinition, ResourceTypeRegistry
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.enums import ScopeType
from jdlib.control.models import Membership, ResourceGrant, Role, RoleBinding, RolePermission, Tenant, User
from jdlib.context import Principal
from jdlib.errors import AuthorizationError, InvalidResourcePermission
from jdlib.models.org import Organization, Team
from tests.support.invoice import Invoice


def _access(control_session_factory) -> AccessControl:
    catalog = PermissionCatalog.with_builtins()
    catalog.register(
        Permission("invoice:approve", "invoice", frozenset(ScopeType), "Approve")
    )
    registry = ResourceTypeRegistry()
    registry.register(
        ResourceTypeDefinition("invoice", Invoice, tenant_owned=True, tenant_routed=True,
                               permission_namespace="invoice")
    )
    return AccessControl(
        session_factory=control_session_factory,
        catalog=catalog,
        reader=ControlAccessReader(control_session_factory),
        cache=AuthzCache(),
        audit=RecordingPlatformAudit(),
        registry=registry,
    )


async def _tenant(control_session_factory) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(Tenant(id=tenant_id, slug=f"gr-{tenant_id.hex[:8]}", name="GR", status="active"))
        await session.commit()
    return tenant_id


async def _owner_with_grant_permissions(control_session_factory, tenant_id):
    owner = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    role_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=owner.user_id, status="active"))
        session.add(Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=owner.user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=role_id, name=f"owner-{role_id.hex[:6]}"))
        for code in ("resource:read", "resource:share", "invoice:approve"):
            session.add(RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code=code))
        session.add(RoleBinding(tenant_id=tenant_id, id=uuid.uuid4(), role_id=role_id,
                                principal_type="user", principal_id=owner.user_id, scope_type="tenant"))
        await session.commit()
    return owner


async def test_grant_requires_namespace_and_holding_permission(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    member = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    async with control_session_factory() as session:
        session.add(User(id=member.user_id, status="active"))
        session.add(Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=member.user_id, status="active"))
        await session.commit()
    resource_id = uuid.uuid4()
    grant = await control.grant_resource(
        tenant_id, resource_type="invoice", resource_id=resource_id,
        principal_type="user", principal_id=member.user_id,
        permission="invoice:approve", actor_id=owner.user_id, actor_principal=owner,
    )
    assert grant.permission_code == "invoice:approve"
    with pytest.raises(InvalidResourcePermission):
        await control.grant_resource(
            tenant_id, resource_type="invoice", resource_id=resource_id,
            principal_type="user", principal_id=member.user_id,
            permission="resource:read", actor_id=owner.user_id, actor_principal=owner,
        )


async def test_grant_is_idempotent_and_revocable(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    resource_id = uuid.uuid4()
    first = await control.grant_resource(
        tenant_id, resource_type="invoice", resource_id=resource_id,
        principal_type="user", principal_id=owner.user_id,
        permission="invoice:approve", actor_id=owner.user_id, actor_principal=owner,
    )
    second = await control.grant_resource(
        tenant_id, resource_type="invoice", resource_id=resource_id,
        principal_type="user", principal_id=owner.user_id,
        permission="invoice:approve", actor_id=owner.user_id, actor_principal=owner,
    )
    assert first.id == second.id
    await control.revoke_grant(
        tenant_id, first.id, actor_id=owner.user_id, actor_principal=owner
    )
    async with control_session_factory() as session:
        remaining = (
            await session.execute(sa.select(ResourceGrant).where(ResourceGrant.id == first.id))
        ).scalar_one_or_none()
    assert remaining is None


async def test_transfer_resource_updates_ownership_and_audits(control_session_factory, async_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from tests.integration.test_session_isolation import _context, _session

    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    async with await _session(
        async_sessionmaker(async_engine, expire_on_commit=False), tenant_id
    ) as session:
        org_a, org_b, team = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        await session.add(Organization(id=org_a, name="A", slug=f"a-{org_a.hex[:6]}"))
        await session.add(Organization(id=org_b, name="B", slug=f"b-{org_b.hex[:6]}"))
        await session.add(Team(id=team, organization_id=org_a, name="T", slug=f"t-{team.hex[:6]}"))
        invoice_id = uuid.uuid4()
        await session.add(Invoice(id=invoice_id, number=f"INV-{invoice_id.hex[:6]}",
                                  organization_id=org_a, team_id=team))
        await session.flush()
        await control.transfer_resource(
            session, resource_type="invoice", resource_id=invoice_id,
            to_organization_id=org_b, to_team_id=None,
            actor_id=owner.user_id, actor_principal=owner,
        )
        row = (
            await session.execute(
                sa.select(Invoice.organization_id, Invoice.team_id).where(Invoice.id == invoice_id)
            )
        ).one()
    assert row == (org_b, None)
```

Note for the implementer: simplify the odd `__import__` calls in `_access` by importing `Permission` and `ScopeType` normally at the top.

- [x] **Step 2: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_access_grants.py -v`
Expected: FAIL

- [x] **Step 3: Implement grants and transfer in `src/jdlib/authz/access.py`**

```python
    async def grant_resource(
        self,
        tenant_id: uuid.UUID,
        *,
        resource_type: str,
        resource_id: uuid.UUID,
        principal_type: str,
        principal_id: uuid.UUID,
        permission: str,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> ResourceGrant:
        definition = self._registry.get(resource_type)
        self._catalog.validate(permission)
        if self._catalog.validate(permission).namespace != definition.permission_namespace:
            raise InvalidResourcePermission(
                f"{permission} is not valid for resource type {resource_type}"
            )
        await self._require_subset(
            tenant_id, [permission, "resource:share"], actor_principal
        )
        self._cache.invalidate()
        async with await self._session() as session:
            existing = (
                await session.execute(
                    sa.select(ResourceGrant).where(
                        ResourceGrant.tenant_id == tenant_id,
                        ResourceGrant.resource_type == resource_type,
                        ResourceGrant.resource_id == resource_id,
                        ResourceGrant.principal_type == principal_type,
                        ResourceGrant.principal_id == principal_id,
                        ResourceGrant.permission_code == permission,
                    )
                )
            ).scalar_one_or_none()
            if existing is not None:
                return existing
            grant = ResourceGrant(
                tenant_id=tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                principal_type=principal_type,
                principal_id=principal_id,
                permission_code=permission,
                created_by=actor_id,
            )
            session.add(grant)
            await self._audit.record(
                action="grant.created",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={
                    "resource": f"{resource_type}:{resource_id}",
                    "permission": permission,
                    "principal_id": str(principal_id),
                },
            )
            await session.commit()
            return grant

    async def revoke_grant(
        self,
        tenant_id: uuid.UUID,
        grant_id: uuid.UUID,
        *,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> None:
        self._cache.invalidate()
        async with await self._session() as session:
            grant = await session.get(
                ResourceGrant, {"tenant_id": tenant_id, "id": grant_id}
            )
            if grant is None:
                raise InvalidReference(f"grant not found: {grant_id}")
            await session.delete(grant)
            await self._audit.record(
                action="grant.revoked",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"grant_id": str(grant_id)},
            )
            await session.commit()

    async def transfer_resource(
        self,
        session: object,
        *,
        resource_type: str,
        resource_id: uuid.UUID,
        to_organization_id: uuid.UUID | None,
        to_team_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
        revoke_grants: bool = False,
    ) -> None:
        definition = self._registry.get(resource_type)
        model = definition.model
        context = getattr(session, "context", None)
        if context is None:
            raise InvalidReference("transfer requires a tenant session")
        self._cache.invalidate()
        row = (
            await session.execute(
                sa.select(model).where(model.id == resource_id)
            )
        ).scalar_one_or_none()
        if row is None:
            raise InvalidReference(f"resource not found: {resource_id}")
        previous = (row.organization_id, row.team_id)
        if to_team_id is not None and to_organization_id is None:
            raise InvalidReference("team ownership requires an organization")
        row.organization_id = to_organization_id
        row.team_id = to_team_id
        if revoke_grants:
            await session.execute(
                sa.delete(ResourceGrant).where(
                    ResourceGrant.tenant_id == context.tenant_id,
                    ResourceGrant.resource_type == resource_type,
                    ResourceGrant.resource_id == resource_id,
                )
            )
        await session.flush()
        await self._audit.record(
            action="resource.owner_changed",
            tenant_id=context.tenant_id,
            actor_id=actor_id,
            metadata={
                "resource": f"{resource_type}:{resource_id}",
                "from": f"{previous[0]}:{previous[1]}",
                "to": f"{to_organization_id}:{to_team_id}",
            },
        )
```

Note: `move_team` follows the same shape for `Team.organization_id` with audit `team.moved`; add it and a test in this task. `AccessControl` already accepts the optional `registry` (Task 1); the Task 3 test helper passes a populated registry.

- [x] **Step 4: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_access_grants.py -v -W error`
Expected: PASS (15 passed)

- [x] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authz/access.py tests/integration/test_access_grants.py
git commit -m "feat: resource grants and ownership transfer"
```

**Review fixes applied (follow-up commit):** authoritative snippets live in `src/jdlib/authz/access.py` and `tests/integration/test_access_grants.py` (15 tests); the notes below are the frozen contract deltas.

- **I11/L14 resource validation:** `grant_resource` resolves the target through an injected `ResourceLookup` collaborator (`ResourceRecord` ownership facts), same pattern as `ScopeLookup`. Missing row → `InvalidReference`; other tenant or soft-deleted → `CrossTenantReferenceError`; absent collaborator → `AuthorizationError` (fail closed). Validation runs after the grant-subset check, before insert. Tests cover missing, other-tenant, soft-deleted, and the unconfigured collaborator.
- **`move_team` ownership cascade:** the move updates `Team.organization_id` and `organization_id` on every registered type owning rows with `team_id == team.id` in one data-modifying-CTE statement (`UPDATE teams ... WITH moved_resource_N AS (UPDATE <type> ...)`), so the immediate composite FK `(tenant_id, team_id, organization_id) → teams` holds at end-of-statement. Separate statements cannot work in either order (both raise `IntegrityError`; verified). The statement carries an explicit `tenant_id` filter plus `execution_options(jdlib_scoped=True)` to pass the tenant-session bulk-DML guard. `revoke_grants` semantics unchanged; the attached-team test now exercises the non-empty `_revoke_team_grants` path. Unattached-team case kept.
- **Race-safe grants:** `grant_resource` inserts with `INSERT ... ON CONFLICT DO NOTHING RETURNING id`; on conflict it re-selects and returns the stored row without a second `grant.created` audit. The unique constraint remains the arbiter; the conflict-without-row branch is defensive. Covered by a true concurrency test (second connection holds the unique-index lock; the API call blocks, then returns the winner's row).
- **`resource:share` held-permission checks:** `revoke_grant` and `transfer_resource` require the caller to hold `resource:share` (`AuthorizationError` otherwise); `grant_resource` keeps the `[permission, resource:share]` subset rule. Tests cover the missing-share denial for both operations.
- **Counts:** `test_access_grants.py` 15 passed; full suite 333 passed; `ruff` and strict `mypy` clean.

---

### Task 4: Invitations

**Files:**
- Modify: `src/jdlib/authz/access.py` (append `invite`, `accept_invitation`)
- Create: `tests/unit/test_invitation_tokens.py`
- Create: `tests/integration/test_access_invitations.py`

**Interfaces:**
- Produces: `invite(tenant_id, *, email, role_id, scope_type, scope_id, invited_by, actor_principal, ttl=timedelta(days=7)) -> tuple[Invitation, str]` (returns raw token once; `member:invite` gate); `accept_invitation(token, *, user_id) -> Membership` (self-service, no gate).

- [x] **Step 1: Write the failing tests**

`tests/unit/test_invitation_tokens.py`:

```python
import uuid
from datetime import datetime, timedelta, timezone

from jdlib.authz.access import build_invitation_token, hash_invitation_secret, verify_invitation


def test_token_roundtrip_and_tampering():
    token = build_invitation_token()
    token_id, secret = token.split("_")[1], token.rsplit("_", 1)[1]
    stored = hash_invitation_secret(secret)
    assert verify_invitation(token, token_id, stored) is True
    assert verify_invitation("inv_deadbeef_wrong", token_id, stored) is False
```

`tests/integration/test_access_invitations.py`:

```python
import uuid

import pytest
import sqlalchemy as sa

from jdlib.authz.access import AccessControl
from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.context import PrincipalKind
from jdlib.control.models import Invitation, Membership, Role, RoleBinding, RolePermission, Tenant, User
from jdlib.context import Principal
from jdlib.errors import InvalidReference


def _access(control_session_factory) -> AccessControl:
    return AccessControl(
        session_factory=control_session_factory,
        catalog=PermissionCatalog.with_builtins(),
        reader=ControlAccessReader(control_session_factory),
        cache=AuthzCache(),
        audit=RecordingPlatformAudit(),
    )


async def test_invite_and_accept_creates_membership_and_binding(control_session_factory):
    tenant_id = uuid.uuid4()
    role_id = uuid.uuid4()
    owner = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    async with control_session_factory() as session:
        session.add(Tenant(id=tenant_id, slug=f"inv-{tenant_id.hex[:8]}", name="INV", status="active"))
        session.add(User(id=owner.user_id, status="active"))
        session.add(Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=owner.user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=role_id, name=f"member-{role_id.hex[:6]}"))
        session.add(RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code="resource:read"))
        await session.commit()
    control = _access(control_session_factory)
    invitation, token = await control.invite(
        tenant_id, email="new@example.com", role_id=role_id, scope_type="tenant", scope_id=None,
        invited_by=owner.user_id,
    )
    assert invitation.status == "pending"
    invitee_user = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=invitee_user, email="new@example.com", status="active"))
        await session.commit()
    membership = await control.accept_invitation(token, user_id=invitee_user)
    assert membership.status == "active"
    async with control_session_factory() as session:
        binding_count = (
            await session.execute(
                sa.select(sa.func.count()).select_from(RoleBinding).where(
                    RoleBinding.tenant_id == tenant_id, RoleBinding.principal_id == invitee_user
                )
            )
        ).scalar_one()
        stored = (
            await session.execute(sa.select(Invitation).where(Invitation.id == invitation.id))
        ).scalar_one()
    assert binding_count == 1
    assert stored.status == "accepted"
    with pytest.raises(InvalidReference):
        await control.accept_invitation(token, user_id=invitee_user)
```

- [x] **Step 2: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/unit/test_invitation_tokens.py tests/integration/test_access_invitations.py -v`
Expected: FAIL

- [x] **Step 3: Implement invitation helpers and methods**

Module-level helpers in `access.py`:

```python
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_HASHER = PasswordHasher()


def build_invitation_token() -> str:
    return f"inv_{secrets.token_urlsafe(16)}_{secrets.token_urlsafe(32)}"


def hash_invitation_secret(secret: str) -> str:
    return _HASHER.hash(secret)


def verify_invitation(token: str, token_id: str, stored_hash: str) -> bool:
    parts = token.split("_")
    if len(parts) != 3 or parts[0] != "inv" or parts[1] != token_id:
        return False
    try:
        return _HASHER.verify(stored_hash, parts[2])
    except VerifyMismatchError:
        return False
```

Methods:

```python
    async def invite(
        self,
        tenant_id: uuid.UUID,
        *,
        email: str,
        role_id: uuid.UUID,
        scope_type: str,
        scope_id: uuid.UUID | None,
        invited_by: uuid.UUID | None,
        ttl: timedelta = timedelta(days=7),
    ) -> tuple[Invitation, str]:
        token = build_invitation_token()
        token_id = token.split("_")[1]
        secret = token.rsplit("_", 1)[1]
        self._cache.invalidate()
        async with await self._session() as session:
            role = await session.get(Role, {"tenant_id": tenant_id, "id": role_id})
            if role is None:
                raise InvalidReference(f"role not found: {role_id}")
            invitation = Invitation(
                tenant_id=tenant_id,
                email=email,
                scope_type=scope_type,
                scope_id=scope_id,
                role_id=role_id,
                token_id=token_id,
                token_hash=hash_invitation_secret(secret),
                status="pending",
                expires_at=datetime.now(timezone.utc) + ttl,
                invited_by=invited_by,
            )
            session.add(invitation)
            await self._audit.record(
                action="invitation.created",
                tenant_id=tenant_id,
                actor_id=invited_by,
                metadata={"email": email, "role_id": str(role_id)},
            )
            await session.commit()
            return invitation, token

    async def accept_invitation(
        self, token: str, *, user_id: uuid.UUID
    ) -> Membership:
        token_id = token.split("_")[1] if token.startswith("inv_") else ""
        self._cache.invalidate()
        async with await self._session() as session:
            invitation = (
                await session.execute(
                    sa.select(Invitation).where(Invitation.token_id == token_id)
                )
            ).scalar_one_or_none()
            if invitation is None or not verify_invitation(
                token, invitation.token_id, invitation.token_hash
            ):
                raise InvalidReference("invalid invitation token")
            if invitation.status != "pending":
                raise InvalidReference(f"invitation is {invitation.status}")
            if invitation.expires_at <= datetime.now(timezone.utc):
                raise InvalidReference("invitation expired")
            membership = Membership(
                tenant_id=invitation.tenant_id,
                user_id=user_id,
                status="active",
            )
            session.add(membership)
            await session.flush()
            session.add(
                RoleBinding(
                    tenant_id=invitation.tenant_id,
                    role_id=invitation.role_id,
                    principal_type="user",
                    principal_id=user_id,
                    scope_type=invitation.scope_type,
                    scope_id=invitation.scope_id,
                    created_by=invitation.invited_by,
                )
            )
            invitation.status = "accepted"
            invitation.accepted_at = datetime.now(timezone.utc)
            await self._audit.record(
                action="invitation.accepted",
                tenant_id=invitation.tenant_id,
                actor_id=user_id,
                metadata={"invitation_id": str(invitation.id)},
            )
            await session.commit()
            return membership
```

- [x] **Step 4: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/unit/test_invitation_tokens.py tests/integration/test_access_invitations.py -v -W error`
Expected: PASS (2 passed)

- [x] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authz/access.py tests/unit/test_invitation_tokens.py tests/integration/test_access_invitations.py
git commit -m "feat: invitations with hashed single-use tokens"
```

**Review fixes applied (follow-up commit from the Task 4 implementation):**

- Interfaces correction: `invite(..., ttl=timedelta(days=7))` accepts the request-scoped TTL; `accept_invitation(token, *, user_id) -> Membership` has no `actor_principal` — the invitee `user_id` is the audit actor.
- Token format: `build_invitation_token()` uses `secrets.token_hex(16)` for the id and `secrets.token_hex(32)` for the secret (the sketch's `token_urlsafe` was dropped); at rest the secret is Argon2id-hashed through a module-level `PasswordHasher`.
- `accept_invitation` validates the invitation's scope placement before the atomic membership + binding write: tenant scope must not carry a `scope_id`; org/team scopes require one and resolve through the injected `ScopeLookup` (`InvalidReference` when missing, `CrossTenantReferenceError` when foreign/soft-deleted, `AuthorizationError` when the lookup is not configured). `invitation.created`/`invitation.accepted` are recorded before commit.
- Shipped tests: 20 integration tests plus 4 unit tests, covering Argon2id hash-at-rest, token uniqueness, malformed/tampered/invalid-hash tokens, expiry and terminal status, scope failure modes, invite authorization, role↔scope compatibility at invite and accept, re-invite and existing-member idempotency, cache invalidation, and audit entries. Authoritative snippets live in `src/jdlib/authz/access.py`, `tests/integration/test_access_invitations.py`, and `tests/unit/test_invitation_tokens.py`.
- Final-wave counts: full suite `359 passed`; `ruff` and strict `mypy` clean.

**Final review wave (fix commit — `fix: invitation idempotency, scope compatibility, invite gate`):** authoritative snippets live in `src/jdlib/authz/access.py`, `tests/integration/test_access_invitations.py`, and `tests/unit/test_invitation_tokens.py`; deltas only below.

- Invite authorization: `invite` takes a required `actor_principal` and gates on `member:invite` through `_require_permission` (`AuthorizationError`); `accept_invitation` stays self-service (acceptance needs no gate). Call sites/tests pass the inviter principal.
- Duplicate pending invites: `invite` revokes any pending invitation for the same `(tenant, email, scope_type, scope_id)` (`status='revoked'`, `revoked_at`) before inserting, and holds the per-tenant advisory lock, so re-inviting replaces instead of raising `IntegrityError`.
- Existing-member accept: `accept_invitation` reuses an active `Membership` (same row/id) instead of inserting a duplicate, creates the `RoleBinding` only when that exact binding is absent, and rejects non-active memberships with `InvalidReference("membership is <status>")`.
- L16 role↔scope compatibility: the `allowed_scopes` check from `bind_role` (`RoleScopeMismatch`) runs at `invite` and is re-checked at `accept_invitation`; scope placement (shape + `_validate_scope`) is shared via `_validate_scope_placement`, also used by `bind_role`.
- Minor inclusions: `verify_invitation` returns `False` for malformed stored hashes — argon2-cffi 25.1.0 has `InvalidHashError(ValueError)`, **not** a `VerificationError` subclass, so both are caught; invite/accept tests probe the shared `AuthzCache` to assert invalidation; `invite` validates scope shape before insert.

**Final review wave 2 (fix commit — `fix: move_team gate, invitation escalation guard, accept race, destination validation`):** authoritative snippets live in `src/jdlib/authz/access.py`, `tests/integration/test_access_grants.py`, `tests/integration/test_access_bindings.py`, and `tests/integration/test_access_invitations.py`; deltas only below.

- `move_team` gate: requires `team:manage` through `_require_permission` after the tenant-session check and before any mutation; denial test proves the team is untouched.
- Invitation anti-escalation (rules 3/7): `invite` resolves the role's permission codes and then applies `_require_subset` (`RoleEscalationBlocked`) plus the owner-assignment check (`role.name == "owner"` requires the actor to hold the full catalog, `AuthorizationError`); denial tests for both, plus a positive full-catalog owner invite.
- `accept_invitation` race safety: the invitation is claimed with a conditional `UPDATE invitations SET status='accepted', accepted_at=now() WHERE tenant_id=... AND id=... AND status='pending'` and the membership/binding write proceeds only when `rowcount == 1`; a losing concurrent accept raises `InvalidReference("invitation is accepted")` and writes no membership/binding. The true concurrency test mirrors the grants race test (winner holds the row lock; the API call blocks, then fails after the winner commits).
- Ownership destination validation (I11): `transfer_resource` and `move_team` resolve non-None destination org/team ids through `_validate_scope` before mutating (missing → `InvalidReference`; foreign → `CrossTenantReferenceError`; soft-deleted → `InvalidReference("<scope> scope is deleted: ...")`); missing/foreign/deleted destination tests for both operations.
- Minor inclusions: soft-deleted scope rows now raise `InvalidReference` with a deleted-specific message instead of a misleading `CrossTenantReferenceError` when the tenant matches (foreign tenant stays `CrossTenantReferenceError`); `_catalog_codes` is computed on demand (no construction snapshot); `move_team` dedupes cascade models by table (one data-modifying CTE per table, regression test captures the emitted SQL); cascaded grant deletions in `transfer_resource`/`move_team` emit one `grant.revoked` audit per grant and re-invite replacement emits `invitation.revoked`.
- Corrected the Task 5 filename reference: `docs/superpowers/plans/2026-09-21-jdlib-access-control-phase-4c.md` (the plan previously named a nonexistent `...-authorization-phase-4c.md`).
- Counts: full suite `367 passed`; `ruff` and strict `mypy` clean.

---

### Task 5: Role × action matrix and phase exit

**Files:**
- Create: `tests/integration/test_role_action_matrix.py`
- Modify: `docs/jdlib/07-implementation-design.md` (file map: `authz/access.py`; note the shared `AuthzCache` instance requirement)
- Modify: `docs/superpowers/plans/2026-09-21-jdlib-access-control-phase-4c.md` (back-ports)

**Interfaces:** none new.

- [x] **Step 1: Write the matrix test**

Seed one tenant with the four built-in templates (owner = all catalog codes; admin = all except `tenant:manage`; member = read/create/update at team scope; viewer = read at org scope), a resource with team ownership, a service account with no binding, and assert via `DefaultPDP` for a representative action set: `resource:read`, `resource:update`, `resource:delete`, `member:invite`, `role:manage`, `tenant:manage`, `resource:share`. Use the real `ControlAccessReader` + `ScopeResolver` + `DefaultPDP` and a real `TenantSession`. Cases: owner allowed all; admin allowed all but `tenant:manage`; member allowed read/update at its team, denied delete/tenant:manage; viewer allowed read, denied update; service account denied everything without bindings; platform operator denied by the tenant PDP (operator path is capability-based, not PDP).

- [x] **Step 2: Run the test, fix any wiring gaps it reveals**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_role_action_matrix.py -v -W error`

- [x] **Step 3: Doc updates**

- `07` file map: add `authz/access.py`; note "one `AuthzCache` instance must be shared between the PDP and `AccessControl` per request".
- Back-port all Task 1–4 code deviations and the matrix test reference into this plan.
- Update the plan series note: Plan 4d next.

- [x] **Step 4: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add tests/integration/test_role_action_matrix.py docs
git commit -m "test: role action matrix; docs sync"
```

**Final state (shipped):** `tests/integration/test_role_action_matrix.py::test_role_action_matrix` seeds one tenant with the four system templates (`owner` = full catalog, `admin` = all but `tenant:manage`, `member` = read/create/update, `viewer` = read), a team-owned invoice under a real org/team, an unbound service account, and a platform operator, then evaluates the seven representative actions through the real `ControlAccessReader` + `ScopeResolver` + `DefaultPDP` with a real `TenantSession`. Asserted matrix: owner all; admin all but `tenant:manage`; member `resource:read`/`resource:update` (team scope); viewer `resource:read` (org scope); service account and platform operator none, with denial reasons `no_allow` and `principal_inactive`. The file also ships `test_access_control_invalidates_the_shared_pdp_cache`, which gives `AccessControl` the same `AuthzCache` as the PDP, binds a new team-scoped role, and proves the PDP refetches the allow (the `07` file map records that one-`AuthzCache`-instance-per-request sharing contract). No source wiring changes were required.

---

## Phase 4c Exit Criteria

- [x] Full suite green on real PostgreSQL 16.
- [x] Roles: subset anti-escalation, catalog validation, system immutability, binding-blocked deletion, audit, cache invalidation.
- [x] Bindings: scope compatibility (`RoleScopeMismatch`), principal membership/tenant validation (`CrossTenantReferenceError`), subset rule, unbind.
- [x] Grants: namespace validation, permission + `resource:share` requirement, idempotent creation, revocation, transfer/move with audit.
- [x] Invitations: hashed single-use tokens, expiry/status checks, atomic membership + binding, audit.
- [x] `04` §8 role × action matrix passes end-to-end through `DefaultPDP`.
- [x] `ruff` and strict `mypy` clean.

## Plan Series (remaining)

- Plan 4d (next) — authentication (OIDC/JWT, API keys) + `ContextFactory`/middleware wiring.
- Plan 5 — schema/database strategies, RLS, privileged tenant-plane deletion.
- Plan 6 — audit sinks, `jdlib.testing`, FastAPI/CLI, public API.
