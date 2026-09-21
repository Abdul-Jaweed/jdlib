# jdlib Context & Resolution (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the tenancy context layer: configuration, `Principal`/`TenantContext`/`PrivilegeContext`, the fail-closed `ContextFactory` with port-based verification, signed async envelopes, the tenant resolver chain, the job propagator/decorator, and pure-ASGI middleware.

**Architecture:** `jdlib.context` owns immutable value objects, the contextvar, the factory, ports (`PrincipalDirectory`, `TenantDirectory`, `ServabilityChecker`, `EntitlementChecker`, `OperatorAuthorizer`, `PrivilegeAudit`), the clock, and envelope signing. `jdlib.tenancy.resolution` owns `RequestInfo` and the resolver chain; `jdlib.tenancy.jobs` owns `ContextPropagator` and `@tenant_job`; `jdlib.tenancy.middleware` owns the pure-ASGI `TenantMiddleware` and the frozen HTTP error mapping. Services that implement the ports arrive in later phases; Phase 2 tests use in-memory fakes.

**Tech Stack:** Python 3.12, pydantic v2 + pydantic-settings, stdlib `hmac`/`hashlib`/`base64`/`contextvars`/`urllib.parse`, pytest + pytest-asyncio; ruff + mypy strict. No new dependencies.

**Specs (frozen):** `docs/superpowers/specs/2026-09-21-jdlib-multitenancy-foundation-design.md` (rev 7) §5.1–5.3, §9; `docs/jdlib/03-isolation-invariants.md` I1/I5/I7/I8; `docs/jdlib/04-authorization-model.md` §2/§6; `docs/jdlib/07-implementation-design.md` §4, §10–§12.

## Global Constraints

- Python `>=3.12`; async-first; no new runtime dependencies.
- `TenantContext`, `Principal`, `PrivilegeContext` are frozen (`dataclass(frozen=True, slots=True)`); the contextvar is the only module state and is fail-closed.
- Envelopes are signed with HMAC-SHA256 using `context.signing_key`; they never carry permissions or scopes.
- Context creation is only possible through `ContextFactory`; privileged creation requires the internal `_PrivilegeIssuer` capability and a `PrivilegeAudit` record.
- HTTP error mapping is frozen: `AuthenticationError→401`, `AuthorizationError→403`, `TenantNotFound`/`TenantAccessDenied→404`, `TenantSuspended`/`TenantNotWritable→423`, `CrossTenantReferenceError→409`, other `JdlibError→500`.
- Ports are `typing.Protocol`s; no service may import `persistence`, `authn`, or concrete strategies.
- Commands: `.venv/Scripts/python -m pytest ...`, `.venv/Scripts/python -m ruff check .`, `.venv/Scripts/python -m mypy src/jdlib`.
- No comments in source; docstrings only where the plan shows them.
- Commit after every task; never commit secrets.

---

### Task 1: Configuration

**Files:**
- Create: `src/jdlib/config.py`
- Create: `tests/unit/test_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `TenancyConfig`, `ContextConfig`, `ResolverConfig`, `ResolverName` (StrEnum: `jwt_claim`, `subdomain`, `path`, `header`, `api_key`).

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_config.py`:

```python
import pytest
from pydantic import SecretStr, ValidationError

from jdlib.config import ContextConfig, ResolverConfig, ResolverName, TenancyConfig


def test_signing_key_is_required():
    with pytest.raises(ValidationError):
        ContextConfig()


def test_defaults():
    config = TenancyConfig(context=ContextConfig(signing_key="s3cret"))
    assert config.context.envelope_ttl.total_seconds() == 300
    assert config.context.operator_ttl.total_seconds() == 1800
    assert config.context.allow_test_contexts is False
    assert config.resolvers.order == [
        ResolverName.JWT_CLAIM,
        ResolverName.SUBDOMAIN,
        ResolverName.PATH,
        ResolverName.HEADER,
        ResolverName.API_KEY,
    ]
    assert config.resolvers.path_prefix == "/t/"
    assert config.resolvers.header_name == "X-Tenant-Slug"
    assert config.resolvers.jwt_claim == "tid"
    assert config.resolvers.base_domain is None


def test_env_parsing(monkeypatch):
    monkeypatch.setenv("JDLIB_CONTEXT__SIGNING_KEY", "env-key")
    monkeypatch.setenv("JDLIB_RESOLVERS__ORDER", '["header","path"]')
    monkeypatch.setenv("JDLIB_RESOLVERS__BASE_DOMAIN", "app.example.com")
    config = TenancyConfig()
    assert config.context.signing_key.get_secret_value() == "env-key"
    assert config.resolvers.order == [ResolverName.HEADER, ResolverName.PATH]
    assert config.resolvers.base_domain == "app.example.com"


def test_secret_is_not_leaked_in_repr():
    config = TenancyConfig(context=ContextConfig(signing_key="top-secret"))
    assert "top-secret" not in repr(config)
    assert isinstance(config.context.signing_key, SecretStr)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.config'`

- [ ] **Step 3: Implement `src/jdlib/config.py`**

```python
from __future__ import annotations

from datetime import timedelta
from enum import StrEnum

from pydantic import BaseModel, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ResolverName(StrEnum):
    JWT_CLAIM = "jwt_claim"
    SUBDOMAIN = "subdomain"
    PATH = "path"
    HEADER = "header"
    API_KEY = "api_key"


class ContextConfig(BaseModel):
    signing_key: SecretStr
    envelope_ttl: timedelta = timedelta(minutes=5)
    operator_ttl: timedelta = timedelta(minutes=30)
    allow_test_contexts: bool = False


class ResolverConfig(BaseModel):
    order: list[ResolverName] = [
        ResolverName.JWT_CLAIM,
        ResolverName.SUBDOMAIN,
        ResolverName.PATH,
        ResolverName.HEADER,
        ResolverName.API_KEY,
    ]
    base_domain: str | None = None
    path_prefix: str = "/t/"
    header_name: str = "X-Tenant-Slug"
    jwt_claim: str = "tid"


class TenancyConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="JDLIB_", env_nested_delimiter="__")

    control_dsn: SecretStr | None = None
    context: ContextConfig
    resolvers: ResolverConfig = ResolverConfig()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/config.py tests/unit/test_config.py
git commit -m "feat: tenancy configuration (context, resolvers)"
```

---

### Task 2: Context value objects, accessors, scoped keys

**Files:**
- Create: `src/jdlib/context.py`
- Create: `tests/unit/test_context_values.py`

**Interfaces:**
- Consumes: `jdlib.errors.MissingTenantContext`; enums from `jdlib.control.enums` (`PrincipalType`, `PlacementStrategy`, `TenantStatus`, `OperatorLevel`).
- Produces: `Principal`, `PrivilegeContext`, `PrivilegeKind`, `TenantContext`, `TenantRef`, `TenantRecord`, `Clock`, `SystemClock`, `current_tenant()`, `current_principal()`, `current_privilege()`, `context_scope()`, `scoped_key()`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_context_values.py`:

```python
import dataclasses
import uuid

import pytest

from jdlib.control.enums import PlacementStrategy, PrincipalType, TenantStatus
from jdlib.context import (
    Principal,
    TenantContext,
    TenantRecord,
    TenantRef,
    context_scope,
    current_principal,
    current_privilege,
    current_tenant,
    scoped_key,
)
from jdlib.errors import MissingTenantContext


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=uuid.UUID("00000000-0000-0000-0000-0000000000aa"),
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalType.USER, id=uuid.uuid4()),
        request_id="req-1",
        correlation_id="corr-1",
    )


def test_accessors_fail_closed_without_context():
    with pytest.raises(MissingTenantContext):
        current_tenant()
    with pytest.raises(MissingTenantContext):
        current_principal()
    with pytest.raises(MissingTenantContext):
        current_privilege()
    with pytest.raises(MissingTenantContext):
        scoped_key("cache", "x")


def test_context_scope_installs_and_clears():
    context = _context()
    with context_scope(context):
        assert current_tenant() is context
        assert current_principal() is context.principal
        assert current_privilege() is None
    with pytest.raises(MissingTenantContext):
        current_tenant()


def test_value_objects_are_frozen():
    context = _context()
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.tenant_id = uuid.uuid4()  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.principal.kind = PrincipalType.SERVICE_ACCOUNT  # type: ignore[misc]


def test_scoped_key_is_versioned_and_encoded():
    with context_scope(_context()):
        assert scoped_key("cache") == "jdlib:v1:00000000-0000-0000-0000-0000000000aa:cache"
        assert (
            scoped_key("cache", "a:b", "c")
            == "jdlib:v1:00000000-0000-0000-0000-0000000000aa:cache:a%3Ab:c"
        )
        assert scoped_key("cache", "a", "b:c") != scoped_key("cache", "a:b", "c")


def test_tenant_ref_and_record_shapes():
    ref = TenantRef(slug="acme")
    record = TenantRecord(
        id=uuid.uuid4(), slug="acme", status=TenantStatus.ACTIVE, strategy=PlacementStrategy.SHARED
    )
    assert ref.id is None
    assert record.status is TenantStatus.ACTIVE
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_context_values.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.context'`

- [ ] **Step 3: Implement `src/jdlib/context.py` (value objects and accessors only)**

```python
from __future__ import annotations

import contextvars
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Protocol
from urllib.parse import quote

from jdlib.control.enums import OperatorLevel, PlacementStrategy, PrincipalType, TenantStatus
from jdlib.errors import MissingTenantContext


class PrivilegeKind(StrEnum):
    OPERATOR = "operator"
    SYSTEM = "system"
    TEST = "test"


@dataclass(frozen=True, slots=True)
class Principal:
    kind: PrincipalType
    id: uuid.UUID
    user_id: uuid.UUID | None = None
    tenant_id: uuid.UUID | None = None
    api_key_id: uuid.UUID | None = None
    scopes: frozenset[str] | None = None
    operator_level: OperatorLevel | None = None


@dataclass(frozen=True, slots=True)
class PrivilegeContext:
    kind: PrivilegeKind
    capability: str | None
    justification: str | None
    actor: Principal
    issued_at: datetime
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: uuid.UUID
    tenant_slug: str
    strategy: PlacementStrategy
    principal: Principal
    request_id: str
    correlation_id: str
    trace_id: str | None = None
    privilege: PrivilegeContext | None = None


@dataclass(frozen=True, slots=True)
class TenantRef:
    id: uuid.UUID | None = None
    slug: str | None = None


@dataclass(frozen=True, slots=True)
class TenantRecord:
    id: uuid.UUID
    slug: str
    status: TenantStatus
    strategy: PlacementStrategy


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


_CTX: contextvars.ContextVar[TenantContext | None] = contextvars.ContextVar(
    "jdlib_tenant_context", default=None
)


@contextmanager
def context_scope(context: TenantContext) -> Iterator[TenantContext]:
    token = _CTX.set(context)
    try:
        yield context
    finally:
        _CTX.reset(token)


def current_tenant() -> TenantContext:
    context = _CTX.get()
    if context is None:
        raise MissingTenantContext("no tenant context is active")
    return context


def current_principal() -> Principal:
    return current_tenant().principal


def current_privilege() -> PrivilegeContext | None:
    return current_tenant().privilege


def scoped_key(namespace: str, *parts: object) -> str:
    context = current_tenant()
    encoded_namespace = quote(namespace, safe="")
    suffix = "".join(f":{quote(str(part), safe='')}" for part in parts)
    return f"jdlib:v1:{context.tenant_id}:{encoded_namespace}{suffix}"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_context_values.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/context.py tests/unit/test_context_values.py
git commit -m "feat: tenant context value objects, fail-closed accessors, scoped keys"
```

---

### Task 3: Ports, ContextFactory, privilege issuance

**Files:**
- Modify: `src/jdlib/context.py` (append ports and factory)
- Create: `tests/support/context_fakes.py`
- Create: `tests/unit/test_context_factory.py`

**Interfaces:**
- Consumes: Task 2 types; `jdlib.errors` (`UnknownPrincipal`, `TenantNotFound`, `TenantAccessDenied`, `AuthorizationError`, `TenantSuspended`).
- Produces: `PrincipalDirectory`, `TenantDirectory`, `ServabilityChecker`, `EntitlementChecker`, `OperatorAuthorizer`, `PrivilegeAudit` protocols; `_PrivilegeIssuer`; `PRIVILEGE_ISSUER`; `ContextFactory` with `for_principal`, `for_operator`, `for_system`, `for_test`.

- [ ] **Step 1: Write the shared fakes**

`tests/support/context_fakes.py`:

```python
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from jdlib.context import (
    Clock,
    Principal,
    PrivilegeContext,
    PrivilegeKind,
    TenantRecord,
    TenantRef,
)


class FrozenClock(Clock):
    def __init__(self, now: datetime | None = None) -> None:
        self._now = now or datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now = self._now + delta


class StaticPrincipals:
    def __init__(self, active: set[uuid.UUID] | None = None) -> None:
        self._active = active or set()

    async def is_active(self, principal: Principal) -> bool:
        return principal.id in self._active


class DictTenants:
    def __init__(self, records: list[TenantRecord] | None = None) -> None:
        self._by_id = {record.id: record for record in records or []}
        self._by_slug = {record.slug: record for record in records or []}

    async def get(self, ref: TenantRef) -> TenantRecord | None:
        if ref.id is not None:
            return self._by_id.get(ref.id)
        if ref.slug is not None:
            return self._by_slug.get(ref.slug)
        return None


class ServabilityStub:
    def __init__(self, suspended: set[uuid.UUID] | None = None) -> None:
        self._suspended = suspended or set()

    async def assert_servable(self, tenant_id: uuid.UUID) -> None:
        if tenant_id in self._suspended:
            from jdlib.errors import TenantSuspended

            raise TenantSuspended(f"tenant {tenant_id} is not servable")


class EntitlementsStub:
    def __init__(self, allowed: set[tuple[uuid.UUID, uuid.UUID]] | None = None) -> None:
        self._allowed = allowed or set()

    async def can_act(self, principal: Principal, tenant_id: uuid.UUID) -> bool:
        return (principal.id, tenant_id) in self._allowed


class OperatorsStub:
    def __init__(self, capabilities: set[str] | None = None) -> None:
        self._capabilities = capabilities or set()

    async def authorize(self, principal: Principal, capability: str) -> bool:
        return capability in self._capabilities


@dataclass
class RecordingPrivilegeAudit:
    records: list[dict[str, object]] = field(default_factory=list)

    async def record_privilege(
        self,
        *,
        kind: PrivilegeKind,
        capability: str | None,
        justification: str | None,
        actor: Principal,
        tenant_id: uuid.UUID,
    ) -> None:
        self.records.append(
            {
                "kind": kind,
                "capability": capability,
                "justification": justification,
                "actor_id": actor.id,
                "tenant_id": tenant_id,
            }
        )
```

- [ ] **Step 2: Write the failing tests**

`tests/unit/test_context_factory.py`:

```python
import uuid

import pytest

from jdlib.config import ContextConfig
from jdlib.context import ContextFactory, Principal, PrivilegeKind, TenantRecord, TenantRef
from jdlib.control.enums import OperatorLevel, PlacementStrategy, PrincipalType, TenantStatus
from jdlib.errors import (
    AuthorizationError,
    MissingTenantContext,
    TenantAccessDenied,
    TenantNotFound,
    TenantSuspended,
    UnknownPrincipal,
)
from tests.support.context_fakes import (
    DictTenants,
    EntitlementsStub,
    FrozenClock,
    OperatorsStub,
    RecordingPrivilegeAudit,
    ServabilityStub,
    StaticPrincipals,
)

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
USER_ID = uuid.uuid4()
OPERATOR_ID = uuid.uuid4()


def _record() -> TenantRecord:
    return TenantRecord(
        id=TENANT_ID, slug="acme", status=TenantStatus.ACTIVE, strategy=PlacementStrategy.SHARED
    )


def _factory(
    *,
    active: set[uuid.UUID] | None = None,
    suspended: set[uuid.UUID] | None = None,
    allowed: set[tuple[uuid.UUID, uuid.UUID]] | None = None,
    capabilities: set[str] | None = None,
    allow_test: bool = False,
) -> tuple[ContextFactory, RecordingPrivilegeAudit]:
    audit = RecordingPrivilegeAudit()
    factory = ContextFactory(
        config=ContextConfig(
            signing_key="test-key", allow_test_contexts=allow_test
        ),
        principals=StaticPrincipals(active or {USER_ID, OPERATOR_ID}),
        tenants=DictTenants([_record()]),
        servability=ServabilityStub(suspended),
        entitlements=EntitlementsStub(allowed or {(USER_ID, TENANT_ID)}),
        operators=OperatorsStub(capabilities or set()),
        audit=audit,
        clock=FrozenClock(),
    )
    return factory, audit


def _user() -> Principal:
    return Principal(kind=PrincipalType.USER, id=USER_ID, user_id=USER_ID)


async def test_for_principal_happy_path():
    factory, _ = _factory()
    context = await factory.for_principal(_user(), TenantRef(slug="acme"), request_id="req-1")
    assert context.tenant_id == TENANT_ID
    assert context.tenant_slug == "acme"
    assert context.strategy is PlacementStrategy.SHARED
    assert context.principal is not None
    assert context.privilege is None


async def test_for_principal_rejects_inactive_principal():
    factory, _ = _factory(active=set())
    with pytest.raises(UnknownPrincipal):
        await factory.for_principal(_user(), TenantRef(slug="acme"), request_id="req-1")


async def test_for_principal_rejects_unknown_tenant():
    factory, _ = _factory()
    with pytest.raises(TenantNotFound):
        await factory.for_principal(_user(), TenantRef(slug="ghost"), request_id="req-1")


async def test_for_principal_rejects_non_servable_tenant():
    factory, _ = _factory(suspended={TENANT_ID})
    with pytest.raises(TenantSuspended):
        await factory.for_principal(_user(), TenantRef(slug="acme"), request_id="req-1")


async def test_for_principal_rejects_unentitled_principal():
    factory, _ = _factory(allowed=set())
    with pytest.raises(TenantAccessDenied):
        await factory.for_principal(_user(), TenantRef(slug="acme"), request_id="req-1")


async def test_for_operator_requires_platform_operator_kind():
    factory, _ = _factory()
    operator = Principal(kind=PrincipalType.USER, id=OPERATOR_ID)
    with pytest.raises(AuthorizationError):
        await factory.for_operator(
            operator, TenantRef(slug="acme"), "platform.tenant.access",
            justification="ticket-1", request_id="req-1",
        )


async def test_for_operator_requires_justification_and_capability():
    factory, _ = _factory()
    operator = Principal(
        kind=PrincipalType.PLATFORM_OPERATOR, id=OPERATOR_ID, operator_level=OperatorLevel.OPERATOR
    )
    with pytest.raises(AuthorizationError):
        await factory.for_operator(
            operator, TenantRef(slug="acme"), "platform.tenant.access",
            justification="  ", request_id="req-1",
        )
    with pytest.raises(AuthorizationError):
        await factory.for_operator(
            operator, TenantRef(slug="acme"), "platform.tenant.access",
            justification="ticket-1", request_id="req-1",
        )


async def test_for_operator_creates_audited_expiring_privilege():
    factory, audit = _factory(capabilities={"platform.tenant.access"})
    operator = Principal(
        kind=PrincipalType.PLATFORM_OPERATOR, id=OPERATOR_ID, operator_level=OperatorLevel.OPERATOR
    )
    context = await factory.for_operator(
        operator, TenantRef(slug="acme"), "platform.tenant.access",
        justification="ticket-1", request_id="req-1",
    )
    assert context.privilege is not None
    assert context.privilege.kind is PrivilegeKind.OPERATOR
    assert context.privilege.expires_at is not None
    assert context.privilege.expires_at > context.privilege.issued_at
    assert audit.records == [
        {
            "kind": PrivilegeKind.OPERATOR,
            "capability": "platform.tenant.access",
            "justification": "ticket-1",
            "actor_id": OPERATOR_ID,
            "tenant_id": TENANT_ID,
        }
    ]


async def test_for_operator_rejects_ttl_above_maximum():
    factory, _ = _factory(capabilities={"platform.tenant.access"})
    operator = Principal(
        kind=PrincipalType.PLATFORM_OPERATOR, id=OPERATOR_ID, operator_level=OperatorLevel.OPERATOR
    )
    from datetime import timedelta

    with pytest.raises(AuthorizationError):
        await factory.for_operator(
            operator, TenantRef(slug="acme"), "platform.tenant.access",
            justification="ticket-1", ttl=timedelta(hours=2), request_id="req-1",
        )


def test_for_system_requires_issuer_capability():
    factory, _ = _factory()
    with pytest.raises(AuthorizationError):
        factory.for_system(_record(), purpose="migration", issuer=object())  # type: ignore[arg-type]
    from jdlib.context import PRIVILEGE_ISSUER

    context = factory.for_system(_record(), purpose="migration", issuer=PRIVILEGE_ISSUER)
    assert context.privilege is not None
    assert context.privilege.kind is PrivilegeKind.SYSTEM
    assert context.privilege.capability == "migration"


def test_for_test_is_gated_by_config():
    factory, _ = _factory()
    from jdlib.context import PRIVILEGE_ISSUER

    with pytest.raises(AuthorizationError):
        factory.for_test(_record(), principal=_user(), issuer=PRIVILEGE_ISSUER)
    factory, _ = _factory(allow_test=True)
    context = factory.for_test(_record(), principal=_user(), issuer=PRIVILEGE_ISSUER)
    assert context.privilege is not None
    assert context.privilege.kind is PrivilegeKind.TEST
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_context_factory.py -v`
Expected: FAIL with `ImportError: cannot import name 'ContextFactory'`

- [ ] **Step 4: Append ports and factory to `src/jdlib/context.py`**

Add imports: `from datetime import timedelta`; `from jdlib.config import ContextConfig`; `from jdlib.errors import AuthorizationError, TenantAccessDenied, TenantNotFound, UnknownPrincipal`.

Append:

```python
class PrincipalDirectory(Protocol):
    async def is_active(self, principal: Principal) -> bool: ...


class TenantDirectory(Protocol):
    async def get(self, ref: TenantRef) -> TenantRecord | None: ...


class ServabilityChecker(Protocol):
    async def assert_servable(self, tenant_id: uuid.UUID) -> None: ...


class EntitlementChecker(Protocol):
    async def can_act(self, principal: Principal, tenant_id: uuid.UUID) -> bool: ...


class OperatorAuthorizer(Protocol):
    async def authorize(self, principal: Principal, capability: str) -> bool: ...


class PrivilegeAudit(Protocol):
    async def record_privilege(
        self,
        *,
        kind: PrivilegeKind,
        capability: str | None,
        justification: str | None,
        actor: Principal,
        tenant_id: uuid.UUID,
    ) -> None: ...


class _PrivilegeIssuer:
    __slots__ = ()


PRIVILEGE_ISSUER = _PrivilegeIssuer()


class ContextFactory:
    def __init__(
        self,
        *,
        config: ContextConfig,
        principals: PrincipalDirectory,
        tenants: TenantDirectory,
        servability: ServabilityChecker,
        entitlements: EntitlementChecker,
        operators: OperatorAuthorizer,
        audit: PrivilegeAudit,
        clock: Clock | None = None,
    ) -> None:
        self._config = config
        self._principals = principals
        self._tenants = tenants
        self._servability = servability
        self._entitlements = entitlements
        self._operators = operators
        self._audit = audit
        self._clock = clock or SystemClock()

    async def _resolve_tenant(self, ref: TenantRef) -> TenantRecord:
        record = await self._tenants.get(ref)
        if record is None:
            raise TenantNotFound(ref.slug or str(ref.id))
        return record

    def _build(
        self,
        record: TenantRecord,
        principal: Principal,
        *,
        request_id: str,
        correlation_id: str | None,
        trace_id: str | None,
        privilege: PrivilegeContext | None,
    ) -> TenantContext:
        return TenantContext(
            tenant_id=record.id,
            tenant_slug=record.slug,
            strategy=record.strategy,
            principal=principal,
            request_id=request_id,
            correlation_id=correlation_id or request_id,
            trace_id=trace_id,
            privilege=privilege,
        )

    async def for_principal(
        self,
        principal: Principal,
        tenant_ref: TenantRef,
        *,
        request_id: str,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> TenantContext:
        if not await self._principals.is_active(principal):
            raise UnknownPrincipal(str(principal.id))
        record = await self._resolve_tenant(tenant_ref)
        await self._servability.assert_servable(record.id)
        if not await self._entitlements.can_act(principal, record.id):
            raise TenantAccessDenied(f"principal {principal.id} cannot act in {record.id}")
        return self._build(
            record,
            principal,
            request_id=request_id,
            correlation_id=correlation_id,
            trace_id=trace_id,
            privilege=None,
        )

    async def for_operator(
        self,
        operator: Principal,
        tenant_ref: TenantRef,
        capability: str,
        *,
        justification: str,
        ttl: timedelta | None = None,
        request_id: str,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> TenantContext:
        if operator.kind is not PrincipalType.PLATFORM_OPERATOR:
            raise AuthorizationError("operator context requires a platform operator principal")
        if not justification.strip():
            raise AuthorizationError("operator context requires a justification")
        effective_ttl = ttl or self._config.operator_ttl
        if effective_ttl > self._config.operator_ttl:
            raise AuthorizationError("requested ttl exceeds the configured maximum")
        if not await self._operators.authorize(operator, capability):
            raise AuthorizationError(f"operator lacks capability {capability}")
        record = await self._resolve_tenant(tenant_ref)
        await self._servability.assert_servable(record.id)
        now = self._clock.now()
        privilege = PrivilegeContext(
            kind=PrivilegeKind.OPERATOR,
            capability=capability,
            justification=justification,
            actor=operator,
            issued_at=now,
            expires_at=now + effective_ttl,
        )
        await self._audit.record_privilege(
            kind=PrivilegeKind.OPERATOR,
            capability=capability,
            justification=justification,
            actor=operator,
            tenant_id=record.id,
        )
        return self._build(
            record,
            operator,
            request_id=request_id,
            correlation_id=correlation_id,
            trace_id=trace_id,
            privilege=privilege,
        )

    def for_system(
        self,
        tenant: TenantRecord,
        *,
        purpose: str,
        issuer: _PrivilegeIssuer,
    ) -> TenantContext:
        if not isinstance(issuer, _PrivilegeIssuer):
            raise AuthorizationError("system context requires the internal privilege issuer")
        now = self._clock.now()
        privilege = PrivilegeContext(
            kind=PrivilegeKind.SYSTEM,
            capability=purpose,
            justification=None,
            actor=Principal(kind=PrincipalType.PLATFORM_OPERATOR, id=uuid.uuid4()),
            issued_at=now,
            expires_at=None,
        )
        return self._build(
            tenant,
            privilege.actor,
            request_id=uuid.uuid4().hex,
            correlation_id=None,
            trace_id=None,
            privilege=privilege,
        )

    def for_test(
        self,
        tenant: TenantRecord,
        *,
        principal: Principal,
        issuer: _PrivilegeIssuer,
    ) -> TenantContext:
        if not isinstance(issuer, _PrivilegeIssuer):
            raise AuthorizationError("test context requires the internal privilege issuer")
        if not self._config.allow_test_contexts:
            raise AuthorizationError("test contexts are disabled by configuration")
        now = self._clock.now()
        privilege = PrivilegeContext(
            kind=PrivilegeKind.TEST,
            capability=None,
            justification=None,
            actor=principal,
            issued_at=now,
            expires_at=None,
        )
        return self._build(
            tenant,
            principal,
            request_id=uuid.uuid4().hex,
            correlation_id=None,
            trace_id=None,
            privilege=privilege,
        )
```

Note: the system context's actor uses `PrincipalType.PLATFORM_OPERATOR` with
`operator_level=None`; `PrivilegeKind.SYSTEM` is what distinguishes it.

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_context_factory.py -v`
Expected: PASS (11 passed)

- [ ] **Step 6: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/context.py tests/support/context_fakes.py tests/unit/test_context_factory.py
git commit -m "feat: context factory with ports and privileged issuance"
```

---

### Task 4: Signed context envelope

**Files:**
- Modify: `src/jdlib/context.py` (append envelope codec)
- Create: `tests/unit/test_envelope.py`

**Interfaces:**
- Consumes: Task 2 types, `jdlib.config.ContextConfig`.
- Produces: `TenantContextEnvelope`, `EnvelopeCodec` with `encode(context) -> str` and `decode(token) -> TenantContextEnvelope`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_envelope.py`:

```python
import base64
import json
import uuid
from datetime import timedelta

import pytest

from jdlib.config import ContextConfig
from jdlib.context import EnvelopeCodec, Principal, TenantContext
from jdlib.control.enums import PlacementStrategy, PrincipalType
from jdlib.errors import ExpiredToken, InvalidToken
from tests.support.context_fakes import FrozenClock

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalType.USER, id=uuid.uuid4(), scopes=frozenset({"x"})),
        request_id="req-1",
        correlation_id="corr-1",
        trace_id="trace-1",
    )


def _codec(clock: FrozenClock | None = None) -> EnvelopeCodec:
    return EnvelopeCodec(
        config=ContextConfig(signing_key="sign-key"), clock=clock or FrozenClock()
    )


def test_roundtrip_preserves_identity_fields_only():
    codec = _codec()
    envelope = codec.decode(codec.encode(_context()))
    assert envelope.tenant_id == TENANT_ID
    assert envelope.principal_type is PrincipalType.USER
    assert envelope.request_id == "req-1"
    assert envelope.correlation_id == "corr-1"
    assert envelope.trace_id == "trace-1"
    assert not hasattr(envelope, "scopes")


def test_token_does_not_contain_permissions_or_scopes():
    token = _codec().encode(_context())
    payload_b64 = token.split(".")[0]
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    assert "scopes" not in payload
    assert "permissions" not in payload


def test_tampered_payload_rejected():
    codec = _codec()
    payload, signature = codec.encode(_context()).split(".")
    forged = base64.urlsafe_b64encode(
        json.dumps({"tenant_id": str(TENANT_ID)}).encode()
    ).rstrip(b"=").decode()
    with pytest.raises(InvalidToken):
        codec.decode(f"{forged}.{signature}")


def test_tampered_signature_rejected():
    codec = _codec()
    payload, _ = codec.encode(_context()).split(".")
    with pytest.raises(InvalidToken):
        codec.decode(f"{payload}.AAAA")


def test_expired_envelope_rejected():
    clock = FrozenClock()
    codec = _codec(clock)
    token = codec.encode(_context())
    clock.advance(timedelta(minutes=6))
    with pytest.raises(ExpiredToken):
        codec.decode(token)


def test_future_envelope_rejected():
    clock = FrozenClock()
    codec = _codec(clock)
    token = codec.encode(_context())
    clock.advance(timedelta(minutes=-5))
    with pytest.raises(InvalidToken):
        codec.decode(token)


def test_malformed_token_rejected():
    with pytest.raises(InvalidToken):
        _codec().decode("not-a-token")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_envelope.py -v`
Expected: FAIL with `ImportError: cannot import name 'EnvelopeCodec'`

- [ ] **Step 3: Append the envelope codec to `src/jdlib/context.py`**

Add imports: `import base64`, `import hashlib`, `import hmac`, `import json`.

```python
@dataclass(frozen=True, slots=True)
class TenantContextEnvelope:
    tenant_id: uuid.UUID
    principal_type: PrincipalType
    principal_id: uuid.UUID
    request_id: str
    correlation_id: str
    trace_id: str | None
    issued_at: datetime
    signature: bytes


class EnvelopeCodec:
    def __init__(self, *, config: ContextConfig, clock: Clock | None = None) -> None:
        self._key = config.signing_key.get_secret_value().encode()
        self._ttl = config.envelope_ttl
        self._clock = clock or SystemClock()

    def _sign(self, payload: bytes) -> bytes:
        return hmac.new(self._key, payload, hashlib.sha256).digest()

    def encode(self, context: TenantContext) -> str:
        payload = {
            "tenant_id": str(context.tenant_id),
            "principal_type": context.principal.kind.value,
            "principal_id": str(context.principal.id),
            "request_id": context.request_id,
            "correlation_id": context.correlation_id,
            "trace_id": context.trace_id,
            "issued_at": self._clock.now().isoformat(),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return f"{_b64(raw)}.{_b64(self._sign(raw))}"

    def decode(self, token: str) -> TenantContextEnvelope:
        try:
            payload_b64, signature_b64 = token.split(".")
            raw = _unb64(payload_b64)
            signature = _unb64(signature_b64)
        except (ValueError, TypeError) as exc:
            raise InvalidToken("malformed envelope") from exc
        if not hmac.compare_digest(signature, self._sign(raw)):
            raise InvalidToken("envelope signature mismatch")
        try:
            payload = json.loads(raw)
            issued_at = datetime.fromisoformat(payload["issued_at"])
            envelope = TenantContextEnvelope(
                tenant_id=uuid.UUID(payload["tenant_id"]),
                principal_type=PrincipalType(payload["principal_type"]),
                principal_id=uuid.UUID(payload["principal_id"]),
                request_id=str(payload["request_id"]),
                correlation_id=str(payload["correlation_id"]),
                trace_id=payload["trace_id"],
                issued_at=issued_at,
                signature=signature,
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise InvalidToken("invalid envelope payload") from exc
        now = self._clock.now()
        if issued_at - now > timedelta(seconds=60):
            raise InvalidToken("envelope issued in the future")
        if now - issued_at > self._ttl:
            raise ExpiredToken("envelope expired")
        return envelope


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_envelope.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/context.py tests/unit/test_envelope.py
git commit -m "feat: signed tenant context envelope"
```

---

### Task 5: Resolver chain

**Files:**
- Create: `src/jdlib/tenancy/__init__.py`
- Create: `src/jdlib/tenancy/resolution.py`
- Create: `tests/unit/test_resolution.py`
- Modify: `docs/jdlib/07-implementation-design.md` (note `RequestInfo` lives in `tenancy/resolution.py` and is imported by `authn/base.py`; add `tenancy/resolution.py` to the file map comments)

**Interfaces:**
- Consumes: `Principal`, `TenantRef`; `ResolverConfig`, `ResolverName`.
- Produces: `RequestInfo(headers, query, path, host, claims)`; `TenantResolver` protocol; `JwtClaimResolver`, `SubdomainResolver`, `PathResolver`, `HeaderResolver`, `ApiKeyResolver`, `ResolverChain`, `build_chain(config)`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_resolution.py`:

```python
import uuid

from jdlib.config import ResolverConfig, ResolverName
from jdlib.context import Principal, TenantRef
from jdlib.control.enums import PrincipalType
from jdlib.tenancy.resolution import (
    ApiKeyResolver,
    HeaderResolver,
    JwtClaimResolver,
    PathResolver,
    RequestInfo,
    ResolverChain,
    SubdomainResolver,
    build_chain,
)

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _request(
    *, headers: dict[str, str] | None = None, path: str = "/", host: str = "app.example.com",
    claims: dict[str, object] | None = None,
) -> RequestInfo:
    return RequestInfo(
        headers=headers or {}, query={}, path=path, host=host, claims=claims or {}
    )


async def test_jwt_claim_resolver_accepts_uuid_and_slug():
    resolver = JwtClaimResolver(claim="tid")
    assert await resolver.resolve(_request(claims={"tid": str(TENANT_ID)}), None) == TenantRef(
        id=TENANT_ID
    )
    assert await resolver.resolve(_request(claims={"tid": "acme"}), None) == TenantRef(slug="acme")
    assert await resolver.resolve(_request(), None) is None


async def test_subdomain_resolver():
    resolver = SubdomainResolver(base_domain="app.example.com")
    assert await resolver.resolve(_request(host="acme.app.example.com"), None) == TenantRef(
        slug="acme"
    )
    assert await resolver.resolve(_request(host="app.example.com"), None) is None
    assert await resolver.resolve(_request(host="evil.com"), None) is None
    assert await resolver.resolve(_request(host="ACME.app.example.com"), None) == TenantRef(
        slug="acme"
    )


async def test_path_resolver():
    resolver = PathResolver(prefix="/t/")
    assert await resolver.resolve(_request(path="/t/acme/invoices"), None) == TenantRef(slug="acme")
    assert await resolver.resolve(_request(path="/t/"), None) is None
    assert await resolver.resolve(_request(path="/other/acme"), None) is None


async def test_header_resolver_is_case_insensitive():
    resolver = HeaderResolver(name="X-Tenant-Slug")
    assert await resolver.resolve(_request(headers={"x-tenant-slug": "acme"}), None) == TenantRef(
        slug="acme"
    )
    assert await resolver.resolve(_request(), None) is None


async def test_api_key_resolver_uses_pinned_tenant():
    resolver = ApiKeyResolver()
    pinned = Principal(kind=PrincipalType.SERVICE_ACCOUNT, id=uuid.uuid4(), tenant_id=TENANT_ID)
    assert await resolver.resolve(_request(), pinned) == TenantRef(id=TENANT_ID)
    assert await resolver.resolve(_request(), None) is None
    assert (
        await resolver.resolve(
            _request(), Principal(kind=PrincipalType.USER, id=uuid.uuid4())
        )
        is None
    )


async def test_chain_first_non_none_wins():
    chain = ResolverChain(
        [HeaderResolver(name="X-Tenant-Slug"), PathResolver(prefix="/t/")]
    )
    request = _request(headers={"x-tenant-slug": "from-header"}, path="/t/from-path")
    assert await chain.resolve(request, None) == TenantRef(slug="from-header")
    assert await ResolverChain([PathResolver(prefix="/t/")]).resolve(request, None) == TenantRef(
        slug="from-path"
    )
    assert await ResolverChain([]).resolve(request, None) is None


def test_build_chain_maps_config_and_skips_subdomain_without_base_domain():
    config = ResolverConfig(order=[ResolverName.SUBDOMAIN, ResolverName.HEADER])
    assert len(build_chain(config).resolvers) == 1
    config = ResolverConfig(
        order=[ResolverName.SUBDOMAIN, ResolverName.HEADER], base_domain="app.example.com"
    )
    assert len(build_chain(config).resolvers) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_resolution.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.tenancy'`

- [ ] **Step 3: Implement `src/jdlib/tenancy/__init__.py` (empty) and `src/jdlib/tenancy/resolution.py`**

```python
from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from typing import NamedTuple, Protocol

from jdlib.config import ResolverConfig, ResolverName
from jdlib.context import Principal, TenantRef
from jdlib.control.enums import PrincipalType

_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")


class RequestInfo(NamedTuple):
    headers: Mapping[str, str]
    query: Mapping[str, str]
    path: str
    host: str
    claims: Mapping[str, object] = {}


class TenantResolver(Protocol):
    async def resolve(
        self, request: RequestInfo, principal: Principal | None
    ) -> TenantRef | None: ...


def _slug_ref(value: str) -> TenantRef | None:
    candidate = value.strip().lower()
    if not candidate:
        return None
    try:
        return TenantRef(id=uuid.UUID(candidate))
    except ValueError:
        pass
    if _SLUG_PATTERN.match(candidate):
        return TenantRef(slug=candidate)
    return None


class JwtClaimResolver:
    def __init__(self, *, claim: str = "tid") -> None:
        self._claim = claim

    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        value = request.claims.get(self._claim)
        if not isinstance(value, str):
            return None
        return _slug_ref(value)


class SubdomainResolver:
    def __init__(self, *, base_domain: str) -> None:
        self._base = base_domain.strip().lower().rstrip(".")

    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        host = request.host.strip().lower().rstrip(".")
        suffix = f".{self._base}"
        if not host.endswith(suffix):
            return None
        label = host[: -len(suffix)]
        if not label or "." in label:
            return None
        return _slug_ref(label)


class PathResolver:
    def __init__(self, *, prefix: str = "/t/") -> None:
        self._prefix = prefix if prefix.endswith("/") else f"{prefix}/"

    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        if not request.path.startswith(self._prefix):
            return None
        remainder = request.path[len(self._prefix):]
        segment = remainder.split("/", 1)[0]
        return _slug_ref(segment)


class HeaderResolver:
    def __init__(self, *, name: str = "X-Tenant-Slug") -> None:
        self._name = name.lower()

    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        value = request.headers.get(self._name)
        if value is None:
            return None
        return _slug_ref(value)


class ApiKeyResolver:
    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        if principal is None or principal.kind is not PrincipalType.SERVICE_ACCOUNT:
            return None
        if principal.tenant_id is None:
            return None
        return TenantRef(id=principal.tenant_id)


class ResolverChain:
    def __init__(self, resolvers: Sequence[TenantResolver]) -> None:
        self.resolvers = list(resolvers)

    async def resolve(self, request: RequestInfo, principal: Principal | None) -> TenantRef | None:
        for resolver in self.resolvers:
            resolved = await resolver.resolve(request, principal)
            if resolved is not None:
                return resolved
        return None


def build_chain(config: ResolverConfig) -> ResolverChain:
    resolvers: list[TenantResolver] = []
    for name in config.order:
        if name is ResolverName.JWT_CLAIM:
            resolvers.append(JwtClaimResolver(claim=config.jwt_claim))
        elif name is ResolverName.SUBDOMAIN:
            if config.base_domain:
                resolvers.append(SubdomainResolver(base_domain=config.base_domain))
        elif name is ResolverName.PATH:
            resolvers.append(PathResolver(prefix=config.path_prefix))
        elif name is ResolverName.HEADER:
            resolvers.append(HeaderResolver(name=config.header_name))
        elif name is ResolverName.API_KEY:
            resolvers.append(ApiKeyResolver())
    return ResolverChain(resolvers)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_resolution.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Update the 07 file map**

In `docs/jdlib/07-implementation-design.md`, change the `tenancy/` line to:

```
├── tenancy/              # resolution.py (RequestInfo + resolvers) · middleware.py · jobs.py
```

and in §9 Authentication, note that `RequestInfo` is defined in `jdlib.tenancy.resolution` and imported by `authn/base.py`.

- [ ] **Step 6: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/tenancy tests/unit/test_resolution.py docs/jdlib/07-implementation-design.md
git commit -m "feat: tenant resolver chain"
```

---

### Task 6: Context propagator and tenant job decorator

**Files:**
- Create: `src/jdlib/tenancy/jobs.py`
- Create: `tests/unit/test_jobs.py`

**Interfaces:**
- Consumes: `EnvelopeCodec`, `ContextFactory` ports (`PrincipalDirectory`, `TenantDirectory`, `ServabilityChecker`, `EntitlementChecker`), `Principal`, `TenantRef`, `context_scope`.
- Produces: `ContextPropagator.reconstruct(token) -> TenantContext`; `tenant_job(propagator)` decorator that wraps `async def fn(envelope: str, ...)`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_jobs.py`:

```python
import uuid

import pytest

from jdlib.config import ContextConfig
from jdlib.context import (
    ContextPropagator,
    EnvelopeCodec,
    Principal,
    TenantContext,
    TenantRecord,
    current_tenant,
)
from jdlib.control.enums import PlacementStrategy, PrincipalType, TenantStatus
from jdlib.errors import (
    InvalidToken,
    MissingTenantContext,
    TenantAccessDenied,
    TenantSuspended,
    UnknownPrincipal,
)
from jdlib.tenancy.jobs import tenant_job
from tests.support.context_fakes import (
    DictTenants,
    EntitlementsStub,
    FrozenClock,
    ServabilityStub,
    StaticPrincipals,
)

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
USER_ID = uuid.uuid4()


def _record() -> TenantRecord:
    return TenantRecord(
        id=TENANT_ID, slug="acme", status=TenantStatus.ACTIVE, strategy=PlacementStrategy.SHARED
    )


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalType.USER, id=USER_ID),
        request_id="req-1",
        correlation_id="corr-1",
    )


def _propagator(
    *,
    active: set[uuid.UUID] | None = None,
    suspended: set[uuid.UUID] | None = None,
    allowed: bool = True,
) -> tuple[ContextPropagator, EnvelopeCodec]:
    codec = EnvelopeCodec(config=ContextConfig(signing_key="k"), clock=FrozenClock())
    propagator = ContextPropagator(
        codec=codec,
        principals=StaticPrincipals(active if active is not None else {USER_ID}),
        tenants=DictTenants([_record()]),
        servability=ServabilityStub(suspended),
        entitlements=EntitlementsStub({(USER_ID, TENANT_ID)} if allowed else set()),
    )
    return propagator, codec


async def test_reconstruct_rebuilds_context_without_privilege():
    propagator, codec = _propagator()
    context = await propagator.reconstruct(codec.encode(_context()))
    assert context.tenant_id == TENANT_ID
    assert context.principal.kind is PrincipalType.USER
    assert context.principal.id == USER_ID
    assert context.privilege is None
    assert context.request_id == "req-1"
    assert context.correlation_id == "corr-1"


async def test_reconstruct_rejects_deactivated_principal():
    propagator, codec = _propagator(active=set())
    with pytest.raises(UnknownPrincipal):
        await propagator.reconstruct(codec.encode(_context()))


async def test_reconstruct_rejects_revoked_membership():
    propagator, codec = _propagator(allowed=False)
    with pytest.raises(TenantAccessDenied):
        await propagator.reconstruct(codec.encode(_context()))


async def test_reconstruct_rejects_suspended_tenant():
    propagator, codec = _propagator(suspended={TENANT_ID})
    with pytest.raises(TenantSuspended):
        await propagator.reconstruct(codec.encode(_context()))


async def test_tenant_job_installs_and_clears_context():
    propagator, codec = _propagator()

    @tenant_job(propagator)
    async def handler() -> str:
        return str(current_tenant().tenant_id)

    assert await handler(codec.encode(_context())) == str(TENANT_ID)
    with pytest.raises(MissingTenantContext):
        current_tenant()


async def test_tenant_job_clears_context_on_error():
    propagator, codec = _propagator()

    @tenant_job(propagator)
    async def handler() -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await handler(codec.encode(_context()))
    with pytest.raises(MissingTenantContext):
        current_tenant()


async def test_tenant_job_rejects_bad_envelope():
    propagator, _ = _propagator()

    @tenant_job(propagator)
    async def handler() -> None:
        raise AssertionError("must not run")

    with pytest.raises(InvalidToken):
        await handler("garbage")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_jobs.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.tenancy.jobs'`

- [ ] **Step 3: Implement `src/jdlib/tenancy/jobs.py`**

```python
from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import TypeVar

from jdlib.context import (
    ContextFactory,
    EnvelopeCodec,
    EntitlementChecker,
    Principal,
    PrincipalDirectory,
    ServabilityChecker,
    TenantContext,
    TenantDirectory,
    TenantRef,
    context_scope,
)
from jdlib.errors import TenantNotFound, TenantAccessDenied, UnknownPrincipal

F = TypeVar("F", bound=Callable[..., Awaitable[object]])


class ContextPropagator:
    def __init__(
        self,
        *,
        codec: EnvelopeCodec,
        principals: PrincipalDirectory,
        tenants: TenantDirectory,
        servability: ServabilityChecker,
        entitlements: EntitlementChecker,
    ) -> None:
        self._codec = codec
        self._principals = principals
        self._tenants = tenants
        self._servability = servability
        self._entitlements = entitlements

    async def reconstruct(self, token: str) -> TenantContext:
        envelope = self._codec.decode(token)
        principal = Principal(kind=envelope.principal_type, id=envelope.principal_id)
        if not await self._principals.is_active(principal):
            raise UnknownPrincipal(str(principal.id))
        record = await self._tenants.get(TenantRef(id=envelope.tenant_id))
        if record is None:
            raise TenantNotFound(str(envelope.tenant_id))
        await self._servability.assert_servable(record.id)
        if not await self._entitlements.can_act(principal, record.id):
            raise TenantAccessDenied(f"principal {principal.id} cannot act in {record.id}")
        return TenantContext(
            tenant_id=record.id,
            tenant_slug=record.slug,
            strategy=record.strategy,
            principal=principal,
            request_id=envelope.request_id,
            correlation_id=envelope.correlation_id,
            trace_id=envelope.trace_id,
            privilege=None,
        )


def tenant_job(propagator: ContextPropagator) -> Callable[[F], F]:
    def decorate(fn: F) -> F:
        @functools.wraps(fn)
        async def wrapper(envelope: str, *args: object, **kwargs: object) -> object:
            context = await propagator.reconstruct(envelope)
            with context_scope(context):
                return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_jobs.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/tenancy/jobs.py tests/unit/test_jobs.py
git commit -m "feat: context propagator and tenant job decorator"
```

---

### Task 7: ASGI middleware and HTTP error mapping

**Files:**
- Create: `src/jdlib/tenancy/middleware.py`
- Create: `tests/unit/test_middleware.py`

**Interfaces:**
- Consumes: `ContextFactory`, `ResolverChain`, `RequestInfo`, `context_scope`, `jdlib.errors`.
- Produces: `PrincipalProvider` protocol; `TenantMiddleware(app, *, factory, chain, principal_provider)`; `http_status_for(exc) -> int`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_middleware.py`:

```python
import json
import uuid

import pytest

from jdlib.config import ContextConfig
from jdlib.context import ContextFactory, Principal, TenantRecord
from jdlib.control.enums import PlacementStrategy, PrincipalType, TenantStatus
from jdlib.errors import (
    AuthenticationError,
    AuthorizationError,
    CrossTenantReferenceError,
    JdlibError,
    TenantAccessDenied,
    TenantNotFound,
    TenantSuspended,
)
from jdlib.tenancy.middleware import PrincipalProvider, TenantMiddleware, http_status_for
from jdlib.tenancy.resolution import HeaderResolver, ResolverChain
from tests.support.context_fakes import (
    DictTenants,
    EntitlementsStub,
    FrozenClock,
    OperatorsStub,
    RecordingPrivilegeAudit,
    ServabilityStub,
    StaticPrincipals,
)

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
USER_ID = uuid.uuid4()


def test_http_status_mapping_is_frozen():
    assert http_status_for(AuthenticationError()) == 401
    assert http_status_for(AuthorizationError()) == 403
    assert http_status_for(TenantNotFound("x")) == 404
    assert http_status_for(TenantAccessDenied("x")) == 404
    assert http_status_for(TenantSuspended("x")) == 423
    assert http_status_for(CrossTenantReferenceError("r", "a", "b")) == 409
    assert http_status_for(JdlibError("other")) == 500


class _Provider:
    def __init__(self, principal: Principal | None) -> None:
        self._principal = principal

    async def __call__(self, request: object) -> Principal | None:
        return self._principal


def _middleware(
    provider: PrincipalProvider, inner, *, active: set[uuid.UUID] | None = None
) -> TenantMiddleware:
    factory = ContextFactory(
        config=ContextConfig(signing_key="k"),
        principals=StaticPrincipals(active if active is not None else {USER_ID}),
        tenants=DictTenants(
            [
                TenantRecord(
                    id=TENANT_ID,
                    slug="acme",
                    status=TenantStatus.ACTIVE,
                    strategy=PlacementStrategy.SHARED,
                )
            ]
        ),
        servability=ServabilityStub(),
        entitlements=EntitlementsStub({(USER_ID, TENANT_ID)}),
        operators=OperatorsStub(),
        audit=RecordingPrivilegeAudit(),
        clock=FrozenClock(),
    )
    return TenantMiddleware(
        inner,
        factory=factory,
        chain=ResolverChain([HeaderResolver(name="X-Tenant-Slug")]),
        principal_provider=provider,
    )


async def _run(middleware: TenantMiddleware, headers: list[tuple[bytes, bytes]]) -> dict[str, object]:
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request"}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/invoices",
        "headers": headers,
        "query_string": b"",
    }
    await middleware(scope, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return {"status": status, "body": body, "sent": sent}


async def test_happy_path_installs_context_for_inner_app():
    seen: list[str] = []

    async def inner(scope, receive, send):
        from jdlib.context import current_tenant

        seen.append(current_tenant().tenant_slug)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = _middleware(_Provider(Principal(kind=PrincipalType.USER, id=USER_ID)), inner)
    result = await _run(middleware, [(b"x-tenant-slug", b"acme")])
    assert result["status"] == 200
    assert seen == ["acme"]


async def test_missing_principal_is_401():
    async def inner(scope, receive, send):
        raise AssertionError("must not run")

    middleware = _middleware(_Provider(None), inner)
    result = await _run(middleware, [(b"x-tenant-slug", b"acme")])
    assert result["status"] == 401
    assert json.loads(result["body"])["error"] == "AuthenticationError"


async def test_unresolved_tenant_is_404():
    async def inner(scope, receive, send):
        raise AssertionError("must not run")

    middleware = _middleware(_Provider(Principal(kind=PrincipalType.USER, id=USER_ID)), inner)
    result = await _run(middleware, [])
    assert result["status"] == 404


async def test_denied_principal_is_404():
    async def inner(scope, receive, send):
        raise AssertionError("must not run")

    other_user = uuid.uuid4()
    middleware = _middleware(
        _Provider(Principal(kind=PrincipalType.USER, id=other_user)), inner, active={other_user}
    )
    result = await _run(middleware, [(b"x-tenant-slug", b"acme")])
    assert result["status"] == 404


async def test_context_is_cleared_after_request():
    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = _middleware(_Provider(Principal(kind=PrincipalType.USER, id=USER_ID)), inner)
    await _run(middleware, [(b"x-tenant-slug", b"acme")])
    from jdlib.context import current_tenant
    from jdlib.errors import MissingTenantContext

    with pytest.raises(MissingTenantContext):
        current_tenant()


async def test_non_http_scope_passes_through():
    calls: list[str] = []

    async def inner(scope, receive, send):
        calls.append(scope["type"])

    middleware = _middleware(_Provider(None), inner)
    await middleware({"type": "lifespan"}, None, None)  # type: ignore[arg-type]
    assert calls == ["lifespan"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_middleware.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.tenancy.middleware'`

- [ ] **Step 3: Implement `src/jdlib/tenancy/middleware.py`**

```python
from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Protocol
from urllib.parse import parse_qs

from jdlib.context import ContextFactory, Principal, context_scope
from jdlib.errors import (
    AuthenticationError,
    AuthorizationError,
    CrossTenantReferenceError,
    JdlibError,
    TenantAccessDenied,
    TenantNotFound,
    TenantNotWritable,
    TenantSuspended,
)
from jdlib.tenancy.resolution import RequestInfo, ResolverChain

ASGIApp = Callable[..., Awaitable[None]]

_STATUS_MAP: tuple[tuple[type[JdlibError], int], ...] = (
    (AuthenticationError, 401),
    (AuthorizationError, 403),
    (TenantNotFound, 404),
    (TenantAccessDenied, 404),
    (TenantSuspended, 423),
    (TenantNotWritable, 423),
    (CrossTenantReferenceError, 409),
)


def http_status_for(exc: JdlibError) -> int:
    for error_type, status in _STATUS_MAP:
        if isinstance(exc, error_type):
            return status
    return 500


class PrincipalProvider(Protocol):
    async def __call__(self, request: RequestInfo) -> Principal | None: ...


def _request_info(scope: Mapping[str, Any]) -> RequestInfo:
    headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in scope.get("headers", [])
    }
    query = {
        key: values[-1] for key, values in parse_qs(
            scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True
        ).items()
    }
    return RequestInfo(
        headers=headers,
        query=query,
        path=scope.get("path", "/"),
        host=headers.get("host", ""),
        claims={},
    )


def _request_ids(headers: Mapping[str, str]) -> tuple[str, str, str | None]:
    request_id = uuid.uuid4().hex
    correlation_id = headers.get("x-correlation-id", request_id)
    trace_id: str | None = None
    traceparent = headers.get("traceparent")
    if traceparent:
        parts = traceparent.split("-")
        if len(parts) >= 4 and len(parts[1]) == 32:
            trace_id = parts[1]
    return request_id, correlation_id, trace_id


async def _send_error(send: Callable[..., Awaitable[None]], exc: JdlibError) -> None:
    status = http_status_for(exc)
    body = json.dumps({"error": type(exc).__name__, "detail": str(exc)}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})


class TenantMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        factory: ContextFactory,
        chain: ResolverChain,
        principal_provider: PrincipalProvider,
    ) -> None:
        self.app = app
        self._factory = factory
        self._chain = chain
        self._principal_provider = principal_provider

    async def __call__(self, scope: Mapping[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = _request_info(scope)
        try:
            principal = await self._principal_provider(request)
            if principal is None:
                raise AuthenticationError("no credentials presented")
            tenant_ref = await self._chain.resolve(request, principal)
            if tenant_ref is None:
                raise TenantNotFound("tenant could not be resolved")
            request_id, correlation_id, trace_id = _request_ids(request.headers)
            context = await self._factory.for_principal(
                principal,
                tenant_ref,
                request_id=request_id,
                correlation_id=correlation_id,
                trace_id=trace_id,
            )
        except JdlibError as exc:
            await _send_error(send, exc)
            return
        with context_scope(context):
            await self.app(scope, receive, send)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_middleware.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Full suite, lint, type check**

Run: `.venv/Scripts/python -m pytest -q && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/jdlib/tenancy/middleware.py tests/unit/test_middleware.py
git commit -m "feat: ASGI tenant middleware and frozen HTTP error mapping"
```

---

## Phase 2 Exit Criteria

- [ ] `.venv/Scripts/python -m pytest -q` green (Phase 1 suite still passes; ~49 new unit tests).
- [ ] `ruff` and `mypy` strict clean.
- [ ] No context access without an active context (I1); context install/clear verified in middleware and jobs (I5, I7).
- [ ] Envelopes are signed, TTL-bounded, permission-free; reconstruct re-verifies principal, tenant, servability, entitlement (I7).
- [ ] Privileged contexts require the internal issuer, a capability, a justification (operator), and an audit record.
- [ ] `scoped_key` is versioned and collision-safe (I8).
- [ ] HTTP error mapping matches the frozen table.

## Plan Series (remaining)

- Plan 3 — Phase 3: `TenantSession`, scoping/stamping/validation events, `rawsql.py` validator, `UnitOfWork`, `TenantRepository`, `SessionRouter`, `IsolationStrategy` + shared adapter.
- Plan 4 — Phases 4–6: `TenantRegistry` lifecycle/provisioning, authorization (catalog, registry, PDP, guards, `AccessControl`), authentication adapters.
- Plan 5 — Phases 7–9: schema and database strategies, RLS emission and tests.
- Plan 6 — Phase 10: audit sinks, `jdlib.testing`, FastAPI/CLI integrations, docs.
