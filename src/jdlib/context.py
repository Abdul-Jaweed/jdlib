from __future__ import annotations

import contextvars
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
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
        return datetime.now(UTC)


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
