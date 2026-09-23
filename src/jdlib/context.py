from __future__ import annotations

import base64
import contextvars
import hashlib
import hmac
import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol
from urllib.parse import quote

from jdlib.config import ContextConfig
from jdlib.control.enums import OperatorLevel, PlacementStrategy, TenantStatus
from jdlib.errors import (
    AuthorizationError,
    ExpiredToken,
    InvalidToken,
    MissingTenantContext,
    TenantAccessDenied,
    TenantNotFound,
    UnknownPrincipal,
)


class PrincipalKind(StrEnum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    PLATFORM_OPERATOR = "platform_operator"
    ANONYMOUS = "anonymous"


class PrivilegeKind(StrEnum):
    OPERATOR = "operator"
    SYSTEM = "system"
    TEST = "test"


@dataclass(frozen=True, slots=True)
class Principal:
    kind: PrincipalKind
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
    target_handle: str | None = None


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


class PrincipalDirectory(Protocol):
    async def is_active(self, principal: Principal) -> bool: ...


class TenantDirectory(Protocol):
    async def get(self, ref: TenantRef) -> TenantRecord | None: ...


class ServabilityChecker(Protocol):
    async def assert_servable(self, tenant_id: uuid.UUID) -> TenantRecord: ...


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
        if (
            principal.kind is PrincipalKind.SERVICE_ACCOUNT
            and principal.tenant_id != record.id
        ):
            raise TenantAccessDenied(
                f"principal {principal.id} is not pinned to tenant {record.id}"
            )
        if not await self._entitlements.can_act(principal, record.id):
            raise TenantAccessDenied(f"principal {principal.id} cannot act in {record.id}")
        await self._servability.assert_servable(record.id)
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
        if operator.kind is not PrincipalKind.PLATFORM_OPERATOR:
            raise AuthorizationError("operator context requires a platform operator principal")
        if not justification.strip():
            raise AuthorizationError("operator context requires a justification")
        effective_ttl = ttl if ttl is not None else self._config.operator_ttl
        if effective_ttl <= timedelta(0):
            raise AuthorizationError("ttl must be positive")
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

    async def for_system(
        self,
        tenant: TenantRecord,
        *,
        purpose: str,
        issuer: _PrivilegeIssuer,
    ) -> TenantContext:
        if issuer is not PRIVILEGE_ISSUER:
            raise AuthorizationError("system context requires the internal privilege issuer")
        now = self._clock.now()
        privilege = PrivilegeContext(
            kind=PrivilegeKind.SYSTEM,
            capability=purpose,
            justification=None,
            actor=Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4()),
            issued_at=now,
            expires_at=None,
        )
        await self._audit.record_privilege(
            kind=PrivilegeKind.SYSTEM,
            capability=purpose or None,
            justification=None,
            actor=privilege.actor,
            tenant_id=tenant.id,
        )
        return self._build(
            tenant,
            privilege.actor,
            request_id=uuid.uuid4().hex,
            correlation_id=None,
            trace_id=None,
            privilege=privilege,
        )

    async def for_test(
        self,
        tenant: TenantRecord,
        *,
        principal: Principal,
        issuer: _PrivilegeIssuer,
    ) -> TenantContext:
        if issuer is not PRIVILEGE_ISSUER:
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
        await self._audit.record_privilege(
            kind=PrivilegeKind.TEST,
            capability=None,
            justification=None,
            actor=principal,
            tenant_id=tenant.id,
        )
        return self._build(
            tenant,
            principal,
            request_id=uuid.uuid4().hex,
            correlation_id=None,
            trace_id=None,
            privilege=privilege,
        )


@dataclass(frozen=True, slots=True)
class TenantContextEnvelope:
    tenant_id: uuid.UUID
    principal_type: PrincipalKind
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
                principal_type=PrincipalKind(payload["principal_type"]),
                principal_id=uuid.UUID(payload["principal_id"]),
                request_id=str(payload["request_id"]),
                correlation_id=str(payload["correlation_id"]),
                trace_id=str(payload["trace_id"]) if payload["trace_id"] is not None else None,
                issued_at=issued_at,
                signature=signature,
            )
            now = self._clock.now()
            if issued_at - now > timedelta(seconds=60):
                raise InvalidToken("envelope issued in the future")
            if now - issued_at > self._ttl:
                raise ExpiredToken("envelope expired")
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise InvalidToken("invalid envelope payload") from exc
        return envelope


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded, altchars=b"-_", validate=True)
