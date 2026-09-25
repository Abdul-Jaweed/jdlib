from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from jdlib.context import (
    Clock,
    Principal,
    PrincipalKind,
    PrivilegeKind,
    TenantRecord,
    TenantRef,
)
from jdlib.control.enums import PlacementStrategy, TenantStatus


class FrozenClock(Clock):
    def __init__(self, now: datetime | None = None) -> None:
        self._now = now or datetime(2026, 1, 1, tzinfo=UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now = self._now + delta


class CallableClock:
    """The callable clock shape `LocalCache` expects, with `now()` as well.

    Two shapes exist in the codebase - the `Clock` protocol's `.now()` and a plain callable -
    so this support class offers both rather than letting each test redefine its own.
    """

    def __init__(self, now: datetime | None = None) -> None:
        self._now = now or datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self._now

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
    def __init__(
        self,
        suspended: set[uuid.UUID] | None = None,
        records: dict[uuid.UUID, TenantRecord] | None = None,
    ) -> None:
        # `suspended or set()` would be wrong here: an empty set is falsy, so a caller who
        # passes one would have it silently replaced and could never suspend a tenant later.
        self._suspended = set() if suspended is None else suspended
        self._records = records or {}

    async def assert_servable(self, tenant_id: uuid.UUID) -> TenantRecord:
        if tenant_id in self._suspended:
            from jdlib.errors import TenantSuspended

            raise TenantSuspended(f"tenant {tenant_id} is not servable")
        record = self._records.get(tenant_id)
        if record is not None:
            return record
        return TenantRecord(
            id=tenant_id,
            slug=str(tenant_id),
            status=TenantStatus.ACTIVE,
            strategy=PlacementStrategy.SHARED,
        )


class EntitlementsStub:
    def __init__(self, allowed: set[tuple[uuid.UUID, uuid.UUID]] | None = None) -> None:
        self._allowed = allowed or set()

    async def can_act(self, principal: Principal, tenant_id: uuid.UUID) -> bool:
        return (principal.id, tenant_id) in self._allowed


class ServiceAccountEntitlementsStub:
    """Models the EntitlementAdapter service-account path: pinned and registered."""

    def __init__(self, registered: set[tuple[uuid.UUID, uuid.UUID]] | None = None) -> None:
        self._registered = registered or set()

    async def can_act(self, principal: Principal, tenant_id: uuid.UUID) -> bool:
        if principal.kind is not PrincipalKind.SERVICE_ACCOUNT:
            return False
        return principal.tenant_id == tenant_id and (tenant_id, principal.id) in self._registered


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
        request_id: str | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        self.records.append(
            {
                "kind": kind,
                "capability": capability,
                "justification": justification,
                "actor_id": actor.id,
                "tenant_id": tenant_id,
                "request_id": request_id,
                "correlation_id": correlation_id,
                "trace_id": trace_id,
            }
        )
