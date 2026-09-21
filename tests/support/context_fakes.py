from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from jdlib.context import (
    Clock,
    Principal,
    PrivilegeKind,
    TenantRecord,
    TenantRef,
)


class FrozenClock(Clock):
    def __init__(self, now: datetime | None = None) -> None:
        self._now = now or datetime(2026, 1, 1, tzinfo=UTC)

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
