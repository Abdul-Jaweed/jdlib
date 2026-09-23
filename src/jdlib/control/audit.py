from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import Principal, PrivilegeKind, current_tenant
from jdlib.control.session import ControlPlaneSession
from jdlib.errors import MissingTenantContext


def _resolve_actor_type(actor_id: uuid.UUID | None, actor_type: str | None) -> str:
    return actor_type or ("system" if actor_id is None else "user")


def _trace_ids() -> tuple[str | None, str | None, str | None]:
    try:
        context = current_tenant()
    except MissingTenantContext:
        return None, None, None
    return context.request_id, context.correlation_id, context.trace_id


class PlatformAudit(Protocol):
    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
        session: ControlPlaneSession | None = None,
        actor_type: str | None = None,
    ) -> None: ...


class NullPlatformAudit:
    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
        session: ControlPlaneSession | None = None,
        actor_type: str | None = None,
    ) -> None:
        raise RuntimeError("no platform audit sink is configured")


@dataclass
class RecordingPlatformAudit:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
        session: ControlPlaneSession | None = None,
        actor_type: str | None = None,
    ) -> None:
        self.entries.append(
            {
                "action": action,
                "tenant_id": tenant_id,
                "actor_id": actor_id,
                "metadata": dict(metadata or {}),
                "actor_type": actor_type,
            }
        )


class DatabaseAuditSink:
    def __init__(self, session_factory: Callable[[], AsyncSession]) -> None:
        self._session_factory = session_factory

    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
        session: ControlPlaneSession | None = None,
        actor_type: str | None = None,
    ) -> None:
        from jdlib.control.models import PlatformAuditEvent

        owns_session = session is None
        control = session or ControlPlaneSession(self._session_factory())
        request_id, correlation_id, trace_id = _trace_ids()
        try:
            control.add(
                PlatformAuditEvent(
                    action=action,
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    actor_type=_resolve_actor_type(actor_id, actor_type),
                    metadata_json=dict(metadata or {}),
                    request_id=request_id,
                    correlation_id=correlation_id,
                    trace_id=trace_id,
                )
            )
            await control.flush()
            if owns_session:
                await control.commit()
        finally:
            if owns_session:
                await control.close()


class CompositeAuditSink:
    def __init__(self, *sinks: PlatformAudit) -> None:
        self._sinks = sinks

    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
        session: ControlPlaneSession | None = None,
        actor_type: str | None = None,
    ) -> None:
        for sink in self._sinks:
            if actor_type is None:
                await sink.record(
                    action=action,
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    metadata=metadata,
                    session=session,
                )
            else:
                await sink.record(
                    action=action,
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    metadata=metadata,
                    session=session,
                    actor_type=actor_type,
                )


class PrivilegeAuditAdapter:
    def __init__(self, sink: PlatformAudit) -> None:
        self._sink = sink

    async def record_privilege(
        self,
        *,
        kind: PrivilegeKind,
        capability: str | None,
        justification: str | None,
        actor: Principal,
        tenant_id: uuid.UUID,
    ) -> None:
        await self._sink.record(
            action=f"privilege.{kind.value}",
            tenant_id=tenant_id,
            actor_id=actor.id,
            metadata={"capability": capability, "justification": justification},
            actor_type=actor.kind.value,
        )
