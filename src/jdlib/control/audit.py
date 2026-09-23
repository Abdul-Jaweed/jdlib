from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.control.session import ControlPlaneSession


class PlatformAudit(Protocol):
    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
        session: ControlPlaneSession | None = None,
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
    ) -> None:
        self.entries.append(
            {
                "action": action,
                "tenant_id": tenant_id,
                "actor_id": actor_id,
                "metadata": dict(metadata or {}),
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
    ) -> None:
        from jdlib.control.models import PlatformAuditEvent

        owns_session = session is None
        control = session or ControlPlaneSession(self._session_factory())
        control.add(
            PlatformAuditEvent(
                action=action,
                tenant_id=tenant_id,
                actor_id=actor_id,
                actor_type="system" if actor_id is None else "user",
                metadata_json=dict(metadata or {}),
            )
        )
        await control.flush()
        if owns_session:
            await control.commit()
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
    ) -> None:
        for sink in self._sinks:
            await sink.record(
                action=action,
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata=metadata,
                session=session,
            )
