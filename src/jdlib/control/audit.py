from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol

from sqlalchemy import text
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
        request_id: str | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        """Record one control-plane audit event.

        The identifiers are optional and fall back to the ambient tenant context.
        Callers that already hold them - an adapter forwarding an event that
        carries them, a writer running on a task of its own where no request
        context is bound - should pass them: identifiers belong to the event, not
        to whichever task happens to flush it.
        """
        ...


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
        request_id: str | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
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
        request_id: str | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        ambient_request, ambient_correlation, ambient_trace = _trace_ids()
        self.entries.append(
            {
                "action": action,
                "tenant_id": tenant_id,
                "actor_id": actor_id,
                "metadata": dict(metadata or {}),
                "actor_type": actor_type,
                "request_id": request_id or ambient_request,
                "correlation_id": correlation_id or ambient_correlation,
                "trace_id": trace_id or ambient_trace,
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
        request_id: str | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        from jdlib.control.models import PlatformAuditEvent

        owns_session = session is None
        control = session or ControlPlaneSession(self._session_factory())
        # Explicit identifiers win over the ambient ones: a writer on its own task
        # - a queued sink draining in the background, which is how the reference
        # application writes its control-plane trail - has no request context
        # bound, and the ambient lookup would fill every column with NULL.
        ambient_request, ambient_correlation, ambient_trace = _trace_ids()
        request_id = request_id or ambient_request
        correlation_id = correlation_id or ambient_correlation
        trace_id = trace_id or ambient_trace
        try:
            if correlation_id:
                # PostgreSQL's own record of this statement should name the request it is
                # storing the evidence for. `set_config(..., true)` is the parameterised,
                # transaction-scoped form of `SET LOCAL`: the log line, and a
                # `pg_stat_activity` row while the write is in flight, carry the correlation
                # id rather than the default client name (observability-validation §6.3).
                await control.execute(
                    text("SELECT set_config('application_name', :name, true)"),
                    {"name": correlation_id},
                )
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
        request_id: str | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        for sink in self._sinks:
            if actor_type is None:
                await sink.record(
                    action=action,
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    metadata=metadata,
                    session=session,
                    request_id=request_id,
                    correlation_id=correlation_id,
                    trace_id=trace_id,
                )
            else:
                await sink.record(
                    action=action,
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    metadata=metadata,
                    session=session,
                    actor_type=actor_type,
                    request_id=request_id,
                    correlation_id=correlation_id,
                    trace_id=trace_id,
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
        request_id: str | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        await self._sink.record(
            action=f"privilege.{kind.value}",
            tenant_id=tenant_id,
            actor_id=actor.id,
            metadata={"capability": capability, "justification": justification},
            actor_type=actor.kind.value,
            request_id=request_id,
            correlation_id=correlation_id,
            trace_id=trace_id,
        )
