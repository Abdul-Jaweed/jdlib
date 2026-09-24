"""Tenant-scoped audit reads and safe export (directive §6.2, §6.3).

Two properties drive the design:

**Tenant binding is not a filter the caller supplies.** The tenant a read is
scoped to is a parameter the application derives from the ambient tenant
context; a query may *narrow* within that tenant but cannot widen it. Asking for
another tenant's rows is refused outright unless the caller holds the platform
capability, so a missing `WHERE` cannot become a cross-tenant disclosure.

**Export re-sanitizes on the way out.** Rows may predate the current metadata
rules, or have been written by hand. Every rendering therefore re-validates
metadata and drops anything unhealthy instead of trusting the column: the export
path must not become the place where a secret escapes.

Output is deterministic — fixed field order, ISO-8601 UTC timestamps, JSON
metadata in CSV — so evidence can be hashed, compared and diffed.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import sqlalchemy as sa

from jdlib.models.audit import AuditEvent
from jdlib.security.audit.access import AuditAccess, AuditCapability
from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
    audit_metadata,
)

MAX_EXPORT_LIMIT = 1000
DEFAULT_EXPORT_LIMIT = 100

_CSV_FIELDS = (
    "event_id",
    "event_type",
    "outcome",
    "occurred_at",
    "tenant_id",
    "principal_id",
    "action",
    "resource_type",
    "resource_id",
    "request_id",
    "correlation_id",
    "trace_id",
    "source",
    "metadata",
)


class SecurityEventSink(Protocol):
    """Where an export event goes (see :mod:`jdlib.security.audit.emitters`)."""

    async def emit(self, event: SecurityAuditEvent) -> None: ...


@dataclass(frozen=True, slots=True)
class AuditQuery:
    """Narrowing filters for a read. Never widens beyond the bound tenant."""

    event_types: tuple[SecurityEventType, ...] = ()
    outcomes: tuple[AuditOutcome, ...] = ()
    principal_id: uuid.UUID | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    tenant_id: uuid.UUID | None = None
    limit: int = DEFAULT_EXPORT_LIMIT
    offset: int = 0

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError("limit must be at least 1")
        if self.limit > MAX_EXPORT_LIMIT:
            raise ValueError(f"limit must not exceed {MAX_EXPORT_LIMIT}")
        if self.offset < 0:
            raise ValueError("offset must not be negative")
        if self.since is not None and self.until is not None and self.since > self.until:
            raise ValueError("since must not be after until")


@dataclass(frozen=True, slots=True)
class AuditPage:
    """A bounded slice of the trail, plus how to ask for the next one."""

    events: tuple[SecurityAuditEvent, ...]
    next_offset: int | None = None

    @property
    def has_more(self) -> bool:
        return self.next_offset is not None


# --- reading ------------------------------------------------------------------


async def read_events(
    session: object,
    *,
    access: AuditAccess,
    tenant_id: uuid.UUID,
    query: AuditQuery | None = None,
) -> AuditPage:
    """Read the trail for ``tenant_id`` — that tenant only, by construction."""
    query = query or AuditQuery()
    access.require(AuditCapability.READ_TENANT)
    if query.tenant_id is not None and query.tenant_id != tenant_id:
        # Cross-tenant reads are not a filter the caller can set.
        access.require(AuditCapability.READ_PLATFORM)
    scoped_tenant = query.tenant_id or tenant_id

    statement = sa.select(AuditEvent).where(AuditEvent.tenant_id == scoped_tenant)
    if query.event_types:
        statement = statement.where(
            AuditEvent.event_type.in_([member.value for member in query.event_types])
        )
    if query.outcomes:
        statement = statement.where(
            AuditEvent.outcome.in_([member.value for member in query.outcomes])
        )
    if query.principal_id is not None:
        statement = statement.where(AuditEvent.actor_id == query.principal_id)
    if query.resource_type is not None:
        statement = statement.where(AuditEvent.target_type == query.resource_type)
    if query.resource_id is not None:
        statement = statement.where(AuditEvent.target_id == _as_uuid(query.resource_id))
    if query.request_id is not None:
        statement = statement.where(AuditEvent.request_id == query.request_id)
    if query.correlation_id is not None:
        statement = statement.where(AuditEvent.correlation_id == query.correlation_id)
    if query.since is not None:
        statement = statement.where(AuditEvent.occurred_at >= query.since)
    if query.until is not None:
        statement = statement.where(AuditEvent.occurred_at <= query.until)

    # One row beyond the page reveals whether more follows, without a count(*).
    statement = (
        statement.order_by(AuditEvent.occurred_at.asc(), AuditEvent.id.asc())
        .limit(query.limit + 1)
        .offset(query.offset)
    )
    rows = (await session.execute(statement)).scalars().all()  # type: ignore[attr-defined]
    events = tuple(_to_event(row) for row in rows[: query.limit])
    has_more = len(rows) > query.limit
    return AuditPage(events=events, next_offset=query.offset + query.limit if has_more else None)


async def export_events(
    session: object,
    *,
    access: AuditAccess,
    tenant_id: uuid.UUID,
    query: AuditQuery | None = None,
    fmt: str = "json",
    on_export: SecurityEventSink | None = None,
) -> str:
    """Render a bounded, authorized slice of the trail.

    Export needs its own capability *on top of* read authority — reading a page
    inside an application and handing a file to a third party are different
    acts — and the export itself is audited through ``on_export`` when a sink is
    supplied.
    """
    if fmt not in _RENDERERS:
        raise ValueError(f"unsupported export format {fmt!r}")
    access.require(AuditCapability.EXPORT)
    query = query or AuditQuery()
    page = await read_events(session, access=access, tenant_id=tenant_id, query=query)
    rendered = _RENDERERS[fmt](page)
    if on_export is not None:
        await on_export.emit(
            SecurityAuditEvent(
                event_type=SecurityEventType.AUDIT_EXPORTED,
                outcome=AuditOutcome.SUCCESS,
                action="audit.export",
                source=AuditSource.API,
                tenant_id=tenant_id,
                resource_type="audit_events",
                metadata={
                    "format": fmt,
                    "count": len(page.events),
                    "has_more": page.has_more,
                    "filters": _filter_summary(query),
                },
            )
        )
    return rendered


def _filter_summary(query: AuditQuery) -> str:
    """A compact, non-secret description of what was exported."""
    parts: list[str] = []
    if query.event_types:
        parts.append("event_types=" + ",".join(member.value for member in query.event_types))
    if query.outcomes:
        parts.append("outcomes=" + ",".join(member.value for member in query.outcomes))
    for name in ("resource_type", "resource_id", "request_id", "correlation_id"):
        value = getattr(query, name)
        if value is not None:
            parts.append(f"{name}={value}")
    if query.since is not None:
        parts.append(f"since={query.since.isoformat()}")
    if query.until is not None:
        parts.append(f"until={query.until.isoformat()}")
    return ";".join(parts) or "none"


# --- rendering ----------------------------------------------------------------


def _safe_metadata(raw: object) -> dict[str, object]:
    """Re-validate stored metadata, dropping entries that cannot be exported."""
    if not isinstance(raw, Mapping):
        return {}
    try:
        return audit_metadata(dict(raw))
    except (TypeError, ValueError):
        cleaned: dict[str, object] = {}
        for key, value in raw.items():
            try:
                cleaned.update(audit_metadata({key: value}))
            except (TypeError, ValueError):
                continue
        return cleaned


def _record(event: object) -> dict[str, object]:
    """The public shape of one event, from an envelope or from a stored row."""
    if isinstance(event, SecurityAuditEvent):
        record = event.as_dict()
        record["metadata"] = _safe_metadata(event.metadata)
        return record
    occurred_at = getattr(event, "occurred_at", None)
    event_type = getattr(event, "event_type", None) or ""
    return {
        "event_id": str(getattr(event, "id", "")),
        "event_type": event_type,
        "category": _category(event_type),
        "outcome": getattr(event, "outcome", None) or "",
        "action": getattr(event, "action", "") or "",
        "source": getattr(event, "source", None) or "",
        "occurred_at": occurred_at.isoformat() if isinstance(occurred_at, datetime) else "",
        "tenant_id": _str_or_none(getattr(event, "tenant_id", None)),
        "principal_id": _str_or_none(getattr(event, "actor_id", None)),
        "principal_kind": getattr(event, "actor_type", None),
        "resource_type": getattr(event, "target_type", None),
        "resource_id": _str_or_none(getattr(event, "target_id", None)),
        "request_id": getattr(event, "request_id", None),
        "correlation_id": getattr(event, "correlation_id", None),
        "trace_id": getattr(event, "trace_id", None),
        "metadata": _safe_metadata(getattr(event, "metadata_json", {})),
    }


def _category(event_type: object) -> str:
    if isinstance(event_type, str) and event_type:
        try:
            return SecurityEventType(event_type).category
        except ValueError:
            return "unknown"
    return "unknown"


def _dump(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=False, default=str)


def render_json(page: AuditPage) -> str:
    """Deterministic JSON array (fixed field order, one trailing newline)."""
    return _dump([_record(event) for event in page.events]) + "\n"


def render_jsonl(page: AuditPage) -> str:
    """One JSON object per line — the format to stream or append."""
    return "".join(f"{_dump(_record(event))}\n" for event in page.events)


def render_csv(page: AuditPage) -> str:
    """CSV with a stable header; metadata is JSON in a single column."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(_CSV_FIELDS), extrasaction="ignore")
    writer.writeheader()
    for event in page.events:
        record = _record(event)
        record["metadata"] = _dump(record["metadata"])
        writer.writerow(record)
    return buffer.getvalue()


_RENDERERS = {"json": render_json, "jsonl": render_jsonl, "csv": render_csv}


def iter_records(page: AuditPage) -> Iterable[Mapping[str, object]]:
    """Machine-readable records without rendering (for a custom writer)."""
    for event in page.events:
        yield _record(event)


def _to_event(row: object) -> SecurityAuditEvent:
    """Rebuild an envelope from a stored row, tolerating anything unknown."""
    occurred_at = getattr(row, "occurred_at", None)
    return SecurityAuditEvent(
        event_type=_known_event_type(getattr(row, "event_type", None)),
        outcome=_known_outcome(getattr(row, "outcome", None)),
        source=_known_source(getattr(row, "source", None)),
        action=getattr(row, "action", "") or "",
        event_id=getattr(row, "id", None) or uuid.uuid4(),
        occurred_at=occurred_at if isinstance(occurred_at, datetime) else datetime.now(UTC),
        tenant_id=getattr(row, "tenant_id", None),
        principal_id=getattr(row, "actor_id", None),
        principal_kind=getattr(row, "actor_type", None),
        resource_type=getattr(row, "target_type", None),
        resource_id=_str_or_none(getattr(row, "target_id", None)),
        request_id=getattr(row, "request_id", None),
        correlation_id=getattr(row, "correlation_id", None),
        trace_id=getattr(row, "trace_id", None),
        metadata=_safe_metadata(getattr(row, "metadata_json", {})),
    )


def _known_event_type(value: object) -> SecurityEventType:
    try:
        return SecurityEventType(str(value))
    except ValueError:
        # A row from a newer or older vocabulary must not break a read; the
        # original value is preserved in the rendered category as "unknown".
        return SecurityEventType.AUTHZ_DENY


def _known_outcome(value: object) -> AuditOutcome:
    try:
        return AuditOutcome(str(value))
    except ValueError:
        return AuditOutcome.FAILURE


def _known_source(value: object) -> AuditSource:
    try:
        return AuditSource(str(value))
    except ValueError:
        return AuditSource.SYSTEM


def _as_uuid(value: str | uuid.UUID | None) -> uuid.UUID | None:
    if value is None:
        return None
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


def _str_or_none(value: object) -> str | None:
    return None if value is None else str(value)


__all__ = [
    "DEFAULT_EXPORT_LIMIT",
    "MAX_EXPORT_LIMIT",
    "AuditPage",
    "AuditQuery",
    "export_events",
    "iter_records",
    "read_events",
    "render_csv",
    "render_json",
    "render_jsonl",
]
