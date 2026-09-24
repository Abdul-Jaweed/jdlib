"""Phase 6: audit authorization, tenant-scoped reads and export (directive §5–6).

The security property under test is that **writing the trail and reading it are
different rights**, and that reading it is tenant-bound:

* a principal that may emit audit events may not read them,
* an unauthenticated or scope-less principal is refused outright (fail closed),
* a tenant reader sees only its own tenant's events, and a cross-tenant request
  is refused even when the caller asks for it explicitly,
* only a platform reader may read across tenants — and it still has to ask,
* export needs its own capability on top of read access,
* the output is deterministic, bounded, and re-sanitized on the way out, so a
  row written by an older version cannot leak through it.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from jdlib.errors import AuthenticationError, JdlibError, PermissionDenied
from jdlib.security.audit import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.audit.access import AuditAccess, AuditCapability
from jdlib.security.audit.export import (
    DEFAULT_EXPORT_LIMIT,
    MAX_EXPORT_LIMIT,
    AuditPage,
    AuditQuery,
    render_csv,
    render_json,
    render_jsonl,
)

TENANT_A = uuid.UUID("aaaaaaaa-1111-2222-3333-444444444444")
TENANT_B = uuid.UUID("bbbbbbbb-1111-2222-3333-444444444444")
PRINCIPAL = uuid.UUID("99999999-8888-7777-6666-555555555555")


def _event(
    *,
    tenant_id: uuid.UUID = TENANT_A,
    offset: int = 0,
    event_type: SecurityEventType = SecurityEventType.AUTHZ_DENY,
    metadata: dict[str, object] | None = None,
) -> SecurityAuditEvent:
    return SecurityAuditEvent(
        event_type=event_type,
        outcome=AuditOutcome.DENIED,
        action="read",
        source=AuditSource.API,
        tenant_id=tenant_id,
        principal_id=PRINCIPAL,
        principal_kind="user",
        resource_type="document",
        resource_id="doc-42",
        request_id=f"req-{offset}",
        correlation_id="corr-1",
        trace_id="trace-1",
        occurred_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC) + timedelta(seconds=offset),
        metadata=metadata or {},
    )


# --- capabilities (directive §6.1) -------------------------------------------


def test_the_capability_vocabulary_is_the_directive_list() -> None:
    assert {capability.value for capability in AuditCapability} == {
        "audit.write",
        "audit.read",
        "audit.read.tenant",
        "audit.read.platform",
        "audit.export",
        "audit.verify",
    }


def test_writing_the_trail_does_not_confer_reading_it() -> None:
    access = AuditAccess(scopes=frozenset({"audit.write"}))
    assert access.allows(AuditCapability.WRITE) is True
    assert access.allows(AuditCapability.READ) is False
    assert access.allows(AuditCapability.READ_TENANT) is False
    assert access.allows(AuditCapability.EXPORT) is False
    assert access.allows(AuditCapability.VERIFY) is False


def test_reading_does_not_confer_exporting() -> None:
    access = AuditAccess(scopes=frozenset({"audit.read.tenant"}))
    assert access.allows(AuditCapability.READ_TENANT) is True
    assert access.allows(AuditCapability.EXPORT) is False


def test_a_scope_less_principal_has_no_access() -> None:
    for scopes in (None, frozenset()):
        access = AuditAccess(scopes=scopes)
        for capability in AuditCapability:
            assert access.allows(capability) is False
        with pytest.raises(AuthenticationError):
            access.require(AuditCapability.READ_TENANT)


def test_a_scope_less_principal_is_unauthenticated_not_merely_denied() -> None:
    # 401 vs 403 matters: one tells the caller to authenticate, the other that
    # they authenticated and still may not.
    with pytest.raises(JdlibError) as excinfo:
        AuditAccess(scopes=None).require(AuditCapability.READ_TENANT)
    assert excinfo.value.__class__.__name__ == "AuthenticationError"
    with pytest.raises(PermissionDenied):
        AuditAccess(scopes=frozenset({"audit.write"})).require(AuditCapability.READ_TENANT)


def test_platform_operator_reaches_platform_capabilities() -> None:
    platform = AuditAccess(scopes=frozenset(), platform_operator=True)
    assert platform.allows(AuditCapability.READ_PLATFORM) is True
    assert platform.allows(AuditCapability.READ_TENANT) is True
    assert platform.allows(AuditCapability.VERIFY) is True
    # ...but not writing the trail, which is an application capability
    assert platform.allows(AuditCapability.WRITE) is False


def test_platform_read_scope_is_explicit() -> None:
    tenant_reader = AuditAccess(scopes=frozenset({"audit.read.tenant"}))
    assert tenant_reader.allows(AuditCapability.READ_PLATFORM) is False
    platform_reader = AuditAccess(scopes=frozenset({"audit.read.platform"}))
    assert platform_reader.allows(AuditCapability.READ_PLATFORM) is True


def test_umbrella_read_scope_grants_tenant_reads_only() -> None:
    access = AuditAccess(scopes=frozenset({"audit.read"}))
    assert access.allows(AuditCapability.READ_TENANT) is True
    assert access.allows(AuditCapability.READ_PLATFORM) is False
    assert access.allows(AuditCapability.EXPORT) is False


def test_unrelated_scopes_grant_nothing() -> None:
    access = AuditAccess(scopes=frozenset({"documents:read", "tenants:admin"}))
    assert access.allows(AuditCapability.READ_TENANT) is False


# --- query model and pagination ----------------------------------------------


def test_query_bounds_the_result_set() -> None:
    assert AuditQuery().limit == DEFAULT_EXPORT_LIMIT
    with pytest.raises(ValueError):
        AuditQuery(limit=0)
    with pytest.raises(ValueError):
        AuditQuery(limit=MAX_EXPORT_LIMIT + 1)
    with pytest.raises(ValueError):
        AuditQuery(offset=-1)
    with pytest.raises(ValueError):
        AuditQuery(since=datetime(2026, 6, 2, tzinfo=UTC), until=datetime(2026, 6, 1, tzinfo=UTC))


def test_page_knows_whether_more_follows() -> None:
    page = AuditPage(events=(_event(),), next_offset=1)
    assert page.has_more is True
    assert page.next_offset == 1
    assert AuditPage(events=(), next_offset=None).has_more is False


# --- deterministic, safe rendering -------------------------------------------


def test_json_rendering_is_deterministic_and_complete() -> None:
    page = AuditPage(events=(_event(offset=0), _event(offset=1)), next_offset=None)
    first = render_json(page)
    assert first == render_json(page)
    decoded = json.loads(first)
    assert [item["event_type"] for item in decoded] == ["AUTHZ_DENY", "AUTHZ_DENY"]
    assert set(decoded[0]) == {
        "event_id",
        "event_type",
        "category",
        "outcome",
        "action",
        "source",
        "occurred_at",
        "tenant_id",
        "principal_id",
        "principal_kind",
        "resource_type",
        "resource_id",
        "request_id",
        "correlation_id",
        "trace_id",
        "metadata",
    }
    assert decoded[0]["occurred_at"] == "2026-06-01T12:00:00+00:00"
    assert decoded[0]["request_id"] == "req-0"


def test_jsonl_rendering_is_one_event_per_line() -> None:
    page = AuditPage(events=(_event(offset=0), _event(offset=1)), next_offset=None)
    lines = render_jsonl(page).splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["request_id"] for line in lines] == ["req-0", "req-1"]


def test_csv_rendering_has_a_stable_header_and_rows() -> None:
    page = AuditPage(events=(_event(offset=0),), next_offset=None)
    rendered = render_csv(page)
    rows = list(csv.DictReader(io.StringIO(rendered)))
    assert list(rows[0]) == [
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
    ]
    assert rows[0]["event_type"] == "AUTHZ_DENY"
    assert rows[0]["occurred_at"] == "2026-06-01T12:00:00+00:00"
    assert json.loads(rows[0]["metadata"]) == {}


class _StoredRow:
    """A row as the database would hand it back — including metadata that the
    current rules would refuse to store (older versions, hand-edited rows)."""

    def __init__(self, metadata_json: dict[str, object]) -> None:
        self.id = uuid.uuid4()
        self.event_type = "CREDENTIAL_ROTATED"
        self.outcome = "SUCCESS"
        self.source = "API"
        self.action = "credential.rotate"
        self.occurred_at = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
        self.tenant_id = TENANT_A
        self.actor_id = PRINCIPAL
        self.actor_type = "user"
        self.target_type = "credential"
        self.target_id = uuid.uuid4()
        self.request_id = "req-1"
        self.correlation_id = "corr-1"
        self.trace_id = "trace-1"
        self.metadata_json = metadata_json


def test_rendering_re_sanitizes_stored_metadata() -> None:
    # A row written by an older version (or by hand) must not leak through the
    # export path: values are re-validated on the way out.
    page = AuditPage(
        events=(
            _StoredRow(
                {
                    "note": "postgresql+asyncpg://app:s3cr3t-pw@db.internal:5432/jdlib",
                    "bad key": "x",
                    "nested": {"a": ["b"]},
                    "reason": "rotation",
                }
            ),
        ),
        next_offset=None,
    )
    for rendered in (render_json(page), render_jsonl(page), render_csv(page)):
        assert "s3cr3t-pw" not in rendered
        assert "bad key" not in rendered
    decoded = json.loads(render_json(page))
    assert decoded[0]["metadata"]["reason"] == "rotation"
    assert decoded[0]["event_type"] == "CREDENTIAL_ROTATED"
    assert decoded[0]["request_id"] == "req-1"
    assert decoded[0]["metadata"]["note"] == "[redacted]"
    assert "nested" not in decoded[0]["metadata"]


def test_rendering_never_emits_a_null_tenant_for_a_tenant_page() -> None:
    event = _event()
    decoded = json.loads(render_json(AuditPage(events=(event,), next_offset=None)))
    assert decoded[0]["tenant_id"] == str(TENANT_A)


def test_empty_page_renders_valid_output() -> None:
    empty = AuditPage(events=(), next_offset=None)
    assert json.loads(render_json(empty)) == []
    assert render_jsonl(empty) == ""
    assert render_csv(empty).splitlines()[0].startswith("event_id,")
