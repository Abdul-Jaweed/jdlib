"""Phase 6: the security audit event vocabulary and envelope (directive §4).

The audit trail is a security control, so the event *names* are part of the
public contract: a log consumer branches on them. These tests pin the vocabulary
to the directive's list, pin the envelope fields it requires, and pin the rule
that matters most — **no secret reaches audit metadata**, even when a caller
passes one by accident.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from jdlib._uuid import uuid7
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.security.audit import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
    audit_metadata,
)
from jdlib.security.context import (
    AuthMethod,
    RequestIds,
    SecurityContext,
    security_context_scope,
)

REQUIRED_EVENT_TYPES = {
    # authentication
    "AUTH_LOGIN_SUCCESS",
    "AUTH_LOGIN_FAILURE",
    "AUTH_TOKEN_INVALID",
    "AUTH_TOKEN_EXPIRED",
    "AUTH_TOKEN_REVOKED",
    "AUTH_API_KEY_USED",
    "AUTH_SERVICE_AUTHENTICATED",
    # authorization
    "AUTHZ_ALLOW",
    "AUTHZ_DENY",
    "AUTHZ_PDP_ERROR",
    "AUTHZ_POLICY_CHANGED",
    "ROLE_ASSIGNED",
    "ROLE_REVOKED",
    "PERMISSION_CHANGED",
    "RESOURCE_GRANT_CREATED",
    "RESOURCE_GRANT_REVOKED",
    # tenant lifecycle
    "TENANT_CREATED",
    "TENANT_PROVISIONED",
    "TENANT_SUSPENDED",
    "TENANT_RESUMED",
    "TENANT_ARCHIVED",
    "TENANT_DEPROVISIONED",
    "TENANT_PURGED",
    "TENANT_RELOCATED",
    # privileged operations
    "PRIVILEGE_ISSUED",
    "PRIVILEGE_USED",
    "PRIVILEGE_EXPIRED",
    # security-sensitive operations
    "RAW_SQL_REJECTED",
    "RAW_SQL_PRIVILEGED",
    "CROSS_TENANT_ACCESS_REJECTED",
    "SECURITY_CONFIGURATION_CHANGED",
    "CREDENTIAL_CREATED",
    "CREDENTIAL_REVOKED",
    "CREDENTIAL_ROTATED",
}

TENANT_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
PRINCIPAL_ID = uuid.UUID("99999999-8888-7777-6666-555555555555")


def _event(**overrides: object) -> SecurityAuditEvent:
    payload: dict[str, object] = {
        "event_type": SecurityEventType.AUTHZ_DENY,
        "outcome": AuditOutcome.DENIED,
        "action": "read",
        "source": AuditSource.API,
        "tenant_id": TENANT_ID,
        "principal_id": PRINCIPAL_ID,
        "principal_kind": "service_account",
        "resource_type": "document",
        "resource_id": "doc-42",
        "request_id": "req-1",
        "correlation_id": "corr-1",
        "trace_id": "trace-1",
    }
    payload.update(overrides)
    return SecurityAuditEvent(**payload)  # type: ignore[arg-type]


# --- vocabulary ---------------------------------------------------------------


AUDIT_ACCESS_EVENT_TYPES = {"AUDIT_READ_DENIED", "AUDIT_EXPORTED"}

# Added by the successor programme, by name: the pin is extended with the addition rather than
# loosened to a subset check, so a further addition still has to be deliberate.
SUCCESSOR_EVENT_TYPES = {
    "RESOURCE_HYDRATED",
    "RESOURCE_HYDRATION_REFUSED",
    "CONNECTOR_REGISTERED",
    "CONNECTOR_ACQUIRED",
    "QUERY_REJECTED",
}


def test_the_vocabulary_covers_the_directive_list() -> None:
    # The directive's names are all present; audit-trail access is its own
    # family on top (directive §6.5).
    names = {member.name for member in SecurityEventType}
    assert names >= REQUIRED_EVENT_TYPES
    assert names >= AUDIT_ACCESS_EVENT_TYPES
    assert names == REQUIRED_EVENT_TYPES | AUDIT_ACCESS_EVENT_TYPES | SUCCESSOR_EVENT_TYPES


def test_every_event_type_is_grouped_into_a_category() -> None:
    # a consumer must be able to route on category without string surgery
    for member in SecurityEventType:
        assert member.category in {
            "authentication",
            "authorization",
            "tenancy",
            "privilege",
            "security",
            "audit",
            "connector",
        }


def test_outcomes_and_sources_are_stable() -> None:
    assert {o.name for o in AuditOutcome} == {"SUCCESS", "FAILURE", "DENIED", "ERROR"}
    assert {s.name for s in AuditSource} == {
        "API",
        "GATEWAY",
        "SERVICE",
        "SYSTEM",
        "BACKGROUND_JOB",
        "CLI",
    }


# --- envelope -----------------------------------------------------------------


def test_envelope_carries_every_required_field() -> None:
    event = _event()
    assert isinstance(event.event_id, uuid.UUID)
    assert event.event_id.version == 7  # time-ordered, so the trail sorts by id
    assert event.occurred_at.tzinfo is not None
    assert event.event_type is SecurityEventType.AUTHZ_DENY
    assert event.outcome is AuditOutcome.DENIED
    assert event.tenant_id == TENANT_ID
    assert event.principal_id == PRINCIPAL_ID
    assert event.resource_type == "document"
    assert event.resource_id == "doc-42"
    assert event.request_id == "req-1"
    assert event.correlation_id == "corr-1"
    assert event.trace_id == "trace-1"
    assert event.source is AuditSource.API
    assert event.action == "read"


def test_identifiers_default_to_the_current_context() -> None:
    principal = Principal(id=PRINCIPAL_ID, kind=PrincipalKind.SERVICE_ACCOUNT)
    request_ids = RequestIds(request_id="req-ctx", correlation_id="corr-ctx", trace_id="trace-ctx")
    tenant = TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req-ctx",
        correlation_id="corr-ctx",
        trace_id="trace-ctx",
    )
    context = SecurityContext(
        principal=principal,
        request_ids=request_ids,
        auth_method=AuthMethod.SERVICE,
        tenant=tenant,
    )
    with security_context_scope(context):
        event = SecurityAuditEvent(
            event_type=SecurityEventType.AUTHZ_ALLOW,
            outcome=AuditOutcome.SUCCESS,
            action="read",
            source=AuditSource.SERVICE,
        )
    assert event.tenant_id == TENANT_ID
    assert event.principal_id == PRINCIPAL_ID
    assert event.principal_kind == PrincipalKind.SERVICE_ACCOUNT.value
    assert event.request_id == "req-ctx"
    assert event.correlation_id == "corr-ctx"
    assert event.trace_id == "trace-ctx"


def test_events_without_a_context_are_allowed_for_platform_events() -> None:
    event = SecurityAuditEvent(
        event_type=SecurityEventType.TENANT_CREATED,
        outcome=AuditOutcome.SUCCESS,
        action="tenant.create",
        source=AuditSource.CLI,
    )
    assert event.tenant_id is None
    assert event.principal_id is None
    assert event.request_id is None


def test_envelope_is_immutable() -> None:
    from dataclasses import FrozenInstanceError

    event = _event()
    with pytest.raises(FrozenInstanceError):
        event.action = "write"  # type: ignore[misc]


def test_event_is_json_serializable() -> None:
    rendered = json.dumps(_event().as_dict())
    assert "AUTHZ_DENY" in rendered


def test_row_mapping_uses_the_audit_columns() -> None:
    row = _event().as_row()
    assert set(row) == {
        "id",
        "actor_type",
        "actor_id",
        "action",
        "target_type",
        "target_id",
        "event_type",
        "outcome",
        "source",
        "metadata",
        "request_id",
        "correlation_id",
        "trace_id",
        "occurred_at",
    }


# --- metadata safety (the property that matters) ------------------------------


def test_metadata_rejects_secret_shaped_values() -> None:
    metadata = audit_metadata(
        {
            "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2ln",
            "dsn": "postgresql+asyncpg://jdlib_user:s3cr3t-pw@postgres.internal:5432/jdlib",
            "password": "hunter2-correct-horse",
            "note": "token=abcdef123456789",
        }
    )
    rendered = json.dumps(metadata)
    for leak in ("eyJhbGciOiJIUzI1NiJ9", "s3cr3t-pw", "hunter2", "abcdef123456789"):
        assert leak not in rendered
    assert metadata["note"] == "[redacted]"


def test_metadata_keeps_ordinary_operational_detail() -> None:
    metadata = audit_metadata(
        {
            "reason": "engine_unavailable",
            "policy": "document",
            "action": "read",
            "duration_ms": 12,
            "cached": False,
            "scopes": ["documents:read"],
            "previous_status": None,
        }
    )
    assert metadata["reason"] == "engine_unavailable"
    assert metadata["duration_ms"] == 12
    assert metadata["cached"] is False
    assert metadata["scopes"] == ["documents:read"]
    assert metadata["previous_status"] is None


def test_metadata_refuses_values_that_cannot_be_audited() -> None:
    with pytest.raises(ValueError):
        audit_metadata({"opaque": object()})
    with pytest.raises(ValueError):
        audit_metadata({"nested": {"deeper": {"too": "deep"}}})
    with pytest.raises(ValueError):
        audit_metadata({"key": "x" * 2000})
    with pytest.raises(ValueError):
        audit_metadata({"count": 10**40})
    with pytest.raises(ValueError):
        audit_metadata({"nonstring key": 1})  # type: ignore[dict-item]


def test_metadata_is_copied_not_referenced() -> None:
    source = {"reason": "denied"}
    metadata = audit_metadata(source)
    source["reason"] = "allowed"
    assert metadata["reason"] == "denied"


def test_audit_metadata_is_frozen_against_non_mapping_input() -> None:
    with pytest.raises(TypeError):
        audit_metadata(["not", "a", "mapping"])  # type: ignore[arg-type]


def test_repr_never_contains_metadata_values() -> None:
    event = _event(metadata={"detail": "internal-only-detail"})
    assert "internal-only-detail" not in repr(event)
    assert event.metadata["detail"] == "internal-only-detail"


def test_uuid7_ids_are_time_ordered() -> None:
    # uuid7 orders by time at millisecond granularity, so compare across
    # distinct milliseconds rather than within one.
    import time

    first = uuid7()
    time.sleep(0.005)
    second = uuid7()
    assert first < second
    assert first.version == 7
    assert datetime.now(UTC) - _event().occurred_at < __import__("datetime").timedelta(seconds=5)
