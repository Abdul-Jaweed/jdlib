"""Phase 7: the telemetry surface cannot leak, cannot explode in cardinality,
and cannot take security down with it.

The three directives under test: §7.3 (structured logs, never a secret), §7.4
(bounded labels), §7.6 (telemetry failure must not disable security).
"""

from __future__ import annotations

import uuid

import pytest

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.security.context import (
    AuthMethod,
    RequestIds,
    SecurityContext,
    security_context_scope,
)
from jdlib.security.telemetry import (
    MetricLabelError,
    SecurityMetrics,
    safe_emit,
    security_log_record,
)

TENANT_A = uuid.UUID("aaaaaaaa-1111-2222-3333-444444444444")
PRINCIPAL = uuid.UUID("99999999-8888-7777-6666-555555555555")

DSA = "postgresql+asyncpg://app:s3cr3t-pw@db.internal:5432/jdlib"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"


def _context_scope():
    principal = Principal(id=PRINCIPAL, kind=PrincipalKind.USER)
    tenant = TenantContext(
        tenant_id=TENANT_A,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req-7",
        correlation_id="corr-7",
        trace_id="trace-7",
    )
    security = SecurityContext(
        principal=principal,
        request_ids=RequestIds(request_id="req-7", correlation_id="corr-7", trace_id="trace-7"),
        auth_method=AuthMethod.SERVICE,
        tenant=tenant,
    )
    return security_context_scope(security)


# --- §7.3 structured logging --------------------------------------------------


def test_a_record_carries_the_directive_fields_and_the_ambient_ids() -> None:
    with _context_scope():
        record = security_log_record(
            event="authorization.denied",
            outcome="denied",
            security_code="AUTHZ_DENIED",
            operation="document.read",
        )
    for field in ("timestamp", "level", "service", "environment", "event", "outcome"):
        assert record[field], field
    assert record["request_id"] == "req-7"
    assert record["correlation_id"] == "corr-7"
    assert record["trace_id"] == "trace-7"
    assert record["principal_id"] == str(PRINCIPAL)
    assert record["tenant_id"] == str(TENANT_A)
    assert record["security_code"] == "AUTHZ_DENIED"
    assert record["operation"] == "document.read"


def test_the_service_and_environment_come_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("JDLIB_SERVICE_NAME", "jdlib-api")
    monkeypatch.setenv("JDLIB_ENVIRONMENT", "production")
    record = security_log_record(event="auth.failure", outcome="failure")
    assert record["service"] == "jdlib-api"
    assert record["environment"] == "production"


@pytest.mark.parametrize(
    "secret",
    (
        DSA,
        JWT,
        "Bearer abcdefghijklmnopqrstuvwxyz123456",
        "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkq-----END PRIVATE KEY-----",
        "api_key=abcdef1234567890",
    ),
)
def test_no_secret_survives_any_field(secret: str) -> None:
    record = security_log_record(
        event="auth.failure",
        outcome="failure",
        operation=secret,
        fields={"context": secret, "reason": f"refused because of {secret}"},
    )
    rendered = str(record)
    assert "s3cr3t-pw" not in rendered
    assert JWT not in rendered
    assert "abcdef1234567890" not in rendered
    assert "BEGIN PRIVATE KEY" not in rendered or "[redacted]" in rendered


def test_a_sensitive_field_name_is_redacted_regardless_of_value() -> None:
    record = security_log_record(
        event="auth.failure",
        outcome="failure",
        fields={"authorization": "anything at all", "cookie": "session=xyz"},
    )
    assert record["authorization"] == "[redacted]"
    assert record["cookie"] == "[redacted]"


def test_a_reserved_or_oversized_field_is_refused() -> None:
    with pytest.raises(ValueError, match="reserved"):
        security_log_record(event="e", outcome="o", fields={"request_id": "spoofed"})
    with pytest.raises(ValueError, match="too long"):
        security_log_record(event="e", outcome="o", fields={"huge": "x" * 600})


def test_a_non_scalar_field_is_refused() -> None:
    with pytest.raises(TypeError, match="scalar"):
        security_log_record(event="e", outcome="o", fields={"headers": {"a": "b"}})


def test_the_record_has_a_stable_key_order() -> None:
    record = security_log_record(event="e", outcome="o")
    assert list(record)[:6] == [
        "timestamp",
        "level",
        "service",
        "environment",
        "request_id",
        "correlation_id",
    ]


# --- §7.4 bounded metrics -----------------------------------------------------


def test_a_known_metric_with_bounded_labels_is_counted() -> None:
    metrics = SecurityMetrics()
    metrics.increment("authorization_denied_total", {"event": "document.read", "outcome": "denied"})
    metrics.increment("authorization_denied_total", {"event": "document.read", "outcome": "denied"})
    assert metrics.snapshot() == {
        "authorization_denied_total{event=document.read,outcome=denied}": 2
    }


@pytest.mark.parametrize(
    "label",
    ("tenant_id", "user_id", "request_id", "correlation_id", "trace_id", "token", "session_id"),
)
def test_an_unbounded_label_is_refused(label: str) -> None:
    metrics = SecurityMetrics()
    with pytest.raises(MetricLabelError, match="unbounded"):
        metrics.increment("authentication_failure_total", {label: "x"})


def test_a_label_outside_the_allow_list_is_refused() -> None:
    metrics = SecurityMetrics()
    with pytest.raises(MetricLabelError, match="allow-list"):
        metrics.increment("authentication_failure_total", {"whatever": "x"})


def test_an_identifier_smuggled_as_a_label_value_is_refused() -> None:
    metrics = SecurityMetrics()
    with pytest.raises(MetricLabelError, match="looks like an identifier"):
        metrics.increment("authorization_denied_total", {"reason": str(TENANT_A)})
    with pytest.raises(MetricLabelError, match="too long"):
        metrics.increment("authorization_denied_total", {"reason": "x" * 100})


def test_an_unknown_metric_is_refused() -> None:
    metrics = SecurityMetrics()
    with pytest.raises(ValueError, match="unknown metric"):
        metrics.increment("made_up_total")


def test_the_directive_metrics_exist() -> None:
    from jdlib.security.telemetry import KNOWN_METRICS

    required = {
        "authentication_success_total",
        "authentication_failure_total",
        "authorization_allow_total",
        "authorization_denied_total",
        "audit_write_total",
        "audit_failure_total",
        "tenant_resolution_failure_total",
        "cerbos_error_total",
        "token_validation_failure_total",
    }
    assert required <= KNOWN_METRICS


# --- §7.6 telemetry failure must not disable security -------------------------


def test_a_failing_emitter_is_swallowed_and_reported() -> None:
    def boom() -> None:
        raise RuntimeError("collector down")

    assert safe_emit(boom) is False, "a telemetry failure must not propagate"


def test_safe_emit_passes_success_through() -> None:
    calls: list[int] = []
    assert safe_emit(lambda: calls.append(1)) is True
    assert calls == [1]


def test_a_broken_metric_sink_cannot_break_an_authorization_decision() -> None:
    # The realistic shape: a decision path increments a counter and a backend
    # raises. The decision must complete.
    class BrokenBackend(SecurityMetrics):
        def increment(self, name: str, labels=None) -> None:
            raise ConnectionError("metrics backend unreachable")

    metrics = BrokenBackend()
    decided = safe_emit(
        lambda: metrics.increment("authorization_allow_total", {"outcome": "allow"})
    )
    assert decided is False  # reported, not raised
