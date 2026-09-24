"""Phase 7: structured security logging and bounded metrics.

Three properties, all test-enforced:

**Secrets cannot enter a log record.** Every string that reaches a record passes
the same redaction set the error responses and audit metadata use, and a field
whose *name* is disqualifying (`authorization`, `cookie`, `access_token`, …) is
redacted whatever its value. The API surface takes no request object, no headers
and no token: there is no parameter a raw credential could be passed to.

**Metric labels are bounded.** Observability dies of cardinality long before it
dies of volume, so the label allow-list is explicit and an identifier smuggled in
as a label *value* (a uuid, an over-long string) is refused rather than recorded.

**Telemetry failure never disables security.** Emission goes through
:func:`safe_emit`, which swallows a telemetry error and reports it once. The
inverse arrangement — a metrics backend outage turning into an authorization
outage — is the failure this module exists to prevent.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from jdlib.security.context import current_security_context_or_none
from jdlib.security.redaction import REDACTED, is_sensitive_key, redact_text

# --- logging ------------------------------------------------------------------

#: The record's fixed fields (directive §7.3), in a stable order.
LOG_FIELDS = (
    "timestamp",
    "level",
    "service",
    "environment",
    "request_id",
    "correlation_id",
    "trace_id",
    "principal_id",
    "tenant_id",
    "event",
    "security_code",
    "operation",
    "outcome",
)

MAX_FIELD_ENTRIES = 24
MAX_FIELD_VALUE = 512


def _service_name() -> str:
    return os.environ.get("JDLIB_SERVICE_NAME", "jdlib")


def _environment() -> str:
    return os.environ.get("JDLIB_ENVIRONMENT") or os.environ.get("JDLIB_ENV") or "development"


def _safe_field(key: str, value: object) -> object:
    """One auxiliary field, redacted or refused."""
    if is_sensitive_key(key):
        return REDACTED
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        if len(value) > MAX_FIELD_VALUE:
            raise ValueError(f"log field {key!r} is too long")
        return redact_text(value)
    raise TypeError(f"log field {key!r} must be a scalar")


def security_log_record(
    *,
    event: str,
    outcome: str,
    level: str = "info",
    security_code: str | None = None,
    operation: str | None = None,
    tenant_id: uuid.UUID | str | None = None,
    principal_id: uuid.UUID | str | None = None,
    fields: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build a structured record for a security-relevant event.

    Identifiers (request, correlation, trace, tenant, principal) are taken from
    the ambient security context where the caller does not supply them, so the
    logs of one request can be joined to its trace and to its audit rows.
    """
    context = current_security_context_or_none()
    record: dict[str, object] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "level": level,
        "service": _service_name(),
        "environment": _environment(),
        "request_id": None,
        "correlation_id": None,
        "trace_id": None,
        "principal_id": None,
        "tenant_id": None,
        "event": redact_text(event),
        "security_code": security_code,
        "operation": redact_text(operation) if operation else None,
        "outcome": outcome,
    }
    if context is not None:
        record["request_id"] = context.request_ids.request_id
        record["correlation_id"] = context.request_ids.correlation_id
        record["trace_id"] = context.request_ids.trace_id or context.trace_id
        record["principal_id"] = str(context.principal.id) if context.principal.id else None
        record["tenant_id"] = (
            str(context.tenant.tenant_id) if context.tenant is not None else None
        )
    if principal_id is not None:
        record["principal_id"] = str(principal_id)
    if tenant_id is not None:
        record["tenant_id"] = str(tenant_id)

    if fields:
        if len(fields) > MAX_FIELD_ENTRIES:
            raise ValueError("too many log fields")
        for key, value in fields.items():
            if key in LOG_FIELDS:
                raise ValueError(f"log field {key!r} is reserved")
            record[key] = _safe_field(key, value)
    return record


# --- metrics ------------------------------------------------------------------

#: Metrics this library emits (directive §7.4).
KNOWN_METRICS = frozenset(
    {
        "authentication_success_total",
        "authentication_failure_total",
        "authorization_allow_total",
        "authorization_denied_total",
        "audit_write_total",
        "audit_failure_total",
        "tenant_resolution_failure_total",
        "cerbos_error_total",
        "token_validation_failure_total",
        "raw_sql_denied_total",
        "gateway_assertion_failure_total",
    }
)

#: Labels that are bounded by construction, so they are safe to aggregate on.
BOUNDED_LABELS = frozenset(
    {
        "event",
        "kind",
        "method",
        "mode",
        "operation",
        "outcome",
        "reason",
        "result",
        "security_code",
        "source",
        "status",
    }
)

#: Labels that must never be used: unbounded identifiers (directive §7.4).
FORBIDDEN_LABELS = frozenset(
    {
        "tenant_id",
        "tenant",
        "user_id",
        "principal_id",
        "principal",
        "request_id",
        "correlation_id",
        "trace_id",
        "span_id",
        "session_id",
        "token",
        "subject",
        "email",
        "client_id",
    }
)

MAX_LABEL_VALUE = 64
_UUID_LIKE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class MetricLabelError(ValueError):
    """A metric label would make the metric unbounded."""


@dataclass
class SecurityMetrics:
    """A bounded-label counter sink.

    Deliberately not a facade over a specific backend: it validates and counts,
    and a deployment exports :meth:`snapshot` (or subclasses to forward to its own
    client). Validation happens before any backend sees the data.
    """

    counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = field(default_factory=dict)

    def increment(self, name: str, labels: Mapping[str, str] | None = None) -> None:
        if name not in KNOWN_METRICS:
            raise ValueError(f"unknown metric {name!r}")
        pairs = self._validate(labels or {})
        self.counters[(name, pairs)] = self.counters.get((name, pairs), 0) + 1

    @staticmethod
    def _validate(labels: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
        pairs: list[tuple[str, str]] = []
        for key, value in sorted(labels.items()):
            if key in FORBIDDEN_LABELS:
                raise MetricLabelError(
                    f"label {key!r} is unbounded; aggregate on a bounded label instead"
                )
            if key not in BOUNDED_LABELS:
                raise MetricLabelError(f"label {key!r} is not in the bounded allow-list")
            text = str(value)
            if len(text) > MAX_LABEL_VALUE:
                raise MetricLabelError(f"label {key!r} value is too long to be bounded")
            if _UUID_LIKE.search(text):
                raise MetricLabelError(
                    f"label {key!r} value looks like an identifier, which is unbounded"
                )
            pairs.append((key, text))
        return tuple(pairs)

    def snapshot(self) -> dict[str, int]:
        """A flat, exportable view: ``metric{key=value}`` → count."""
        view: dict[str, int] = {}
        for (name, pairs), count in sorted(self.counters.items()):
            suffix = ",".join(f"{key}={value}" for key, value in pairs)
            view[f"{name}{{{suffix}}}" if suffix else name] = count
        return view


# --- failure isolation --------------------------------------------------------

_reported: set[str] = set()


def safe_emit(emit: Callable[[], Any]) -> bool:
    """Run a telemetry emission; never let telemetry break a security decision.

    Returns whether the emission succeeded. A failure is reported once per
    distinct message (a metrics outage must not become a log flood), and is not
    raised: the caller is in the middle of deciding something.
    """
    try:
        emit()
    except Exception as exc:  # noqa: BLE001 - the whole point is to swallow it
        message = f"{type(exc).__name__}: {exc}"
        if message not in _reported:
            _reported.add(message)
            import logging

            logging.getLogger("jdlib.security.telemetry").warning(
                "telemetry emission failed: %s", message
            )
        return False
    return True


__all__ = [
    "BOUNDED_LABELS",
    "FORBIDDEN_LABELS",
    "KNOWN_METRICS",
    "LOG_FIELDS",
    "MetricLabelError",
    "SecurityMetrics",
    "safe_emit",
    "security_log_record",
]
