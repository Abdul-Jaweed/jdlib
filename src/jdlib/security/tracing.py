"""W3C Trace Context and security spans (directive §7.1, §7.2).

**Propagation is parsed strictly.** A `traceparent` is either well-formed or it
is refused: a trace id half-understood from a malformed header silently breaks
the join between a request, its logs and its audit rows, which is the one thing
the header exists to provide.

**Spans carry dimensions, not identifiers.** A span is not aggregated, so the
cardinality argument that governs metrics does not apply — but the identifiers
that make a trace *findable* already live in the log record and the audit row,
joined by `trace_id`. What a span carries is the dimension an operator filters
on (operation, decision, principal kind, auth method, gateway). An identifier or
a credential-shaped attribute is refused, and a string value still passes the
shared redaction set.

**No tracer, no dependency.** The span layer is duck-typed against the OpenTelemetry
API rather than importing it: the library is inert without it, an application
that already has a tracer passes its own, and the core never grows an optional
import. Span failures are swallowed in both directions — a collector outage must
not disable security, and a failing span must not mask the exception the body is
raising.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from jdlib.security.context import RequestIds
from jdlib.security.redaction import is_sensitive_key, redact_text

TRACEPARENT_HEADER = "traceparent"
TRACESTATE_HEADER = "tracestate"
REQUEST_ID_HEADERS = ("x-request-id", "x-correlation-id")
CORRELATION_ID_HEADER = "x-correlation-id"

_HEX = frozenset("0123456789abcdef")
_VERSION = "00"


class SecuritySpanError(ValueError):
    """A span attribute would make the span unsafe or unqueryable."""


@dataclass(frozen=True, slots=True)
class TraceContext:
    """A parsed W3C trace context."""

    trace_id: str
    parent_id: str
    sampled: bool = True


def _is_lower_hex(value: str, length: int) -> bool:
    return len(value) == length and all(char in _HEX for char in value)


def parse_traceparent(value: object) -> TraceContext | None:
    """Parse a W3C ``traceparent``; ``None`` when it is not well-formed.

    Strict on purpose: lowercase hex only, exactly four fields, non-zero ids,
    and the version this implementation understands. An unsupported version is
    refused rather than guessed at, per the recommendation's forward-compatibility
    rule.
    """
    if not isinstance(value, str):
        return None
    parts = value.strip().split("-")
    if len(parts) != 4:
        return None
    version, trace_id, parent_id, flags = parts
    if version != _VERSION:
        return None
    if not _is_lower_hex(trace_id, 32) or trace_id == "0" * 32:
        return None
    if not _is_lower_hex(parent_id, 16) or parent_id == "0" * 16:
        return None
    if not _is_lower_hex(flags, 2):
        return None
    return TraceContext(trace_id=trace_id, parent_id=parent_id, sampled=bool(int(flags, 16) & 0x01))


def format_traceparent(context: TraceContext, *, sampled: bool | None = None) -> str:
    """Render a ``traceparent`` header value."""
    flag = context.sampled if sampled is None else sampled
    return f"{_VERSION}-{context.trace_id}-{context.parent_id}-{'01' if flag else '00'}"


def _header(headers: Mapping[str, object], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == lowered and isinstance(value, str):
            return value
    return None


def request_ids_from_headers(headers: Mapping[str, object]) -> RequestIds:
    """Derive the request's identity from inbound headers.

    The trace context is taken only when it parses, so a malformed header cannot
    poison the trace id; a request id and correlation id are generated when the
    caller supplies none, because a request with no ids cannot be joined to
    anything after the fact.
    """
    context = parse_traceparent(_header(headers, TRACEPARENT_HEADER))
    request_id = _header(headers, REQUEST_ID_HEADERS[0]) or uuid.uuid4().hex
    correlation_id = _header(headers, CORRELATION_ID_HEADER) or uuid.uuid4().hex
    return RequestIds(
        request_id=request_id,
        correlation_id=correlation_id,
        trace_id=context.trace_id if context is not None else None,
    )


# --- spans --------------------------------------------------------------------

#: Attributes a span may carry. Everything else is refused, so the allow-list is
#: what an operator can filter on — and the identifiers are not in it.
SPAN_ATTRIBUTE_ALLOWLIST = frozenset(
    {
        "decision",
        "principal.kind",
        "auth.method",
        "gateway.name",
        "tenant.strategy",
        "outcome",
        "mode",
        "kind",
        "status",
        "reason",
        "result",
    }
)

FORBIDDEN_SPAN_ATTRIBUTES = frozenset(
    {
        "tenant_id",
        "principal_id",
        "user_id",
        "request_id",
        "correlation_id",
        "trace_id",
        "span_id",
        "session_id",
        "token",
        "authorization",
        "cookie",
        "subject",
        "email",
    }
)

_SPAN_PREFIX = "security."


class TracerLike(Protocol):
    def start_span(self, name: str, attributes: dict[str, Any]) -> Any: ...


def _safe_attribute(key: str, value: object) -> object:
    if key in FORBIDDEN_SPAN_ATTRIBUTES or is_sensitive_key(key):
        raise SecuritySpanError(
            f"span attribute {key!r} is an identifier or a credential; "
            "join on trace_id and put identifiers in the log record instead"
        )
    if not key.startswith(_SPAN_PREFIX) and key not in SPAN_ATTRIBUTE_ALLOWLIST:
        raise SecuritySpanError(f"span attribute {key!r} is not in the bounded allow-list")
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact_text(value)
    raise SecuritySpanError(f"span attribute {key!r} must be a scalar")


class SecuritySpan:
    """A span that never fails the operation it describes.

    With no tracer it is inert and validates nothing (there is nothing to
    export). With a tracer, attributes are validated before they reach it, and
    every interaction is guarded so a telemetry error cannot reach the caller.
    """

    def __init__(
        self,
        tracer: TracerLike | None,
        name: str,
        *,
        attributes: Mapping[str, object] | None = None,
        trace_id: str | None = None,
    ) -> None:
        self.trace_id = trace_id
        self._tracer = tracer
        self._span: Any = None
        self._name = name
        self._attributes: dict[str, object] = {}
        if tracer is None:
            return
        for key, value in (attributes or {}).items():
            self._attributes[key] = _safe_attribute(key, value)
        try:
            self._span = tracer.start_span(name, self._attributes)
        except Exception:  # noqa: BLE001 - a collector outage is not a security event
            self._span = None

    def set_attribute(self, key: str, value: object) -> None:
        if self._span is None:
            return
        try:
            self._span.set_attribute(key, _safe_attribute(key, value))
        except SecuritySpanError:
            raise
        except Exception:  # noqa: BLE001
            return None

    def end(self, *, status: str | None = None) -> None:
        if self._span is None:
            return
        try:
            self._span.end(status=status)
        except Exception:  # noqa: BLE001
            return None

    def __enter__(self) -> SecuritySpan:
        return self

    def __exit__(self, *exc: object) -> None:
        # Never return True: the body's exception must propagate. A failing span
        # must not become a failing request's only visible symptom.
        self.end()
        return None


def security_span(
    tracer: TracerLike | None,
    name: str,
    *,
    attributes: Mapping[str, object] | None = None,
    trace_id: str | None = None,
) -> SecuritySpan:
    """Open an inert-or-real span; use as a context manager.

    The name should be the operation (`authorization.decide`,
    `authentication.validate`, `audit.record`), which is what an operator
    searches for.
    """
    return SecuritySpan(tracer, name, attributes=attributes, trace_id=trace_id)


__all__ = [
    "CORRELATION_ID_HEADER",
    "FORBIDDEN_SPAN_ATTRIBUTES",
    "REQUEST_ID_HEADERS",
    "SPAN_ATTRIBUTE_ALLOWLIST",
    "TRACEPARENT_HEADER",
    "SecuritySpan",
    "SecuritySpanError",
    "TraceContext",
    "format_traceparent",
    "parse_traceparent",
    "request_ids_from_headers",
    "security_span",
]
