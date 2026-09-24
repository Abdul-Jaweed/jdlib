"""Phase 7: W3C Trace Context and security spans.

Two halves. The first is pure and testable to the letter: `traceparent` parsing
and formatting per the W3C recommendation — a malformed header is refused rather
than half-understood, because a trace id taken from garbage is worse than no
trace id. The second is the span layer, which must be **inert when no tracer is
configured**, must refuse unbounded/likely-secret attributes, and must not let a
tracer failure reach the security decision it is describing.
"""

from __future__ import annotations

import uuid

import pytest

from jdlib.security.tracing import (
    SecuritySpan,
    SecuritySpanError,
    format_traceparent,
    parse_traceparent,
    request_ids_from_headers,
    security_span,
)

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
SPAN_ID = "00f067aa0ba902b7"
VALID = f"00-{TRACE_ID}-{SPAN_ID}-01"


class _RecordingTracer:
    def __init__(self) -> None:
        self.spans: list[tuple[str, dict[str, object]]] = []
        self.ends: list[str | None] = []

    def start_span(self, name: str, attributes: dict[str, object]) -> _RecordingSpan:
        self.spans.append((name, attributes))
        return _RecordingSpan(self, name)


class _RecordingSpan:
    def __init__(self, tracer: _RecordingTracer, name: str) -> None:
        self._tracer = tracer
        self._name = name

    def set_attribute(self, key: str, value: object) -> None:
        self._tracer.spans[-1][1][key] = value

    def end(self, *, status: str | None = None) -> None:
        self._tracer.ends.append(status)

    def __enter__(self) -> _RecordingSpan:
        return self

    def __exit__(self, *exc: object) -> None:
        self.end()


class _ExplodingTracer:
    def start_span(self, name: str, attributes: dict[str, object]) -> object:
        raise ConnectionError("collector unreachable")


# --- §7.1 W3C Trace Context ---------------------------------------------------


def test_a_valid_traceparent_is_parsed() -> None:
    parsed = parse_traceparent(VALID)
    assert parsed is not None
    assert parsed.trace_id == TRACE_ID
    assert parsed.parent_id == SPAN_ID
    assert parsed.sampled is True


def test_the_sampled_flag_is_read_both_ways() -> None:
    assert parse_traceparent(f"00-{TRACE_ID}-{SPAN_ID}-00").sampled is False
    assert parse_traceparent(f"00-{TRACE_ID}-{SPAN_ID}-01").sampled is True


@pytest.mark.parametrize(
    "value",
    (
        None,
        "",
        "not-a-trace",
        f"{TRACE_ID}-{SPAN_ID}",  # missing version and flags
        f"00-{TRACE_ID}-{SPAN_ID}",  # missing flags
        f"00-{TRACE_ID}-{SPAN_ID}-01-extra",
        f"00-{TRACE_ID.upper()}-{SPAN_ID}-01",  # uppercase is not permitted
        f"00-{SPAN_ID}-{TRACE_ID}-01",  # ids the wrong way round
        "00-" + "0" * 32 + f"-{SPAN_ID}-01",  # all-zero trace id
        f"00-{TRACE_ID}-" + "0" * 16 + "-01",  # all-zero parent id
        f"ff-{TRACE_ID}-{SPAN_ID}-01",  # invalid version
        f"00-{TRACE_ID}-{SPAN_ID}-zz",  # non-hex flags
        f"00-{TRACE_ID[:31]}-{SPAN_ID}-01",  # short trace id
    ),
)
def test_a_malformed_traceparent_is_refused(value: object) -> None:
    assert parse_traceparent(value) is None


def test_a_traceparent_round_trips() -> None:
    parsed = parse_traceparent(VALID)
    assert format_traceparent(parsed) == VALID


def test_formatting_reflects_the_sampled_flag() -> None:
    parsed = parse_traceparent(VALID)
    assert format_traceparent(parsed, sampled=False) == f"00-{TRACE_ID}-{SPAN_ID}-00"


def test_request_ids_are_taken_from_the_headers() -> None:
    ids = request_ids_from_headers(
        {"traceparent": VALID, "x-request-id": "req-1", "x-correlation-id": "corr-1"}
    )
    assert ids.trace_id == TRACE_ID
    assert ids.request_id == "req-1"
    assert ids.correlation_id == "corr-1"


def test_request_ids_survive_missing_or_bad_headers() -> None:
    ids = request_ids_from_headers({"traceparent": "garbage"})
    assert ids.trace_id is None
    assert ids.request_id, "a request id must be generated when none was supplied"
    assert ids.correlation_id, "a correlation id must be generated when none was supplied"


def test_header_lookup_is_case_insensitive() -> None:
    ids = request_ids_from_headers({"TraceParent": VALID})
    assert ids.trace_id == TRACE_ID


# --- §7.2 security spans ------------------------------------------------------


def test_a_span_carries_only_bounded_attributes() -> None:
    tracer = _RecordingTracer()
    with security_span(
        tracer,
        "authorization.decide",
        attributes={
            "security.operation": "document.read",
            "security.outcome": "allow",
            "decision": "allow",
            "principal.kind": "user",
        },
    ) as span:
        span.set_attribute("security.code", "OK")
    (name, attributes) = tracer.spans[0]
    assert name == "authorization.decide"
    assert attributes["decision"] == "allow"
    assert attributes["security.code"] == "OK"


@pytest.mark.parametrize(
    "key",
    ("tenant_id", "principal_id", "user_id", "request_id", "trace_id", "token", "authorization"),
)
def test_an_identifier_or_secret_attribute_is_refused(key: str) -> None:
    tracer = _RecordingTracer()
    with (
        pytest.raises(SecuritySpanError),
        security_span(tracer, "authorization.decide", attributes={key: "x"}),
    ):
        pass


def test_a_secret_in_an_allowed_attribute_is_still_redacted() -> None:
    tracer = _RecordingTracer()
    with security_span(
        tracer,
        "authentication.validate",
        attributes={"security.operation": "Bearer abcdefghijklmnop"},
    ):
        pass
    (_, attributes) = tracer.spans[0]
    assert "abcdefghijklmnop" not in str(attributes)


def test_a_session_without_a_tracer_is_inert() -> None:
    with security_span(None, "authorization.decide", attributes={"decision": "allow"}) as span:
        span.set_attribute("security.outcome", "allow")
    # reaching here without an error is the assertion


def test_an_unconfigured_span_accepts_anything_without_storing_it() -> None:
    span = SecuritySpan(None, "noop")
    span.set_attribute("tenant_id", "whatever")
    span.end()


def test_a_failing_tracer_does_not_reach_the_caller() -> None:
    # §7.6: telemetry failure must not disable security. The decision path
    # continues; the failure is reported, not raised.
    with security_span(
        _ExplodingTracer(), "authorization.decide", attributes={"decision": "allow"}
    ) as span:
        span.set_attribute("security.outcome", "allow")


def test_a_span_failure_inside_the_block_does_not_mask_the_body() -> None:
    # A tracer that dies mid-block must not swallow the body's own exception.
    class HalfBrokenTracer:
        def start_span(self, name: str, attributes: dict[str, object]) -> object:
            return _BrokenSpan()

    class _BrokenSpan:
        def set_attribute(self, key: str, value: object) -> None:
            raise RuntimeError("span gone")

        def __enter__(self) -> _BrokenSpan:
            return self

        def __exit__(self, *exc: object) -> None:
            raise RuntimeError("span gone")

    with (
        pytest.raises(ValueError, match="the real failure"),
        security_span(HalfBrokenTracer(), "authorization.decide"),
    ):
        raise ValueError("the real failure")


def test_the_trace_id_is_available_for_joining_records() -> None:
    parsed = parse_traceparent(VALID)
    span = SecuritySpan(None, "join", trace_id=parsed.trace_id)
    assert span.trace_id == parsed.trace_id
    assert uuid.UUID(parsed.trace_id)  # a real identifier, not a placeholder
