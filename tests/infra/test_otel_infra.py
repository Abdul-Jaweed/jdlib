"""Layer 3: telemetry through a real OpenTelemetry Collector (Phase 7.5, §7.6).

The unit tests prove the library refuses to emit unsafe telemetry. This proves
the other half — that what the library emits when wired to real infrastructure is
actually *received and stored*, which is the difference between "we wrote a span"
and "an operator could have found it".

The library ships no OTLP exporter (no optional import in the core), so the test
plays the exporter role: a duck-typed tracer using the library's own
`security_span` API over OTLP/HTTP, and then it reads back what the collector's
file exporter wrote.

Skipped cleanly when the harness has not been started — see
`tests/infra/otel/start.sh`. Skips caused by a *listed but unreachable* collector
are failures, not skips: a green run that never reached the collector would be a
lie.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import secrets
import time
import urllib.error
import urllib.request

import pytest

from jdlib.security.tracing import SecuritySpan, security_span

_ENV_FILE = pathlib.Path(__file__).parent / "out" / "otel.env"
TIMEOUT_SECONDS = 20


def _config() -> dict[str, str]:
    """Read the harness's env file, falling back to the process environment."""
    values: dict[str, str] = {}
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith("export ") and "=" in line:
                key, _, value = line[len("export ") :].partition("=")
                values[key.strip()] = value.strip()
    for key in (
        "JDLIB_INFRA_OTEL_OTLP_HTTP",
        "JDLIB_INFRA_OTEL_OUTPUT",
        "JDLIB_INFRA_OTEL_PROMETHEUS",
        "JDLIB_INFRA_OTEL_INTERNAL_METRICS",
    ):
        values.setdefault(key, os.environ.get(key, ""))
    return values


_CONFIG = _config()

pytestmark = [
    pytest.mark.infra,
    pytest.mark.skipif(
        not _CONFIG.get("JDLIB_INFRA_OTEL_OTLP_HTTP"),
        reason="observability collector not started (bash tests/infra/otel/start.sh)",
    ),
]


class _OtlpSpan:
    """Minimal OTLP/HTTP JSON exporter standing in for the application's tracer."""

    def __init__(self, endpoint: str, name: str, attributes: dict[str, object]) -> None:
        self._endpoint = endpoint
        self._name = name
        self._attributes = dict(attributes)
        self.trace_id = secrets.token_hex(16)
        self.span_id = secrets.token_hex(8)
        self._started = time.time_ns()

    def set_attribute(self, key: str, value: object) -> None:
        self._attributes[key] = value

    def end(self, *, status: str | None = None) -> None:
        payload = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "jdlib-tests"}}
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "jdlib.security"},
                            "spans": [
                                {
                                    "traceId": self.trace_id,
                                    "spanId": self.span_id,
                                    "name": self._name,
                                    "kind": 1,
                                    "startTimeUnixNano": str(self._started),
                                    "endTimeUnixNano": str(time.time_ns()),
                                    "attributes": [
                                        {"key": key, "value": {"stringValue": str(value)}}
                                        for key, value in self._attributes.items()
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        request = urllib.request.Request(
            f"{self._endpoint}/v1/traces",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - local harness
            assert response.status in {200, 202}, response.status


class _OtlpTracer:
    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint
        self.spans: list[_OtlpSpan] = []

    def start_span(self, name: str, attributes: dict[str, object]) -> SecuritySpan:
        span = _OtlpSpan(self._endpoint, name, attributes)
        self.spans.append(span)
        return span  # type: ignore[return-value]


def _resolve(value: str) -> pathlib.Path:
    """Resolve the harness's output path.

    `start.sh` runs under bash, where the repo path looks like
    `/j/ai-agents-resources/jdlib/...`; a Windows Python cannot open that, so an
    MSYS-style path is converted and a relative path is anchored at the repo root.
    """
    if re.match(r"^/[a-zA-Z]/", value):
        drive, _, rest = value[1:].partition("/")
        return pathlib.Path(f"{drive.upper()}:/{rest}")
    path = pathlib.Path(value)
    if path.is_absolute():
        return path
    return pathlib.Path(__file__).parents[2] / path


def _store_size(output: pathlib.Path) -> int:
    """The store's size before this test sends anything.

    A store left behind by a previous session must not be able to green this
    test: the claim is about what arrives *now*, so the search starts where
    this run's bytes begin. Which was not theoretical - with the collector
    unable to write a store at all, the un-anchored form passed on a stale
    file, while the span test (anchored on a fresh trace id) failed. The
    difference between the two was only the anchor.
    """
    try:
        return output.stat().st_size
    except OSError:
        return 0


def _await_output(needle: str, *, output: pathlib.Path, since: int = 0) -> str:
    """Poll the collector's file exporter for what this run sent."""
    deadline = time.time() + TIMEOUT_SECONDS
    text = ""
    while time.time() < deadline:
        if output.exists():
            text = output.read_text(encoding="utf-8", errors="replace")
            if needle in text[since:]:
                return text
        time.sleep(0.5)
    raise AssertionError(
        f"collector never stored {needle!r} in this run "
        f"(output={output}, bytes before this run={since}, size={len(text)})"
    )


def test_a_security_span_reaches_the_collector_and_is_stored() -> None:
    endpoint = _CONFIG["JDLIB_INFRA_OTEL_OTLP_HTTP"]
    output = _resolve(_CONFIG["JDLIB_INFRA_OTEL_OUTPUT"])
    since = _store_size(output)
    tracer = _OtlpTracer(endpoint)

    with security_span(
        tracer,
        "authorization.decide",
        attributes={"security.operation": "document.read", "decision": "allow"},
    ) as span:
        span.set_attribute("security.outcome", "allow")
        trace_id = span._span.trace_id if span._span is not None else ""

    stored = _await_output(trace_id, output=output, since=since)
    assert "authorization.decide" in stored
    assert "document.read" in stored
    assert str(trace_id) in stored


def test_a_secret_cannot_reach_the_collector_even_end_to_end() -> None:
    endpoint = _CONFIG["JDLIB_INFRA_OTEL_OTLP_HTTP"]
    output = _resolve(_CONFIG["JDLIB_INFRA_OTEL_OUTPUT"])
    since = _store_size(output)
    tracer = _OtlpTracer(endpoint)
    secret = "postgresql+asyncpg://app:s3cr3t-pw@db.internal:5432/jdlib"

    # An allowed attribute carrying a value that must be redacted on the way out.
    span = security_span(
        tracer, "authentication.validate", attributes={"security.operation": secret}
    )
    span.end()
    stored = _await_output("authentication.validate", output=output, since=since)
    assert "s3cr3t-pw" not in stored
    assert "db.internal" not in stored


def test_the_collector_is_really_collecting_metrics() -> None:
    internal = _CONFIG.get("JDLIB_INFRA_OTEL_INTERNAL_METRICS")
    if not internal:
        pytest.skip("collector was started before the internal metrics endpoint existed")
    with urllib.request.urlopen(internal, timeout=10) as response:  # noqa: S310 - local harness
        body = response.read().decode("utf-8", errors="replace")
    assert response.status == 200
    assert "otelcol_" in body, "the collector's own metrics should be exposed"


def test_the_prometheus_exporter_endpoint_is_serving() -> None:
    with urllib.request.urlopen(  # noqa: S310 - local harness
        _CONFIG["JDLIB_INFRA_OTEL_PROMETHEUS"], timeout=10
    ) as response:
        assert response.status == 200
