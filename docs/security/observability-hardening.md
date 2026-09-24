# Observability Hardening (Phase 7)

Status: **COMPLETE** — all six slices are implemented and verified. The
safety-critical half (§7.3 structured logging, §7.4 bounded metrics, §7.6 failure
isolation) landed first; the OpenTelemetry span layer (§7.1, §7.2) and the Docker
collector stack (§7.5) followed, and the collector section below records what a
real collector stored rather than what a mock was told.

Source: `src/jdlib/security/telemetry.py` (new), `src/jdlib/security/redaction.py`
(extended: header and cookie field names)
Tests: `tests/unit/security/test_telemetry.py` (26)

---

## 1. Structured logs (§7.3)

`security_log_record(...)` builds a record with the directive's fields in a stable
order — timestamp, level, service, environment, request_id, correlation_id,
trace_id, principal_id, tenant_id, event, security_code, operation, outcome — and
fills the identifiers from the ambient security context when the caller does not
supply them, so one request's logs, spans and audit rows join on the same ids.

The API surface is the protection: it takes no request object, no headers and no
token, so there is no parameter a raw credential could be passed to. Every string
that reaches a record passes the shared redaction set (the same one behind the
error responses and audit metadata), a field whose *name* is disqualifying
(`authorization`, `cookie`, `set-cookie`, `signing_key`, …) is redacted whatever
its value, reserved names cannot be spoofed, and non-scalars are refused outright
rather than serialized into a log line.

Service and environment come from `JDLIB_SERVICE_NAME` / `JDLIB_ENVIRONMENT` so a
deployment can label its own records without a code change.

## 2. Bounded metrics (§7.4)

`SecurityMetrics` counts the directive's metrics and validates every label
*before* any backend sees it:

* a label outside the bounded allow-list is refused,
* an unbounded identifier label (`tenant_id`, `user_id`, `request_id`, `token`,
  `session_id`, …) is refused with an explicit reason,
* a label *value* that looks like an identifier (a uuid, an over-long string) is
  refused too — smuggling `tenant_id` in as `{"reason": "<uuid>"}` is the same
  cardinality mistake with extra steps.

Cardinality is the failure mode that kills an observability stack quietly, so the
check is in the write path, not in a code review.

## 3. Telemetry failure cannot disable security (§7.6)

`safe_emit(...)` runs an emission and swallows a telemetry error, reporting it
once per distinct message so a collector outage cannot become a log flood. The
test that matters is the realistic one: a decision path increments a counter, the
metrics backend raises, and the decision still completes. The inverse — a metrics
outage becoming an authorization outage — is the failure this arrangement exists
to prevent.

## 4. Trace context and spans (§7.1, §7.2)

`parse_traceparent` is strict: lowercase hex only, exactly four fields, non-zero
ids, and an unsupported version is refused rather than guessed at (the
recommendation's forward-compatibility rule). A trace id half-understood from a
malformed header silently breaks the join between a request, its logs and its
audit rows — the header's only purpose — so refusing is the safer failure.
`request_ids_from_headers` derives request, correlation and trace ids from
inbound headers and *generates* the first two when they are absent, because a
request with no ids cannot be joined to anything after the fact.

Spans carry dimensions, not identifiers. A span is not aggregated, so the
cardinality argument that governs metrics does not apply — but the identifiers
that make a trace findable already live in the log record and the audit row,
joined by `trace_id`. The attribute allow-list is therefore explicit
(`security.*`, plus operation/decision/principal.kind/auth.method/gateway.name/
tenant.strategy/outcome/mode/kind/status/reason/result), an identifier or
credential-shaped attribute is refused with that reason, and a string value still
passes the shared redaction set.

The layer is duck-typed against the OpenTelemetry API rather than importing it:
the library is inert without a tracer, an application that has one passes its
own, and the core never grows an optional import. Failures are swallowed in both
directions — a collector outage must not disable security, and a failing span
must not mask the exception the body is raising (the context manager returns
`None`, never `True`).

## 5. Docker observability stack (§7.5)

`tests/infra/otel/` brings up a real OpenTelemetry Collector (contrib, OTLP
gRPC + HTTP receivers, batch processor, file + Prometheus exporters) the same way
the Kong harness does: a `start.sh`, a `stop.sh`, config in the repo, and an
environment file the tests read. The file exporter exists for the assertion that
matters — *what the collector received*, not what a mock was told.

The library ships no OTLP exporter (the core grows no optional import), so the
test plays the exporter role: a duck-typed tracer using the library's own
`security_span` API over OTLP/HTTP, then it reads back what the collector stored.
Four checks, all green against the real collector:

| Check | Result |
|---|---|
| A security span reaches the collector and is stored (trace id, name, attributes verified in the exporter's output) | pass |
| A secret in an allowed attribute never reaches the collector end-to-end (`s3cr3t-pw`, `db.internal` absent from stored telemetry) | pass |
| The collector's own metrics are exposed (it is collecting, not merely listening) | pass |
| The Prometheus exporter endpoint is serving | pass |

Skips are clean when the harness has not been started, but a *listed yet
unreachable* collector is a failure, not a skip: a green run that never reached
the collector would be a lie.

Two bugs were caught by running it rather than by review: the second span was
constructed but never ended (so nothing was exported — OTel exports on span end),
and the collector's internal metrics needed their own endpoint and port mapping
before "it is collecting" could be asserted at all.

## 6. Phase 7 gate (§7.6)

| Verification | Where it is enforced |
|---|---|
| No secret leakage | `test_telemetry.py` (6 secret shapes × every field, sensitive field names, reserved names), `test_otel_infra.py` (end-to-end through the collector) |
| No unexpected high-cardinality metrics | `test_telemetry.py` — unbounded label names *and* identifier-shaped label values are refused in the write path |
| Trace propagation works | `test_tracing.py` (W3C parsing/formatting, 13 malformed shapes refused) + the collector test (real `traceparent`-shaped ids arriving) |
| Failure paths are observable | `test_audit_events.py` / `test_audit_emitters.py` emit denials and errors as first-class events; `safe_emit` keeps a telemetry outage from hiding them |
| Telemetry failure does not disable security | `test_telemetry.py::test_a_broken_metric_sink_cannot_break_an_authorization_decision`, `test_tracing.py` (failing tracer, failing span end) |

Gate: **1089 passed, 6 skipped**, `ruff` and `mypy` clean (96 source files). The
six skips remain the documented Tyk limitation; the observability harness adds
none — it ran against a real collector.
