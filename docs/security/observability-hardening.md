# Observability Hardening (Phase 7)

Status: **IN PROGRESS** — the safety-critical half is implemented and verified
(§7.3 structured logging, §7.4 bounded metrics, §7.6 failure isolation). The
OpenTelemetry span layer (§7.1, §7.2) and the Docker collector stack (§7.5) are
the remaining slices.

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

## 4. Remaining in this phase

* **§7.1 OpenTelemetry** — traces, spans, W3C Trace Context propagation, with the
  `trace_id`/`span_id`/`request_id`/`correlation_id` relationships preserved.
  Intended shape: an optional extra (`opentelemetry-api`) so the core stays
  import-safe, spans emitted through the same `safe_emit` isolation, and the
  context ids carried onto the span rather than into a label.
* **§7.2 Security spans** — authentication, tenant resolution, authorization,
  Cerbos decision, token validation, gateway validation, audit recording,
  privileged operations; bounded attributes only, with a test asserting no
  attribute is high-cardinality and none can carry a token.
* **§7.5 Docker observability stack** — an OpenTelemetry Collector (plus
  Prometheus/Grafana where practical) brought up the way `tests/infra/kong` does,
  with a real test that telemetry emitted by the library is collected, and a
  skip-clean harness when Docker is unavailable.
* **§7.6 gate** — the full phase gate with the verification list (no secret
  leakage, no unexpected high-cardinality metrics, trace propagation works,
  failure paths observable, telemetry failure does not disable security).
