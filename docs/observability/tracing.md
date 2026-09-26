# Tracing

`jdlib.security.tracing` produces spans with an explicit allow-list of attributes, and propagates the
trace context across the process boundary.

## The allow-list

`SecuritySpan` accepts attributes from a fixed set; anything else is dropped rather than exported. The
list is code, not configuration, because it is a claim about what may leave the process.

What is on it: the route or tool name, the outcome, the decision, the request and trace ids, the
resolver that decided the tenant, durations. What is not, and never will be: arguments, credentials,
tenant data, identifiers from a payload.

## Propagation

```python
from jdlib.security.tracing import parse_traceparent, request_ids_from_headers, security_span
```

* `request_ids_from_headers` reads the incoming `traceparent` (and the deployment's request id
  header) into `RequestIds`;
* `parse_traceparent` / `format_traceparent` are the W3C header's two directions, so an outbound call
  carries the same trace;
* `security_span` opens a span with the context bound.

`TracerLike` is the port: the library emits through whatever tracer the deployment supplies, and the
unit suites use a recording double.

## Why an allow-list rather than a filter

A filter has to know every bad thing; an allow-list has to know every good thing. The second list is
shorter, reviewable, and — the point — it fails closed. A new attribute added by a future contributor
is invisible until someone deliberately adds it to the list.

## Where it is tested

`tests/unit/security/` for the allow-list, the header parsing (including malformed input) and the
span's attribute behaviour.
