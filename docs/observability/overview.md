# Observability

Three signals and one rule: nothing leaves the process that has not been allow-listed. This section is
how to use them; the [observability architecture](../architecture/observability-architecture.md) is
how they are wired.

| Page | The signal |
|---|---|
| [Logging](logging.md) | the record shape, the redaction floor |
| [Metrics](metrics.md) | `jdlib.security.telemetry.SecurityMetrics`, and the bounded-label rule |
| [Tracing](tracing.md) | spans, the allow-list, propagation |
| [Audit events](audit-events.md) | the vocabulary, the sinks, what an incident reconstructs |

## The posture

* **Allow-list, not deny-list.** A span attribute that is not on the list is dropped. The rule does
  not depend on every future caller remembering it.
* **Bounded labels.** `MetricLabelError` refuses a label that is not bounded, so a tenant slug or an
  identifier cannot become a metric dimension by accident — and cardinality cannot be the incident.
* **The audit plane is evidence, not telemetry.** It records decisions, is written for allows *and*
  refusals, and is what the compliance surface reads.
