# Metrics

`jdlib.security.telemetry.SecurityMetrics` emits counters and durations with **bounded labels only**.

## The rule

A metric label must come from a closed set. `MetricLabelError` refuses anything else, which is the
mechanism that keeps a caller-controlled value (a tenant slug, a request id, an identifier) out of the
label space: a metric whose cardinality grows with traffic is an outage with a dashboard.

## What is measured

| Signal | The question it answers |
|---|---|
| decisions | how many requests were allowed, denied, or degraded |
| refusals by code | which refusal is happening, and how often |
| durations | where the time goes, by stage |
| breaker transitions | when a dependency stopped answering, and when it came back |
| admission refusals | whether the gate is the constraint |
| audit sink failures | whether the evidence is complete |

## Wiring

```python
from jdlib.security.telemetry import SecurityMetrics

metrics = SecurityMetrics(...)      # your exporter, or the deployment's collector
```

The library does not pick a backend: it emits through the interface the deployment supplies, so the
same code works with an OTel collector, a Prometheus bridge, or a test double.

## Where it is tested

`tests/unit/security/` for the label rule (including the refusal) and the emitted names.
