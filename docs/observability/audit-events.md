# Audit events

The audit plane records **decisions**, not traffic: who asked, for which tenant, what was decided, and
with which request identity. It is the signal the compliance surface reads.

## The vocabulary

| Module | What it holds |
|---|---|
| `jdlib.security.audit.events` | the event types and their fields |
| `jdlib.security.audit.emitter` | the emitter: how an event is built and written |
| `jdlib.security.audit.emitters` | the sinks: the database sink, the in-memory one for tests |
| `jdlib.security.audit.access` | reading the trail |
| `jdlib.security.audit.export` | the export surface, for evidence |
| `jdlib.security.audit.adapters` | adapting a sink the deployment already has |

## What is written

* **An allow and a refusal both.** A trail that only records denials cannot answer "was this ever
  allowed?", which is the question an incident usually starts with.
* **The decision's inputs**, not the data: the principal, the tenant, the permission, the resource's
  scope, the outcome, the request id.
* **The surfaces' differences honestly.** A refused MCP tool call writes three events (the call, the
  decision, the outcome) where the HTTP path writes one; the enterprise example asserts the difference
  rather than smoothing it.

## Reading it

```python
from jdlib.security.audit.access import ...      # query the trail
from jdlib.security.audit.export import ...      # produce evidence
```

The compliance surface (`jdlib.security.compliance.evidence`) reads the same records, which is why the
[compliance page](../compliance/README.md) can say what it can prove.

## The failure posture

An audit sink that is down does not fail the request: the write fails, the failure is counted, and the
request's outcome is unchanged. That is a deliberate trade — the alternative is an evidence store
whose availability becomes the application's availability — and it is why the sink's failure metric is
part of the incident view.
