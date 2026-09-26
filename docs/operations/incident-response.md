# Incident response

What an incident reads, in the order it is useful. The library's job is to make these questions
answerable from the evidence it already writes.

## The questions

| Question | The signal that answers it |
|---|---|
| was the caller authenticated, and as whom? | the audit event's principal and method |
| which tenant, and how was it resolved? | the audit event's tenant; the resolver named in the span |
| was the operation allowed, denied, or degraded? | the decision event |
| did the operation actually run? | the presence of the handler's span — a denial has none |
| which dependency was slow or down? | the breaker's transitions, the span durations, `/readyz` |
| was anything dropped? | the audit sink's failure metric; the exporter's own counters |
| what changed? | the deploy's `ShutdownReport` and the migration revision in the control plane |

## The first three moves

1. **Scope it to a tenant, a principal, or a dependency** — the audit trail is indexed by all three,
   and the answer usually decides which of the remaining questions matter.
2. **Distinguish "denied" from "degraded".** Both answer `403`; only one is an attack, and only one
   is an outage. The decision event says which.
3. **Check whether the refusals are the system working.** A `429`, a fast `403` after a dependency
   recovered, and a `403 TENANT_SUSPENDED` are all the controls doing their jobs; treating them as
   the incident sends the response in the wrong direction.

## What the library deliberately does not do

* **It does not page anyone.** Alerting is the deployment's, on the metrics it exports.
* **It does not hold the audit trail.** The sink is the deployment's (a database, or a store it
  already runs); the library provides the vocabulary and the export surface.
* **It does not retry a failed audit write.** The write fails and is counted — an evidence store
  whose availability becomes the application's availability is a worse trade.

## After the incident

Two things to write down, because both are cheap now and expensive later:

* the **refusal code** and the layer it came from — the stable codes are what make a postmortem
  comparable across incidents;
* whether the controls behaved as designed. If a control did not fire, that is a defect to fix; if it
  fired and the outcome was still bad, that is a design decision to revisit.
