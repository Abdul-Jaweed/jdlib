---
guide: audit
authority: docs/security/audit-hardening.md
modules:
  - src/jdlib/security/audit/__init__.py
  - src/jdlib/security/audit/access.py
  - src/jdlib/security/audit/adapters.py
  - src/jdlib/security/audit/emitter.py
  - src/jdlib/security/audit/emitters.py
  - src/jdlib/security/audit/events.py
  - src/jdlib/security/audit/export.py
  - src/jdlib/control/audit.py
exports:
  - SecurityAuditEvent
  - AuditOutcome
  - AuditSource
  - AuditCapability
  - AuditQuery
  - AuditPage
  - DecisionObserver
  - NullSecurityEventSink
  - PlatformAudit
  - DatabaseAuditSink
  - CompositeAuditSink
example:
  - examples/enterprise/app/security/audit.py
test_files:
  - tests/unit/security/test_audit_events.py
  - tests/unit/security/test_audit_emitters.py
  - tests/unit/security/test_audit_control_adapters.py
  - tests/integration/test_audit_isolation_export.py
---
# Audit and security events

> **Design authority:** [`docs/security/audit-hardening.md`](../../security/audit-hardening.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

One vocabulary for security-relevant events -- authentication, authorization, privileged access, raw SQL, exports -- with emitters that write them somewhere and a query/export surface an operator can read.

## Why it exists

A security decision that leaves no trace is a decision nobody can review, and a trail with five shapes is one nobody can query. One event type, one outcome vocabulary, one writer.

## When to use it

Whenever a decision or a privileged action happens: an authentication, an authorization answer, a raw-SQL escape, an operator acting on a tenant, an export. If a reviewer would want to know, it belongs in the trail.

## When not to use it

For debugging output and ordinary application logs, which have a different audience and a different retention. An audit event is evidence; a log line is not.

## How it works

`SecurityAuditEvent` is the record (type, outcome, principal, tenant, request/correlation ids, resource, metadata); emitters (`emitter.py`, `emitters.py`) deliver it; the library's `emit_safely` keeps a failed audit from failing the request it describes. `AuditQuery`/`AuditPage` read it back, and `AuditCapability` gates who may.

## Architecture

`security/audit/events.py` (the vocabulary), `emitter.py`/`emitters.py` (delivery), `access.py` and `export.py` (reading it back), `adapters.py` (the platform writer); `control/audit.py` is where a deployment's rows live (`DatabaseAuditSink`, `CompositeAuditSink`, `PrivilegeAuditAdapter`).

## Example

`examples/enterprise/app/security/audit.py` joins the library's event vocabulary to the platform audit writer -- the join the library deliberately leaves to the application, because the *action* an event is recorded under is the deployment's vocabulary.

## Security

Events record the decision, not the data: a denial names the action and the reason, never the row's contents. The trail is written as the platform (a separate writer from the request path), so a caller cannot suppress it, and `emit_safely` means an audit failure is visible in logs rather than silently dropping the event.

## Reliability

Audit writes do not block the request path; a sink failure is reported and the request continues. Delivery is at-least-once from the emitter's perspective, which is why events carry their own ids -- a duplicate is detectable.

## Observability

Events carry the trace id, so a decision can be joined to its span and to the request that caused it.

## Audit

This *is* the audit feature: `AuditOutcome` (allowed, denied, failed) and `AuditSource` (API, job, operator) make the trail answer 'who asked, what happened, and where from'.

## Configuration

Where the trail is written is configuration; which events are emitted is the library's decision, with sensitive categories (privileged access, exports) always recorded.

## Testing

`test_audit_events.py`, `test_audit_emitters.py` and `test_audit_control_adapters.py` cover the vocabulary, delivery and the platform writer; `tests/integration/test_audit_isolation_export.py` covers reading and exporting under authorization.

## Common mistakes

Logging the data instead of the decision; letting an audit failure fail the request; inventing a second event shape per surface; writing the trail as the runtime role (so a caller's session can reach it); exporting without a capability check.

## Production checklist

Write the trail as a role the request path cannot modify; export on a schedule and store the export under its own retention; alert on denial spikes; and include the trail in your backup -- it is evidence, not logs.
