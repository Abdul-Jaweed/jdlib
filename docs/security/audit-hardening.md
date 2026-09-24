# Audit Hardening (Phase 6)

Status: **IN PROGRESS** — vocabulary, persistence, emission, audit access
(reads, tenant isolation, export) are done and
verified against real PostgreSQL; export and the integrity decision follow.

Source: `src/jdlib/security/audit/` (new), `src/jdlib/models/audit.py`,
`src/jdlib/models/audit_recorder.py`,
`src/jdlib/migrations/tenant/versions/0002_security_audit_columns.py`
Tests: `tests/unit/security/test_audit_events.py` (16),
`tests/unit/security/test_audit_emitters.py` (12),
`tests/integration/test_security_audit_persistence.py` (9, real PostgreSQL)

| Evidence | Result |
|---|---|
| Unit (vocabulary, envelope, emitters) | 28 passed |
| Integration against real PostgreSQL (Testcontainers) | 9 passed |
| `ruff` / `mypy` | see the final gate in §7 |

---

## 1. Event vocabulary (directive §4)

`SecurityEventType` carries exactly the 34 names the directive lists, grouped by
category (`authentication`, `authorization`, `tenancy`, `privilege`, `security`)
so a consumer can route without string surgery. A test asserts the enum is
*exactly* the directive's list — adding or renaming an event is a deliberate,
reviewed act, because evidence mappings and dashboards key off these strings.

Outcomes: `SUCCESS`, `FAILURE`, `DENIED`, `ERROR`.
Sources: `API`, `GATEWAY`, `SERVICE`, `SYSTEM`, `BACKGROUND_JOB`, `CLI`.

## 2. The envelope

`SecurityAuditEvent` is a frozen dataclass carrying every field the directive
requires: `event_id` (UUIDv7, time-ordered so the trail sorts by id), `occurred_at`,
`event_type`, `category`, `request_id`, `correlation_id`, `trace_id`, `tenant_id`,
`principal_id`, `principal_kind`, `action`, `resource_type`, `resource_id`,
`outcome`, `source` and `metadata`.

Two behaviours are worth calling out because they are what make emission cheap
and safe:

* **Identifiers default from the ambient security context.** A caller inside a
  request writes
  `SecurityAuditEvent(event_type=..., outcome=..., action=..., source=...)` and
  the tenant, principal, request, correlation and trace ids are filled in. A
  platform event outside any request is equally valid and stays empty.
* **`repr` prints metadata *keys*, never values.** Otherwise a stray log line or
  an exception traceback would be a second, unaudited copy of the metadata.

## 3. No secret can reach audit metadata

`audit_metadata()` validates and sanitizes at construction, so the sink never
sees a secret and an operator cannot leak one by accident:

| Rule | Effect |
|---|---|
| secret-shaped values are redacted (`jdlib.security.redaction`, the same patterns the error responses use) | a DSN, JWT, bearer token, `password=…` or PEM block becomes `[redacted]` |
| secret-named keys are redacted regardless of value (`password`, `token`, `client_secret`, `dsn`, …) | a value that does not *look* like a secret still cannot be stored under a revealing key |
| keys must match `^[a-z][a-z0-9_.-]{0,63}$` | no whitespace, no control characters, stable queryable names |
| values must be JSON scalars or flat lists of scalars; nested structures, oversized strings (>1024), out-of-range integers (≥2⁶³) and non-JSON objects are **rejected with an exception** | failing loudly at the call site beats silently dropping evidence or storing something unqueryable |
| at most 32 entries, lists ≤256 items | a caller cannot use audit as a data dump |

The integration test proves this at the storage layer, not just in the model: a
`dsn`, a `client_secret` and a `token=…` note are all absent from the JSONB that
PostgreSQL actually holds (see §5).

## 4. Persistence and transaction semantics (directive §5)

The audit table gained the vocabulary columns (`event_type`, `outcome`,
`source`) plus an index the export path will filter on, and
`TenantAuditRecorder.record_security(event)` maps an envelope onto a row.
Migration: `0002_security_audit_columns` (chains onto `0001_tenant_baseline`;
verified).

**Documented semantic — audit participates in the caller's transaction.** An
audit row is written in the same transaction as the operation it describes:

* a committed operation leaves exactly one row,
* a **rolled-back operation leaves no audit row at all** — proven by an
  integration test rather than asserted in prose,
* an audit write that cannot be performed fails the operation, because an
  operation whose evidence cannot be recorded is an operation whose evidence
  does not exist.

The alternative (write audit in its own transaction, "so it always survives")
was rejected: it produces rows describing work that never happened, which is
worse than a missing row for an investigator. A deployment that needs
out-of-band audit for aborted operations must add a separate compensating path —
this is stated as a consumer responsibility, not silently assumed.

**Fail closed on attribution.** An event that names a tenant other than the
ambient one is refused (`ValueError`) and nothing is written: a mis-attributed
audit row is worse than a missing one, because it points an investigation at the
wrong tenant.

**Principal kinds outside the column vocabulary are preserved.** The table
accepts `user`/`service_account`/`platform_operator`/`system`; an `anonymous`
principal (or an event raised outside any request) is recorded as `system` with
the real kind preserved in `metadata["principal_kind"]`. An audit write must not
fail a database constraint — losing the evidence entirely is the worse outcome.

**Tenant isolation.** `audit_events` is derived from `TenantRouted`, and a test
asserts the table is in the RLS policy generator's list
(`rls_eligible_tables`), i.e. audit rows are not exempt from tenant isolation.
Policy-level enforcement for the table is exercised by the existing RLS suite
(`tests/integration/test_rls_db.py`), which installs and verifies policies for
all eligible tables.

**Concurrency.** Six concurrent writers across separate sessions and pooled
connections all persist, with distinct ids and no lost rows (integration).

## 5. Emission (directive §4)

`authorization_audit_observer(sink)` plugs into the observer seam the
enforcement point already exposes:

```python
pep = AuthorizationPEP(
    pdp=cerbos,
    on_decision=authorization_audit_observer(TransactionAuditSink(session)),
)
```

| Decision | Event | Outcome |
|---|---|---|
| allowed | `AUTHZ_ALLOW` | `SUCCESS` |
| denied | `AUTHZ_DENY` | `DENIED` |
| degraded (engine unavailable) | `AUTHZ_PDP_ERROR` | `ERROR` |

The event describes the same question the engine was asked (tenant, resource,
actions, principal) and deliberately **excludes policy identifiers and
versions** — internal detail does not belong in the trail, and the decision's
own `safe_metadata()` remains the contract for anything leaving the process. For
a non-UUID principal (a federated subject), the raw subject is kept as
`metadata["principal_ref"]` rather than dropped.

Sink semantics are explicit because audit availability is a security decision:

* `TransactionAuditSink` — writes in the caller's transaction (fail closed);
  this is what the project uses,
* `NullSecurityEventSink` — drops events; for tests, or a deliberate documented
  gap. Never selected implicitly,
* a sink that raises propagates to the caller. Nothing swallows an audit
  failure: silent audit loss is worse than a visible failure.

## 6. Audit access, scoped reads and export (directive §6)

**Capability model.** Reading the trail is not implied by writing it. Six
capabilities — `audit.write`, `audit.read`, `audit.read.tenant`,
`audit.read.platform`, `audit.export`, `audit.verify` — are evaluated against the
scopes the security context already carries (`AuditAccess`), so there is no
second authorization system. A principal carrying no scopes at all is refused as
*unauthenticated* (401); a scoped principal that lacks the capability gets a 403.
Both are test-pinned, including the pair that matters most: a holder of
`audit.write` cannot read the trail, and a reader of the trail cannot export it.

**Tenant binding is not a filter the caller supplies.**
`read_events(session, access=…, tenant_id=…)` always scopes to that tenant (the
application derives it from the ambient tenant context). A
`AuditQuery(tenant_id=…)` naming a different tenant is refused outright unless
the caller holds `audit.read.platform` — a missing `WHERE` cannot become a
cross-tenant disclosure, and the platform path stays a deliberate,
capability-gated act rather than a query tweak.

**Reads are bounded and stable.** `limit` is capped at `MAX_EXPORT_LIMIT` (1000)
and validated at construction: a limit of 0, a negative offset, or `since` after
`until` raise `ValueError`. One row beyond the page decides `has_more` without a
`count(*)`; ordering is `(occurred_at, id)`, proven stable by walking a page
sequence and asserting no row repeats and none is skipped.

**Export.** `export_events()` renders JSON, JSONL or CSV with fixed field order,
ISO-8601 UTC timestamps and JSON-encoded metadata in CSV, so the same query
renders byte-identically — verified by rendering twice and comparing, and by
asserting the three formats agree on event identities. An unsupported format is
refused *before* any SQL runs. Export requires its own capability on top of read
authority, and the export itself becomes an `AUDIT_EXPORTED` event (format,
count, `has_more`, non-secret filter summary) through the caller's sink.

**Export cannot launder a secret.** Stored metadata is re-validated on the way
out rather than trusted: entries with an invalid key, a non-scalar value or a
credential-shaped string are dropped or redacted at render time. The test writes
a row *around* the model (as an older version or a manual insert would) carrying
a DSN, an invalid key and a nested object, and asserts none of it survives.

A row whose vocabulary this build does not know also must not break a read: the
row is reconstructed with a fallback member and its category renders as
`unknown`.

**Emission points for the remaining families (§6.5).** The families that had
vocabulary but no producer are wired through seams the library already calls —
no second plumbing, and a deployment that wires no sink keeps today's behaviour
exactly:

| Family | Seam it plugs into | Events |
|---|---|---|
| Privilege lifecycle | `PrivilegeAudit.record_privilege` (context factory) | `PRIVILEGE_ISSUED` |
| Privileged raw SQL | `RawSqlAuditor.record_raw_sql` (persistence) | `RAW_SQL_PRIVILEGED` |
| Refused privileged raw SQL | the privilege gate in `TenantSession.raw_sql` | `RAW_SQL_REJECTED` |

A refusal is the interesting half: an attempt to run privileged raw SQL without
a privilege is recorded *before* `AuthorizationError` is raised, with the actor
and the request/correlation ids taken from the tenant context — a refusal with no
actor would not be evidence. Two rules hold across the adapters: the statement
text is never copied into the trail (a statement carries literals, so only its
kind — `select`, `update` — is recorded), and an emission never replaces the
failure it accompanies. Free text such as a break-glass justification passes
through the same redaction rules as any other metadata, so a DSN typed into it
does not survive.

The refusal hook is consulted opportunistically (`getattr`), so an auditor
written against the original protocol still satisfies it — additive for every
existing implementation, proven by a test asserting a session with no sink
behaves exactly as before.

Integration coverage (real PostgreSQL, 11 tests): tenant isolation, cross-tenant
refusal, platform read, unauthenticated refusal, write≠read, pagination
stability, export determinism and bounding, the export event, cross-format
agreement, the legacy-row case, export-capability enforcement, format refusal.

## 7. Integrity evaluation (directive §7)

Directive §7 asks for an evaluation rather than an implementation, and warns
against cryptography for its own sake. The evaluation, honestly stated:

**Threat model.** Two adversaries matter. (a) An application-level attacker
without database access: they can neither read nor write audit rows (RLS plus a
distinct application role), and the model above already prevents *forging* rows
from application code, because the tenant is taken from the ambient context and
is validated. (b) An actor with database write access (compromised credentials,
a privileged migration, a malicious operator): they can `UPDATE`/`DELETE` rows,
and **no in-database scheme stops them**. Append-only triggers can be dropped by
the same actor; hash chaining only becomes evidence if the chain head is anchored
somewhere the actor does not control.

**Conclusion.** Per-row hash chaining inside the same database would add cost and
theatre without changing the adversary's capability, so it is **not implemented**
(status: evaluated, not implemented). What genuinely raises integrity comes from
outside the database, and is the deployment's responsibility:

1. ship audit rows to append-only storage the application's role cannot rewrite
   (WAL/CDC streaming, object storage with retention locks, a SIEM),
2. anchor a periodic digest of the tenant's audit range in that external store —
   this is the cheapest tamper-detection mechanism that actually bites, and it
   only works once (1) exists,
3. keep the application role without `DELETE`/`UPDATE` on `audit_events` — the
   fail-closed design above never needs either.

**Residual risk (documented, not mitigated by this library).** Absent (1)–(3), a
database-level actor can alter history undetectably. This is recorded here, in
the compliance evidence (Phase 9) and in the final report's residual-risk
section, rather than papered over.

## 8. Gate

Run on the slice as committed:

```bash
pytest -q -W error      # full suite, all layers
ruff check .
mypy src/jdlib
```

## 9. Remaining in this phase

* **Audit export** (§6): filters (tenant, principal, event_type, outcome,
  resource, time range, request/correlation id), JSON + CSV output, the export
  itself authorized and audited, no secrets or unnecessary PII. Not yet
  implemented — it is the next slice, and it is the reason this document's status
  is IN PROGRESS rather than COMPLETE.
* **Emission for the remaining families** (§4): authentication
  (`AUTH_LOGIN_*`, `AUTH_TOKEN_*`), tenant lifecycle, privilege and
  security-sensitive events (`RAW_SQL_REJECTED`, `CROSS_TENANT_ACCESS_REJECTED`,
  `CREDENTIAL_*`, `SECURITY_CONFIGURATION_CHANGED`) have vocabulary and storage
  but are not yet emitted from their enforcement points.
* **Audit authorization**: who may read the trail (distinct from who may write
  it) — implemented together with export.
