# JDLib production readiness

This document answers the certification questions for the **successor capabilities** (§4–§12 of
the programme) and re-states the numbers the library's own gate produces. Every figure below is
script-derived from the working tree at the commit named in the roadmap, and every answer names
the command that produced it. Where evidence does not exist yet, the answer says so instead of
asserting readiness.

## Numbers

| Measure | Value | Command |
|---|---|---|
| Unit tests | **1077 passed** | `.venv/Scripts/python.exe -m pytest tests/unit -q` |
| Integration tests | **358 passed** | `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python.exe -m pytest tests/integration -q` |
| Coverage (unit layer, branch on) | **64%** — 7110 statements, 2447 missed | `.venv/Scripts/python.exe -m pytest tests/unit -q --cov=jdlib --cov-branch` |
| Lint | clean | `.venv/Scripts/python.exe -m ruff check .` |
| Types | clean, 142 source files | `.venv/Scripts/python.exe -m mypy src/jdlib` |
| Source modules | 142 | `find src/jdlib -name "*.py" | wc -l` |
| Test modules | 120 | `find tests -name "test_*.py" | wc -l` |
| Source lines | 18110 | `find src/jdlib -name "*.py" -exec cat {} + | wc -l` |
| Adversarial suite | **43 passed** | `.venv/Scripts/python.exe -m pytest tests/unit/security/test_adversarial_successor.py -q` |

The coverage figure is the **unit layer only**, and that is deliberate: integration tests run
against real PostgreSQL, Redis and MinIO containers, and counting them would inflate the number
with the code they exercise rather than measure the library. No coverage threshold is enforced
(`branch = true`, no `fail_under`), so the number is reported, not gamed.

## Certification questions

### Identity — can a job or a credential be made to act as something it is not?

**Answer: no, and the mechanism is a signature over the job's own fields.**
`JobEnvelope` signs `job_id`, `issued_at`, `expires_at` and the tenant token together with
HMAC-SHA256 and compares with `hmac.compare_digest`. A rewritten expiry, a swapped job id, a
swapped tenant token, a truncated signature and a re-encoded payload are each refused with
`EnvelopeForgeryError` — five named tests, including one that keeps the original signature string
while changing the payload to prove the signature covers what it claims to.

### Tenant isolation — can any new path reach another tenant's data?

**Answer: not through hydration, caching, storage or the query compiler.**

- *Cache*: entries are keyed by tenant, so a value written for one tenant is invisible to another
  (test asserts `None`, not an error message).
- *Storage*: keys are built in one place, always relative to the caller's tenant, and six hostile
  keys are refused rather than repaired.
- *Query*: the scope predicate is applied by the compiler, and a caller-supplied filter on
  `tenant_id` cannot replace it — the compiled statement carries **two** predicates and the
  caller's value stays a bound parameter.
- *Tenant plane*: the compiler refuses `projects` and `audit_events` outright (ADR-1), so the
  tenant plane keeps exactly one path, the repository.

### Authorization — can a delegated privilege be replayed or widened?

**Answer: no.** A delegation is `PrivilegeContext(kind="delegation")`, not a second privilege
model, and `validate_delegation` refuses an unidentified, expired, replayed, unjustified,
wrong-capability, wrong-tenant or suspended-actor delegation. Replay is keyed on the delegation
identifier and **not** on the capability, so changing the requested capability does not reset the
check — the adversarial suite asserts exactly that. A non-delegation passes through unchanged,
which is the ADR's explicit choice and is asserted as a choice rather than as a refusal.

### Hydration — can a resolved target outlive its rotation?

**Answer: no.** The cache key includes the credential version, `current_version` establishes the
version on demand, and a rotated credential yields a different version — hence a different key,
hence a rebuild. A pinned retired version fails closed with `CredentialVersionRetiredError`
rather than silently resolving the current value.

### Query compilation — can an identifier, an operator or a value escape?

**Answer: no.** Identifiers are validated against an allow-list at **parse** time, which is before
rendering and before any connection is opened. The adversarial suite tries SQL fragments, comment
openers, case confusion, trailing whitespace, embedded NUL, dotted qualification, `*`, function
calls, casts and **homoglyphs** (Cyrillic `е` and `а` in identifier position) — all refused. Values
are never text: a hostile value appears in `parameters` and never in `text`. Operators come from
an allow-list, and `CompiledQuery` renders as `values=[REDACTED]`.

### Cryptography — what is the library's own key material handling?

**Answer: values are never rendered.** `ResolvedSecret.__repr__` shows metadata only,
`CompiledQuery.__repr__` redacts values, span attributes refuse identifiers and credentials by
name and by prefix, and audit metadata is sanitised through `audit_metadata`. Credentials are
resolved through one provider chain and never printed by default by the CLI.

### External state — what does a hostile key or handle look like, and what happens?

**Answer: refused, never repaired.** Object keys with a parent segment, an absolute path, an empty
value or a separator another SDK might normalise are refused. A connector refuses to open for an
unauthorized context and refuses a statement that is not a read when it declares `writes=false`.
A cache refuses a credential-shaped value by construction (ADR-2). Every refusal is recorded on
the boundary's span and, where the boundary can name a tenant, as an audit event.

## What this document does not claim

- **Snowflake, MongoDB, StarRocks, BigQuery, GCS and Azure Blob are not implemented and are not
  exported.** A provider or connector class in the public surface is a claim that it works, and
  a test asserts their absence rather than a comment promising future work.
- **All seven reliability gaps the inventory recorded are now closed.** Circuit breaking landed
  with the connector in §6; the rest closed in `src/jdlib/reliability/` and `src/jdlib/tenancy/` -
  a shared retry budget, job retries, dead letters, the per-attempt revalidation that preserves a
  job's authority, and the shutdown path. The seventh, half-open recovery *outside* the connector
  policy, is `jdlib.reliability.breaker`: the same state machine the connector now consults instead
  of keeping its own, so a job dispatcher or a sink gets closed -> open -> half-open with exactly
  one trial admitted, time injected, and no second copy of the rules to drift from the first.
  What no non-connector caller has *adopted* yet is a separate question from what the library
  provides; the capability is here, tested, and importable, and the connector's own tests are what
  prove the extraction kept its behaviour.
  The inventory's ABSENT verdicts are left as they were written, because they are a measurement
  at a revision, not a status board; what has been built since is stated below it.
- **Infrastructure-dependent layers are not all exercised on every machine.** The infra suite
  needs the lab stack; where it cannot run, it skips, and a skipped suite is not evidence.
- **The coverage figure is 64%, not higher.** The new namespaces are above that line; several
  older ones are not.

## How to reproduce

```bash
cd /j/ai-agents-resources/jdlib
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m mypy src/jdlib
.venv/Scripts/python.exe -m pytest tests/unit -q
TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python.exe -m pytest tests/integration -q
.venv/Scripts/python.exe -m pytest tests/unit -q --cov=jdlib --cov-branch
```

The integration layer needs Docker. On this host, `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` is
required or clients time out reaching the mapped ports — a platform difference recorded here
because it is the difference between a green gate and a misleading red one.
