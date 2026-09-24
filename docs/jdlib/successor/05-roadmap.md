# JDLib successor programme — roadmap

## How to read this

Phase 0 (this document set) is complete when committed. The phases below are ordered by
**dependency**, not by the directive's numbering: hydration needs credentials and a cache to exist
first, so the secrets and caching phases run before it even though the directive presents resource
hydration first. Phase *names* are kept so the mapping stays obvious.

Every phase follows the programme's gate (§31): implementation + tests + security tests + type
checking + lint + documentation + clean working tree + commit, in that order of evidence. A phase
whose evidence is inconclusive reports `INCONCLUSIVE`, never `PASS` (§32). This programme assumes it
outlives one context window: each phase ends with the repository green, the phase document
committed, and the next phase's inputs written down.

Estimated sizes are **ordered effort bands** (`S` = a session, `M` = two to three sessions,
`L` = more), not calendar promises.

---

## §1 — Hygiene before capability (S, no directive phase)

ADR-15. Three defects found by Phase 0 recon, fixed before any new subsystem compounds them:

| Fix | Evidence required |
|---|---|
| Declare `starlette` (imported at `integrations/fastapi.py:21`, declared nowhere) | the import runs from a fresh install of the extra alone |
| A test that fails when a first-party import is neither declared nor stdlib | the test fails on the pre-fix tree and passes after |
| Coverage measurement wired into the gate | a baseline number recorded in the phase doc, with the command |
| `tests/integration` skips cleanly without Docker instead of raising | running the directory with no Docker yields skips with reasons and exit 0 |

Gate: unit + lint + types clean; the three new tests mutation-checked (they must fail when the fix
is reverted).

---

## §2 — Credentials and secret providers (M) — directive Phase 3

Extends the existing `SecretProvider` seam (IMPOVE row in the capability matrix) rather than adding
a second abstraction (ADR-2, ADR-4). Deliverables: `SecretRef`, `SecretVersion`,
`RotatingSecretProvider`, provider composition, revocation semantics, and redaction extended over
the new paths. Every credential-shaped value is proven absent from logs, exception text, audit
payloads and `repr()` by a mutation-checked guard.

Gate: unit + security tests; a mutation that removes the fail-closed branch fails the suite; a
credential-shaped value written to a cache is caught by a test.

## §3 — Scoped caching (M) — directive Phase 2

`ScopedKeyFactory`, `CachePolicy`, `LocalCache`, `RedisCache`, `ScopedCache` (ADR-8). Redis behind
an extra. Deliverables include the serialisation round-trip the archived implementation lacked,
per-namespace invalidation, and documented behaviour when Redis is unavailable.

**Status: DELIVERED (2026-09-24).** `ScopedKeyFactory` (the only key builder, with scoped invalidation prefixes), `CachePolicy` (bounded TTLs), `LocalCache` (injected clock, namespace- and tenant-scoped invalidation, no global flush), the `CacheProvider` protocol, `RedisCache` (a versioned JSON envelope, lazy client import, SCAN-based scoped invalidation, no flush) and the ADR-2 guard - a credential object cannot be stored at all, including inside a container, and the refusal names the namespace rather than the value.

`RedisCache` was the part recorded PARTIAL and is now tested against **real Redis** in the integration layer, with no mocks: nine tests covering the round trip, a refusal at write time for a value that cannot survive it, expiry, the key shape as it exists in the store, cross-tenant invisibility, scoped invalidation, the credential refusal leaving the store untouched, and the absence of a flush. Delivering it needed two environment facts worth recording: this stack needs `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` or the client times out connecting, and `testcontainers.redis` is deprecated in favour of `testcontainers.community.redis` - which matters here because the gate runs with `-W error`.

28 tests (19 unit, 9 integration) across commits `f93207a` and `bd6aab4`; the latter was committed with a failing lint gate and corrected forward in `b97c6fc`, because this repository does not force-push.

Gate: the adversarial set from the matrix (cross-tenant poisoning, TTL, version skew, Redis
failure, local fallback, serialisation safety), plus a load-bearing check that key construction
refuses a tenant-scoped key with no tenant.

## §4 — Resource hydration (M) — directive Phase 1

Implements the contract already specified in `docs/jdlib/05-tenant-lifecycle.md` §7: registry,
resolver, handles, connector factory seam, lifecycle. Lazy initialisation, deterministic identity,
credential-version-aware caching.

Gate: the directive's test list — right tenant, wrong tenant, missing context, suspended tenant,
unauthorized resource, revoked credential, expired privilege, cache isolation, cache poisoning,
credential leakage, concurrency — each mapped to a named test.

## §5 — Delegated and privileged access (S–M) — directive Phase 5

`PrivilegeContext(kind="delegation")` with capability, justification, TTL, revalidation and audit
(ADR-3). No new enforcement point.

Gate: adversarial suite over the *existing* descriptor — TTL expiry, absent justification,
capability mismatch, replay, cross-tenant target, privilege used after actor suspension.

## §6 — Connector framework (M) — directive Phase 6

`DataConnector` protocol, `ConnectorRegistry` (startup-validated), `ConnectorFactory`,
`ConnectorCapabilities`, `ConnectionPolicy` with timeout/retry/circuit-breaking, plus the contract
test suite and test doubles every implementation must pass (ADR-6).

Gate: a connector that cannot verify it received an authorized context refuses to open; a
blocking-call test proves async discipline (ADR-14).

## §7 — Data connectors (S) — directive Phase 7

The PostgreSQL connector (reusing the existing engine, strategies and pool rules). Snowflake,
MongoDB, StarRocks, BigQuery: **DEFER**, each with the adoption conditions named in ADR-6. No empty
shells ship (§38).

Gate: live round-trip against the existing PostgreSQL lab; health check; policy behaviour under
timeout and retry.

## §8 — Query specification and compiler (L) — directive Phase 8

Scoped by ADR-1: engines without an ORM only. Deliverables: `QuerySpecification` (Pydantic),
AST, `QueryCompiler` → `CompiledQuery` (text + bound parameters as one value), `QueryDialect`,
and `query/safety.py` (identifier allowlist enforced **at parse time**, dangerous-construct
rejection, complexity limits, tenant constraint applied by the compiler).

Gate: fuzz/adversarial suite — SQL injection attempts, identifier injection, dangerous constructs,
unbounded pagination, cross-tenant AST, query amplification — plus a test asserting
`TenantRepository` remains the only path to tenant-plane rows.

## §9 — Object storage (M) — directive Phase 9

`ObjectStorageProvider`, `StoredObject`, `ObjectMetadata`, and exactly one verified backend
(ADR-5). GCS and Azure stay deferred and unexported.

Gate: live put/get/list/delete/stream round-trip; tenant-scoped key construction; credentials
resolved through §2's path; no provider class exported without a passing contract suite.

## §10 — Integrations: background jobs and propagation (M) — directive Phase 10

`JobEnvelope` with the revalidation chain (ADR-10); CLI administrative context already exists and
is only extended; the two *measured* trace-propagation gaps (gateway→app, JDLib→PDP) closed or
documented as PARTIAL with the stopping point cited. gRPC: DEFER, flagged (ADR-11).

Gate: envelope forgery, TTL lapse, replay after revocation, tenant suspension between enqueue and
execution; propagation re-measured with the same method that found the gaps.

## §11 — Observability for the new boundaries (S–M) — directive Phase 11

Boundary instrumentation only — hydration, connector acquisition, query compilation, credential
resolution, audit — extending the existing boundary list, never a per-method decorator
(the archived library's 15–30% overhead is the rejected pattern).

Gate: spans asserted at the listed boundaries and *absent* from helper internals; telemetry-safety
rules re-run over the new paths (no secrets, no payload text, no bind values).

## §12 — Audit and compliance for new capabilities (S–M) — directive Phase 12

Extend the existing audit model to credential access/rotation, resource lifecycle, connector
lifecycle, query rejections, delegation. The platform/tenant audit planes, operational logs,
metrics, traces and compliance evidence stay separate concepts (the directive says so, and the
existing implementation already does).

Gate: every new event type has a producer wired to a sink and a test asserting the emitted event;
a mutation that removes a mandatory event's fail-closed path fails the suite.

## §13 — Reference application (M) — directive Phase 13

The private reference app consumes the new capabilities end to end: authentication → tenant
resolution → authorization → delegated access → resource hydration → credential resolution →
connector → query compilation → tenant-scoped query → database → audit + telemetry, with the
scenario list from the directive (normal user, service account, operator, delegated, denied,
expired privilege, revoked membership, cross-tenant attack, resource access, connector failure,
credential failure).

Gate: the walkthrough runs from an empty machine on the documented path — the standard the
hardening programme established, which is what makes the demonstration evidence rather than a
screenshot.

## §14 — Adversarial review and certification (M) — directive Phases 14 and 35

The red-team list from the directive, in its areas: identity, tenant isolation, authorization,
resource hydration, query compiler, cryptography, external state. Every discovered defect gets
reproduce → failing test → fix → regression test → adversarial re-test. Then the certification
review with evidence per question, and the final report.

Gate: `docs/jdlib/production-readiness.md` complete with real numbers; every answer in the
certification list backed by a command that was run.

## §15 — Documentation (§26, §36)

The directive names seventeen `docs/jdlib/*.md` pages plus API reference. Existing pages are
updated, not duplicated; each is written after the phase it documents, and every claim is
machine-checked where checkable (counts, paths, line anchors).

---

## Sequencing summary

```
§1 hygiene → §2 credentials → §3 caching → §4 hydration → §5 delegation
           → §6 connector framework → §7 connectors → §8 query → §9 storage
           → §10 integrations → §11 observability → §12 audit
           → §13 reference app → §14 red team + certification → §15 docs
```

Each arrow is a real dependency, not a preference: §4 resolves credentials (§2) and caches
resolved handles (§3); §7 needs the framework (§6); §14 attacks what §4–§12 built.

## Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Programme outlives the session | lost context between phases | phase documents are the handoff; each phase ends with the repository green and the next inputs written down |
| Infrastructure flakiness on hosted runners (the ZITADEL cold-start class) | a phase gate reads red for reasons outside the change | gates name the failing component and report PARTIAL with the cause rather than disabling the job |
| Deferred connectors become "implemented" in prose | false capability claims | the matrix and the docs state deferred status; ADR-6's adoption conditions are quoted wherever a connector is mentioned |
| Query-system scope creep back toward a general DSL | a second path to tenant data | ADR-1 is binding; §8's gate asserts `TenantRepository` remains the only tenant-plane path |
| Coverage baseline invites gaming | tests written for the number | coverage is a *reported* figure, never a phase gate target |
| The archived library's fail-open habits re-enter by convenience | exactly the defects this programme rejects | every phase's security tests include the fail-closed mutation check |

## Open product questions (asked, not assumed)

1. **gRPC** (ADR-11): is there a consumer? Absent one, it stays deferred.
2. **Analytics engines** (ADR-6): which engine, if any, does a real consumer need first? The
   framework is engine-agnostic, so the answer changes a small amount of work.
3. **`jdlib_reference`-style extraction**: whether JDLib should eventually ship a consumer-facing
   scaffold — not required by any phase, noted so the question is not lost.
