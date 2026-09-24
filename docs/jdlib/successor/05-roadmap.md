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

**Status: DELIVERED (2026-09-24).** `ResourceHandle` (validated opaque name), `ConnectionConfig` (renders without its target), `ResourceResolver` and `ResourceHydrationError`. Lazy resolution keyed by tenant, handle **and credential version**, so a rotation rebuilds rather than serving a stale target; a cached value is type-checked before it is handed out, so a poisoned entry fails closed; one lock per scope, so concurrent hydration of the same handle resolves exactly once. The resolver enforces nothing - the checks are injected by the caller, because this library has no third enforcement point - and every refusal raises rather than falling back to a shared target.

All eleven gate items have a named test: right tenant, wrong tenant, missing context, suspended tenant, unauthorized resource, rotated credential, expired privilege, cache isolation, cache poisoning, credential leakage, concurrency.

Two corrections were made against the plan while building it. First, `VersionedSecretProvider.current_version` now establishes the version on demand: a caller deciding whether a cached target is still valid must be able to ask *before* resolving, and reading the inner provider is the cheap half of that decision. Second, the wrong-tenant test asserts isolation (one tenant's entry cannot satisfy another, and corrupting A's entry cannot make B fail) rather than a refusal, because refusing would mean the resolver deciding authorisation - exactly the third enforcement point the design forbids. Authorisation belongs to the injected check, which has its own test.

Gate: the directive's test list — right tenant, wrong tenant, missing context, suspended tenant,
unauthorized resource, revoked credential, expired privilege, cache isolation, cache poisoning,
credential leakage, concurrency — each mapped to a named test.

## §5 — Delegated and privileged access (S–M) — directive Phase 5

`PrivilegeContext(kind="delegation")` with capability, justification, TTL, revalidation and audit
(ADR-3). No new enforcement point.

**Status: DELIVERED (2026-09-24).** `PrivilegeKind.DELEGATION` joins the existing descriptor rather than spawning a privilege model (ADR-3), `PrivilegeContext` gains an optional `delegation_id`, and `validate_delegation` refuses a delegation that is expired, unidentified, replayed, unjustified, for the wrong capability, aimed at another tenant, or whose actor has been suspended. It decides nothing: a refusal is raised for the caller's existing enforcement point to act on, and anything that is not a delegation passes through untouched, which is why the operator path has a positive control of its own.

Nine tests, one per gate item plus three positive controls. TTL is enforced through the descriptor's own `is_live`, not a parallel rule, so there is one answer to "is this privilege still good". The `seen` set and the suspension check are injected, because this library does not own that state.

Gate: adversarial suite over the *existing* descriptor — TTL expiry, absent justification,
capability mismatch, replay, cross-tenant target, privilege used after actor suspension.

## §6 — Connector framework (M) — directive Phase 6

`DataConnector` protocol, `ConnectorRegistry` (startup-validated), `ConnectorFactory`,
`ConnectorCapabilities`, `ConnectionPolicy` with timeout/retry/circuit-breaking, plus the contract
test suite and test doubles every implementation must pass (ADR-6).

**Status: DELIVERED (2026-09-24).** `DataConnector` protocol, `ConnectorCapabilities`, `ConnectionPolicy`, `CircuitBreaker`, `ConnectorRegistry` and `assert_connector_contract` in `jdlib.data`. The inventory's constraint is honoured rather than mentioned: the policy **extends** the existing adapter-local idiom (validated frozen config, injected clock and sleeper, fail-closed exhaustion) and adds only what the inventory recorded as genuinely absent - circuit breaking and half-open recovery. Retry classification consults `is_retryable()` first and the error's own `transient` flag second, so the public contract that had no callers now has one.

Async discipline is checked by inspection, not by racing a timer: a synchronous implementation fails `assert_connector_contract`, and the registry refuses it at registration, which is what "startup-validated" has to mean to be worth anything. The authorized-context gate lives in the connector because it is the only party that can see both the target and the context at once, and `ConnectionConfig` now carries `tenant_id` so that check is possible at all.

13 tests, TDD. Two were mine to fix: the policy API is async and one call had been left un-awaited, and capabilities are a class attribute because the registry validates a connector *type* before any configuration exists to instantiate one.

Gate: a connector that cannot verify it received an authorized context refuses to open; a
blocking-call test proves async discipline (ADR-14).

## §7 — Data connectors (S) — directive Phase 7

The PostgreSQL connector (reusing the existing engine, strategies and pool rules). Snowflake,
MongoDB, StarRocks, BigQuery: **DEFER**, each with the adoption conditions named in ADR-6. No empty
shells ship (§38).

**Status: DELIVERED for PostgreSQL; the other four engines remain DEFERRED** (2026-09-24). `PostgresConnector` in `jdlib.data`: it reuses the library's own async engine layer and the pool rule already in use (`create_async_engine`, `pool_pre_ping`) rather than adding an engine abstraction, and it builds its engine per open from the RESOLVED target - never from a DSN it holds, because a stored DSN is a credential that outlives its rotation.

Two refusals carry the phase: a tenant mismatch between the authorized context and the target refuses to open, and a statement that is not a read is refused, because the connector declares `writes=False` and a declaration nothing enforces is a comment. The read check is deliberately shallow - first keyword, comments stripped - because the thorough analyser already exists elsewhere in the library for the tenant plane, and a second competing SQL analyser is the duplication the naming decisions forbid.

Gate evidence: a live round trip, a health check across the open/close boundary, and a timeout (`pg_sleep` under a one-second policy timeout raising `ConnectorTimeoutError`), all against a real PostgreSQL 16 server in the integration layer with no mocks. The **retry** half of the policy gate is evidenced at the policy level in §6 rather than here: inducing a transient PostgreSQL failure reliably is not something this suite pretends to do, and the application-level recovery drill already covers restart behaviour. Five integration tests.

Snowflake, MongoDB, StarRocks and BigQuery are **not** stubbed: no empty shell ships, per the directive's own rule, and their adoption conditions remain as ADR-6 records them.

Gate: live round-trip against the existing PostgreSQL lab; health check; policy behaviour under
timeout and retry.

## §8 — Query specification and compiler (L) — directive Phase 8

Scoped by ADR-1: engines without an ORM only. Deliverables: `QuerySpecification` (Pydantic),
AST, `QueryCompiler` → `CompiledQuery` (text + bound parameters as one value), `QueryDialect`,
and `query/safety.py` (identifier allowlist enforced **at parse time**, dangerous-construct
rejection, complexity limits, tenant constraint applied by the compiler).

**Status: DELIVERED (2026-09-24).** `jdlib.query`: `QuerySpecification` (Pydantic), `Filter`/`SortKey`, an immutable `QueryNode` AST, `IdentifierPolicy`, `parse_specification`, `QueryCompiler` → `CompiledQuery`, and dialects for PostgreSQL and MySQL.

Three decisions carry it. The allowlist is enforced **at parse time**, so a hostile or unknown table, column, operator or sort key never reaches a compiler - and there is exactly one place to audit. Dangerous constructs are **unexpressible** rather than forbidden: the specification has no field for raw SQL, a join, a subquery or a function call, and every value is bound, so `(select secret from credentials)` and `'; drop table events; --` are both simply values. And `CompiledQuery` carries its text and its parameters as ONE value, because neither is useful without the other - a caller cannot run the statement with values interpolated or reuse the parameters against different SQL.

The tenant constraint is applied by the compiler from the security context, never from the caller, and a specification naming a different tenant is refused rather than narrowed. A specification naming a **tenant-plane** table is refused outright: ADR-1 puts `TenantRepository` on that path and the compiler does not become a second one - which is the roadmap's own gate item, tested as `test_a_tenant_plane_table_is_out_of_reach`.

37 tests, TDD, adversarial by construction: injection through values and through every identifier position, subquery smuggling, unbounded pagination, query amplification via an oversized `IN` list, cross-tenant AST, and an absent security context.

Gate: fuzz/adversarial suite — SQL injection attempts, identifier injection, dangerous constructs,
unbounded pagination, cross-tenant AST, query amplification — plus a test asserting
`TenantRepository` remains the only path to tenant-plane rows.

## §9 — Object storage (M) — directive Phase 9

`ObjectStorageProvider`, `StoredObject`, `ObjectMetadata`, and exactly one verified backend
(ADR-5). GCS and Azure stay deferred and unexported.

**Status: DELIVERED (2026-09-24).** `jdlib.storage`: `ObjectStorageProvider` protocol, `StoredObject`, `ObjectMetadata`, `assert_object_storage_contract`, and one verified backend - `S3ObjectStorage`, tested against real MinIO. Google Cloud Storage and Azure Blob have **no module and no export**: a provider class in the public surface is a claim that it works, and a test asserts they are absent rather than merely discouraged.

Keys are built in exactly one place and are always relative to the caller's tenant, so a key cannot name another tenant's object even if a caller tries. The refusal list is blunt on purpose - a parent segment, an absolute path, an empty key, a separator a different SDK might normalise - because silently repairing a key is exactly how one tenant's write lands in another tenant's prefix. Six hostile keys are tested.

The S3 client is blocking, and every call is dispatched to a thread: that is the honest way to meet the async discipline ADR-14 asks for rather than an async-looking wrapper around a blocking call. The endpoint, bucket and credentials arrive through section 4's resolved target - never a stored DSN - and the provider refuses to open when the authorized context does not cover the target.

13 integration tests against real MinIO, no mocks: put/get round trip, metadata without downloading, a stream that actually streams, delete, cross-tenant invisibility, key escapes, the unauthorized-context refusal, and the export boundary.

Gate: live put/get/list/delete/stream round-trip; tenant-scoped key construction; credentials
resolved through §2's path; no provider class exported without a passing contract suite.

## §10 — Integrations: background jobs and propagation (M) — directive Phase 10

`JobEnvelope` with the revalidation chain (ADR-10); CLI administrative context already exists and
is only extended; the two *measured* trace-propagation gaps (gateway→app, JDLib→PDP) closed or
documented as PARTIAL with the stopping point cited. gRPC: DEFER, flagged (ADR-11).

**Status: DELIVERED (2026-09-24).** `jdlib.tenancy.job_envelope`: `JobEnvelope` and `JobDispatcher`, extending `ContextPropagator` rather than replacing it. The tenant token, its signature, its TTL and its clock were already `EnvelopeCodec`'s, and the chain a job must walk - principal active, tenant present, entitlement held, tenant servable - was already `ContextPropagator.reconstruct`'s. Nothing was rebuilt.

A queue needs two things a request does not. The same delivery may arrive twice, so the envelope carries a job id; and a job may wait in a queue while the authority behind it is withdrawn, so the envelope carries its own lifetime and is revalidated **at execution, not at enqueue**. Both are signed together with the tenant token, so a rewritten expiry fails the way a rewritten tenant would - and the identity is the forgery that matters, since swapping a job id is how replay detection would be defeated.

A job id is required rather than defaulted: an unidentified job is not a safer job, it is an undetectable replay. The chain runs authenticity, lifetime, identity, revocation, then the tenant chain, so a cheap local check precedes a lookup. Fail closed is tested as work not happening - one test drives each of the five failure modes and asserts the handler never ran - rather than as an error being reported after the fact.

21 unit tests. One latent defect fixed on the way, in test support rather than production: `ServabilityStub` built itself as `suspended or set()`, and because an empty set is falsy a caller who passed one had it discarded - so suspending a tenant *after* constructing the stub could never be observed. That is exactly the case the gate needs to test.

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
