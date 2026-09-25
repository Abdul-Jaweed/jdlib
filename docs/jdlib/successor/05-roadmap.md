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

**Status: DELIVERED (2026-09-24).** `starlette` is declared with the FastAPI extra
(`pyproject.toml:55`); `tests/unit/test_dependency_declarations.py` fails when a first-party import
is neither declared nor stdlib; `scripts/ci-local.sh` runs the suite with coverage (reported, never
a threshold); `tests/integration` skips cleanly without Docker.

---

## §2 — Credentials and secret providers (M) — directive Phase 3

Extends the existing `SecretProvider` seam (IMPOVE row in the capability matrix) rather than adding
a second abstraction (ADR-2, ADR-4). Deliverables: `SecretRef`, `SecretVersion`,
`RotatingSecretProvider`, provider composition, revocation semantics, and redaction extended over
the new paths. Every credential-shaped value is proven absent from logs, exception text, audit
payloads and `repr()` by a mutation-checked guard.

Gate: unit + security tests; a mutation that removes the fail-closed branch fails the suite; a
credential-shaped value written to a cache is caught by a test.

**Status: DELIVERED (2026-09-24).** `jdlib.credentials`: `SecretRef` and `SecretVersion`
(`refs.py`), `VersionedSecretProvider` — rotation is *detected*, not performed (`rotation.py`) —
a composite provider, and redaction extended over the new paths (the cache refusal itself is §3's
ADR-2 guard).

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

**Status: DELIVERED (2026-09-24).** The four new boundaries emit spans: `resources.hydrate`, `query.compile`, `credentials.resolve` and `connector.acquire`. The machinery is the library's own and unchanged - `security_span` is inert without a tracer, validates every attribute against the bounded allow-list before it reaches an exporter, refuses identifiers and credentials outright, and never lets a telemetry error reach the caller (`security_span` finally has call sites; the reliability inventory had recorded none).

The rejected pattern was per-method instrumentation, so the assertions that carry weight are the negative ones: **one span per operation, named at the entry point, and no spans at all from the helpers beneath it** - the allow-list, the parsing, the cache lookups, the credential resolution and the rendering stay silent, and the refusal path lands on the boundary's own span as `security.result=refused` rather than opening a second one.

Telemetry safety is re-run over the new paths rather than assumed: a bound filter value and a resolved credential are both proven absent from every exported attribute, and every attribute is asserted to be in the `security.` namespace and neither forbidden nor sensitive. A collector that fails is asserted not to fail the operation.

10 unit tests. One support addition rather than a second local fake: the codebase had two clock shapes (the `Clock` protocol's `.now()` and a plain callable that `LocalCache` wants), so `CallableClock` now offers both in one place.

Gate: spans asserted at the listed boundaries and *absent* from helper internals; telemetry-safety
rules re-run over the new paths (no secrets, no payload text, no bind values).

## §12 — Audit and compliance for new capabilities (S–M) — directive Phase 12

Extend the existing audit model to credential access/rotation, resource lifecycle, connector
lifecycle, query rejections, delegation. The platform/tenant audit planes, operational logs,
metrics, traces and compliance evidence stay separate concepts (the directive says so, and the
existing implementation already does).

**Status: DELIVERED (2026-09-24).** Producers, mostly - which is the honest finding: the audit vocabulary was already richer than its producers. `CREDENTIAL_ROTATED` existed with nothing to emit it, so rotation now emits it. Delegation reuses the privilege vocabulary rather than growing a parallel one (ADR-3): `PRIVILEGE_USED` on acceptance, `AUTHZ_DENY` on refusal, emitted *before* the refusal is raised so the record exists even though the caller sees only the exception.

Five names are genuinely new - `RESOURCE_HYDRATED`, `RESOURCE_HYDRATION_REFUSED`, `CONNECTOR_REGISTERED`, `CONNECTOR_ACQUIRED`, `QUERY_REJECTED` - and the vocabulary pin in `tests/unit/security/test_audit_events.py` was **extended by name** (`SUCCESSOR_EVENT_TYPES`) rather than loosened to a subset check, so the next addition still has to be deliberate. The category pin gained `connector` for the same reason.

`SecurityEventEmitter` is a callable and `emit_safely` returns whether the event actually reached it, so 'recorded' and 'not recorded' are distinguishable rather than assumed. The rule is asserted as behaviour, not documented: a sink that raises does not soften a refusal and does not break a success, and an absent sink is not an error - audit is configuration, never a precondition for serving a request or for refusing one. No event carries a credential, a resolved target or a bind value; the tests assert their absence from the recorded events.

14 unit tests. Both audit-vocabulary pins fired when the types were added, which is the pins doing their job.

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

**Status: DELIVERED (2026-09-25).** The swap is on the data path: the app's report surface is built
from the successor capabilities — hydration → credential resolution → connector → compilation →
tenant-scoped query → audit — in `src/jdlib_reference_app/dataplane.py`, with the request models
beside the plane they belong to and the route in `main.py` behind `Depends(permission(...))`.

`tests/integration/test_reports_query.py` — **9 tests, run against a real database** — is the part
that makes this evidence rather than wiring: two tenants are provisioned and seeded, and the live
assertions are that the caller's tenant sees exactly its own row, that a caller-supplied filter on
the *other* tenant's id returns zero rows (the compiler's scope predicate is ANDed, not replaced),
that the tenant plane is refused at parse time and a hostile identifier refused before any
connection, and that the two boundary events were emitted. The earlier scenario list is carried by
the app's own suites from the phases that built those flows; this phase's new coverage is the data
plane.

One library change came *out* of this phase rather than being designed into it:
`ConnectionConfig.server_settings`. The live test failed first with `relation "memberships" does
not exist` while the compiled SQL was exactly right — asyncpg takes a `search_path` only as a
connection setting, and neither `?options=` nor `?server_settings=` in the DSN is honoured. That is
a property of a hydrated target, so the target now carries it and the connector passes it, with a
live test asserting `current_schema()`.

**Not claimed:** the walkthrough is run on this machine's documented path, not on a freshly
provisioned one; the empty-machine standard was demonstrated in the hardening programme (see the
app's `docs/final-report.md`), and repeating it was not part of this phase.

## §14 — Adversarial review and certification (M) — directive Phases 14 and 35

The red-team list from the directive, in its areas: identity, tenant isolation, authorization,
resource hydration, query compiler, cryptography, external state. Every discovered defect gets
reproduce → failing test → fix → regression test → adversarial re-test. Then the certification
review with evidence per question, and the final report.

**Status: DELIVERED (2026-09-25), sequenced before §13 on purpose.** §14 attacks what §4–§12 built, as the dependency note at the end of this roadmap says, so it needs only JDLib and can run while the reference-app swap is still outstanding.

`tests/unit/security/test_adversarial_successor.py` - **43 tests, and its honest headline is that it found no new defects.** The attacks that mattered were already refused by construction, and the way to say that without overclaiming is to show the *mechanism*: a caller-supplied filter on `tenant_id` produces a statement with **two** predicates and a bound parameter, not a replaced scope; a homoglyph identifier (Cyrillic `е`, `а`) is refused by an ASCII-only allow-list rather than by luck; a delegation identifier is checked per-identifier and not per-capability, so changing the requested capability does not reset the replay check; a re-encoded payload that keeps its original signature string is still refused. Two tests failed on the first run and both were the suite's own wrong guesses about the credential API (`ResolvedSecret.value`, `SecretRef(version=...)`) - recorded here rather than quietly corrected, because a red-team suite that only ever passes deserves suspicion.

`docs/jdlib/production-readiness.md` carries the certification answers, each with the command that produced it: **1077** unit tests, **358** integration tests, **64%** unit-layer coverage (7110 statements, branch on), 142 source modules, 120 test modules, 18110 source lines, lint and types clean over 142 files. It also carries a *what this does not claim* section: the unimplemented connectors and storage backends, the six reliability gaps still open after §6 closed circuit breaking, and the fact that infra-dependent suites skip where the lab is absent - a skipped suite is not evidence.

**Limit stated plainly:** this is the in-repo red team. Attacks against running infrastructure are exercised by the integration suites against real PostgreSQL, Redis and MinIO; they were not re-run as a discrete adversarial exercise against the lab stack in this phase, and no claim here rests on one.

Gate: `docs/jdlib/production-readiness.md` complete with real numbers; every answer in the
certification list backed by a command that was run.

## §15 — Documentation (§26, §36)

The directive names seventeen `docs/jdlib/*.md` pages plus API reference. Existing pages are
updated, not duplicated; each is written after the phase it documents, and every claim is
machine-checked where checkable (counts, paths, line anchors).

**Status: DELIVERED (2026-09-25).** The pages the directive names exist, and the ones that
describe a capability do not duplicate it — they index it:

| Page | Content |
|---|---|
| `architecture.md` | The layering, the two planes, where each refusal comes from |
| `security-model.md` | Trust boundaries, the fail-closed table, audit vs telemetry vs logs |
| `tenancy.md` | Resolution, placement, isolation, lifecycle, background work |
| `authentication.md` | Authenticators, machine identities, failure semantics, what authn does *not* do |
| `authorization.md` | The single enforcement point, the decision→outcome table, resources and their tenant |
| `privileged-access.md` | `PrivilegeContext`, the delegation conditions, replay keying, audit-before-raise |
| `resource-management.md`, `credentials.md`, `connectors.md`, `query-system.md` | Index the canonical capability pages |
| `production-readiness.md` | The certification answers (§14) |
| `capabilities/` | Seven capability pages plus an index: credentials, caching, resources, connectors, query, storage, jobs |

**Every claim is checked, not trusted.** Each capability page carries front-matter naming its
modules, exports, refusals, test files and test-function count, and
`tests/unit/test_successor_docs.py` verifies all of it — named modules and test files exist, exports
resolve in the namespace, each refusal is a real attribute of the module declared to define it, and
the stated count matches the files. The same module asserts the directive's page set exists and is
not a stub, and that no page cites a source path that has moved. Counts are test **functions**, not
parametrized cases, and the pages say so, because a case count depends on how the suite was invoked
while a function count is a property of the file.

**One correction worth recording:** the first version of that checker failed on its own parser — a
bare `sources:` key stored `""` where the following `  - item` lines expected a list — and the
capability pages were initially written one directory too deep (the generator joined the same
relative path twice). Both were caught by the checker and the directory listing rather than by
reading, which is the argument for having it.

---

## §16 — Neo4j graph capability (L) — directive §8–§17

Neo4j as a first-class data plane, not a driver wrapper: a `jdlib.graph` package following the
`jdlib.storage` / `jdlib.data` idioms — a port, one verified adapter behind an optional extra, its
own error taxonomy, tenant scoping built in exactly one place — with Cypher safety as a property of
the *types* rather than of a sanitiser, and every external call inside the reliability primitives the
library already owns (`CircuitBreaker`, `backoff_seconds`, `is_retryable_failure`) instead of a
second reliability stack.

The security model is the tenant plane's: the effective tenant comes from the authenticated context
and never from a request parameter; every query binds it as a parameter; a label, relationship type
or property key is a validated value, allowlisted at construction, so injection has no string to
land in. Retries do not duplicate writes — a write is retried only where the correctness model
permits it, and the audit record follows the committed outcome rather than the attempt.

**Status: COMPLETE (2026-09-26).** Landed as `b80f419` (config + errors), `327a6ad` (identifiers
and query builders), `a9f7d90` (client + policy), `209bc88` (tenant scoping + repository),
`adf071a` (transactions), `9b5c442` (reliability), `f174849` (observability + audit), `4ddd65b`
(harness + live suite), `afd71d7` (adversarial suite + the identifier-position fix). The capability
page is `docs/jdlib/capabilities/graph.md`.

Two defects were found and fixed inside the phase, both by writing tests that could fail:
a refusal emitted outside the context scope (an event with no actor is not evidence), and a
plain string in an identifier position interpolating into the statement — a cross-tenant mass
delete that every tenant check passed. The second is the reason the adversarial slice exists.

Limits, stated in the capability page: schema DDL has no path through the client (an operator
declares constraints out of band), and `GraphQuery` is a trusted low-level seam that cannot run
unscoped but is not vocabulary-checked.

Gate: Neo4j live in the infra harness (the suite skips cleanly without it); the injection suite
(Cypher, label, relationship type, property key, arbitrary query, cross-tenant traversal,
unrestricted delete); a test asserting the caller cannot supply the tenant parameter; the complete
local gate green.

## §17 — FastMCP integration (L) — directive §18–§28

The MCP server is a *consumer* of the library's security model, not a second one: authentication
resolves to the same `SecurityContext`, tenant resolution to the same `TenantContext`, authorization
to the same PEP/PDP pair, and every tool call walks the same
authentication → tenant → authorization → operation → audit → telemetry chain an HTTP route does.
Tools are typed and bounded; arbitrary Cypher or arbitrary database access is not a tool — if it
exists at all it is an explicitly privileged capability with authorization, audit and limits.

**Status: COMPLETE (2026-09-26).** Landed as `6a9e631` (registry), `f2190f4` (security boundary),
`3cac36f` (invocation chain), `2c04dbe` (graph tools), `1a2655e` (resources), `6c1ee99`
(concurrency gate in `jdlib.reliability`), `1e5581d` (drain, saturation and deadlines wired into
the invocation), `239f65c` (observability and audit), `819b6a8` (server factory behind the optional
`mcp` extra), `9e59db3` (adversarial suite). The phase close — the capability page and this line —
is the commit that carries it.

Ten slices, 8 modules, 16 public exports, 7 refusals, and 89 test functions across 9 files, all
machine-checked by `tests/unit/test_successor_docs.py` against the tree rather than trusted. The
capability page is `docs/jdlib/capabilities/mcp.md`.

**Two defects were found and fixed inside the phase.** The adversarial slice found a resource URI
that was not registered reaching `self._resources.get(uri)` and then an attribute access on the
`None` it returned — a caller-supplied string producing a crash where the surface owes a refusal;
it now raises `McpResourceDefinitionError`, the error the registry already raises for an unknown
tool. And the server factory found that fastmcp 4.0.10 advertises a tool's `additionalProperties:
false` schema without enforcing it, so the invocation chain enforces the declaration before
authorization — an advertised contract the library does not keep is a lie told to every client.

**Deliberately not claimed.** §26's metric names are not minted in the library: its observability
seam is spans plus the audit trail, and metrics are the collector's derivation from those spans in
the lab. Minting names with nothing to emit them is the vocabulary-with-no-producer the pin exists
to catch. `mcp.dependency` is likewise not a second span — the dependency's own span is
`graph.statement`.

### The reuse map — what the boundary composes rather than reimplements

The directive's §18 chain (MCP → security boundary → SecurityContext → authentication → tenant
resolution → authorization → service → resources) is built out of the parts that already exist:

| Step | Reused from |
|---|---|
| authentication | `jdlib.authn.wiring.build_authenticator` — the same validator the HTTP path installs |
| principal | the `PrincipalProvider` seam `jdlib.integrations.fastapi` already takes |
| tenant resolution | the `TenantResolver` protocol (`jdlib/tenancy/resolution.py`) and the `ResolverChain` the FastAPI installer takes |
| authorization | the `PolicyDecisionPoint` protocol (`jdlib/security/authz/interfaces.py`) behind the same `Enforcer` |
| privilege | the existing privilege mechanism — a second one is explicitly forbidden (§20) |
| audit | the `SecurityEventEmitter` seam and the `SecurityEventType` vocabulary, extended by name |
| telemetry | the `TracerLike` span seam (`jdlib.security.tracing`) — spans, not a second metrics stack |
| reliability | `jdlib.reliability` (breaker, budget, policy, lifecycle) — request and dependency timeouts, retry where safe, cancellation |
| data | `jdlib.graph`'s `GraphRepository` and `jdlib.data`'s connectors — no tool touches a driver |
| errors | `jdlib.security.responses` — the one canonical envelope, extended with the MCP shapes |

A test asserts the reuse rather than the resemblance: the boundary is given the same collaborator
objects the HTTP installer takes, and the denial path is proven not to execute the handler.

### Slices

1. the tool registry: a tool declares its capability, its schema and its handler, and a tool
   without a declared capability cannot be registered at all (the roadmap's own gate);
2. the security boundary: a request's credential becomes a `SecurityContext` through the reused
   authenticator, and identity claims in tool arguments are refused rather than read;
3. the invocation chain: boundary → authorization → handler inside the context scope → audit,
   with the denial path proving the handler never ran and the error mapping proving no internal
   detail escapes;
4. the graph tools: `graph_get`, `graph_search`, `graph_create`, `graph_update`,
   `graph_create_relationship`, `graph_delete` over `GraphRepository` — tenant from the context,
   identifiers from the vocabulary, bounded inputs, a delete that needs the stronger capability;
5. the resources: read-only, authorized, tenant-aware, bounded, audited when sensitive, and
   structurally unable to expose configuration or secrets;
6. reliability: request timeout, dependency timeout, cancellation propagating to the operation,
   bounded concurrency, graceful shutdown — through the existing primitives;
7. observability and audit: the `mcp.*` span names and the audit events, with the vocabulary pin
   extended by name, and correlation ids carried end to end;
8. the server: an optional `mcp` extra, the framework imported lazily (import-safety proven in a
   subprocess), a factory that wires the registry onto FastMCP, and a graceful shutdown path;
9. adversarial: forged identity arguments, a tool with no capability, cross-tenant tool calls,
   injection through arguments, the error surface, and cancellation;
10. the capability page, the roadmap close, and the complete gate.

Gate: the same security, audit and observability assertions the HTTP path carries, run through the
MCP entry point; a tool inventory test that fails when a tool is added without a declared capability;
the live layer for the graph-backed tools; and the complete local gate green.

## §18 — Example application: minimal and enterprise (L) — the example-application directive

Two runnable examples against the real library: a minimal one (FastAPI → JDLib → PostgreSQL, the
smallest correct setup) and an enterprise one (gateway, Cerbos, PostgreSQL, Neo4j, MCP, audit,
reliability, observability), with the feature matrix, the per-feature documentation template, the
with/without-JDLib comparisons and the test matrix the directive asks for.

**Status: NOT STARTED.** Depends on §16 and §17: an example may not document a capability the
library does not have, and the directive's own rule is that the example must actually run.

Gate: both examples run from the documented path on an empty lab; every documented command is
executed at least once; the feature matrix cites `file:line`; no claim without an example and a test.

## Sequencing summary

```
§1 hygiene → §2 credentials → §3 caching → §4 hydration → §5 delegation
           → §6 connector framework → §7 connectors → §8 query → §9 storage
           → §10 integrations → §11 observability → §12 audit
           → §13 reference app → §14 red team + certification → §15 docs
           → §16 Neo4j graph → §17 FastMCP → §18 example application → §19 certification
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

---

## §18 — Example application and developer documentation (L) — directive §1–§32

The directive asks for two runnable examples, a documentation set that follows one template per
feature, a "with and without JDLib" comparison, a test matrix, a security review of the example
itself, and a final report — with the examples, the docs and the tests kept consistent with each
other, and with the documentation *tested* rather than assumed (§27).

**Where the artefacts live, and why.** The directive offers a tree and then says to adapt it to the
repository's own conventions, so:

| Directive | Here | Why |
|---|---|---|
| `examples/minimal`, `examples/enterprise` | same, at the repo root | no existing convention to follow, and `packages = ["src/jdlib"]` keeps them out of the distribution |
| `docs/examples/` | `docs/jdlib/examples/` | `docs/jdlib/` is where the library's own docs live |
| `docs/features/` | `docs/jdlib/features/` | the template-shaped developer guides |
| `docs/architecture/` | `docs/jdlib/architecture/` | beside the existing `docs/jdlib/architecture.md`, which links to them |

The existing `docs/jdlib/*.md` pages (`authentication.md`, `authorization.md`, `tenancy.md`,
`privileged-access.md`, `credentials.md`, `connectors.md`, `query-system.md`,
`resource-management.md`, `security-model.md`) are the **design authority** for their topics. The
new `features/` guides are the developer-facing shape of the same material and link to them rather
than restating them: two authorities for one topic is how documentation starts lying.

### The reuse map — what the examples compose rather than reimplement

| Step | Seam the example uses |
|---|---|
| installer, middleware, error envelope | `jdlib.integrations.fastapi.install` (`fastapi.py:57`) and `install_error_envelope` (`:127`) |
| request-scoped collaborators | `JdlibContainer` (`fastapi.py:49`), `get_context` (`:77`), `get_uow` (`:82`) |
| per-route authorization | `require(permission)` (`fastapi.py:87`) |
| authentication, principal, tenant resolution | `build_authenticator` (`authn/wiring.py:30`), the `PrincipalProvider` and `ResolverChain` seams |
| graph access | `jdlib.graph.GraphRepository` and its `GraphQuery` builders — never a driver |
| MCP surface | `jdlib.integrations.mcp.build_mcp_server` (`mcp/server.py`), `graph_tools`, the resources |
| audit | `SecurityEventEmitter` + the `SecurityEventType` vocabulary |
| telemetry | the `TracerLike` span seam (`security/tracing.py`) |
| reliability | `jdlib.reliability` — breaker, budget, policy, `ConcurrencyGate`, `ShutdownCoordinator` |
| errors | `jdlib.security.responses` — the one canonical envelope |

An example that reached a driver, minted its own error body or wrote its own tenant check would be
the thing this programme exists to remove, so each example is checked for exactly that: the tests
assert the example's routes are declared through `require(...)` and that no example module imports
a driver, a raw session factory or a second envelope.

### Status

| Slice | State | Evidence |
|---|---|---|
| E1 — the minimal example | **landed** `47caeb6` | 11 tests in `examples/minimal/tests` (shape, envelope, readiness, startup refusal, the live operator step and the live denial with an allowing control); 9/9 mutations bit; two library defects found and fixed (`ConnectionError` → 503 on the async driver, and the guard's `jdlib_permission` declaration) |
| E2 — configuration, security, api | **landed** | `examples/enterprise/`: settings marked required/optional, the Cerbos bridge, the operator directory, the audit sink, two guarded routes; 5 tests, 2/2 mutations |
| E3 — services, repositories, graph, mcp, **and the Cerbos policy files + `docker/`** | next | the policy files move here from E2 so that every artifact ships having been run: a policy that has never been compiled against a live engine is a claim, not a control |
| E4–E8 | next | as listed below |

The examples are type-checked from E1 onwards (`mypy src/jdlib examples` in `scripts/ci-local.sh` and
the workflow), and their tests are collected by the repository's own gate (`testpaths`).

### Slices

1. **E1 — the minimal example.** *Landed* `47caeb6`: a real FastAPI app that installs the
   library, serves one tenant-scoped route through `require(...)`, and answers a denial; runnable
   with uvicorn and driven in-process by `httpx.ASGITransport` (the repository's own convention —
   no `TestClient`, which the suite's warning flags retire). README with the run commands.
2. **E2 — the enterprise example: configuration, security, api.** `examples/enterprise/app/`
   skeleton: `configuration/` (settings from env, no secrets in files), `security/` (authenticator,
   principal provider, resolver chain, container), `api/` (routers with `require(...)`), plus
   `config/`, `docker/` and the README.
3. **E3 — the enterprise example: services, repositories, graph, mcp.** The layers below the API,
   including a graph repository use and an MCP surface built by `build_mcp_server`.
4. **E4 — the enterprise example's tests.** `tests/{unit,integration,security,e2e}` in the example:
   unit (no services), integration (Postgres via the harness), security (tenant isolation, denial
   non-execution, no error leakage), e2e (a request through the whole chain).
5. **E5 — feature documentation.** The 14 guides under `docs/jdlib/features/`, each with the
   directive's headings (what / why / when / when not / how / architecture / example / security /
   reliability / observability / audit / configuration / testing / common mistakes / production),
   each linking to its design-authority page.
6. **E6 — architecture and flows, and the example docs.** `docs/jdlib/architecture/`
   (example-architecture, security-flow, tenant-flow, neo4j-flow, mcp-flow, observability-flow)
   and `docs/jdlib/examples/` (overview, minimal-example, enterprise-example, with-and-without,
   developer-journey).
7. **E7 — the documentation is tested (§27) and the matrix is derived (§28).**
   `tests/unit/test_example_docs.py`: every guide carries every template heading, every cited path
   exists, every documented command is one the repository can run, the matrices' rows cite test
   files that exist and hold tests, and the examples import. A register that lies fails its own
   test — the same treatment the capability pages already get.
8. **E8 — security review, final validation, final report (§29–§32).** The example's own security
   review with evidence per check, the complete gate at the end of the phase, and the report with
   the directive's fields.

### What the directive forbids, restated as constraints

* **No deliberately vulnerable code** for the without-JDLib comparison (§25): those examples are
  illustrative snippets, marked as such, never runnable production paths.
* **No unsupported claims** in the comparison: every "with JDLib" cell names the seam that does it.
* **Fast validation during development** (§30): the layered gate per slice; the complete
  container-backed suite at the phase boundary rather than after every edit.
* **Do not weaken tests to achieve green, do not convert failures into skips** (§30) — and a
  documented command that does not work is fixed, not removed (§27).

**Status: IN PROGRESS (started 2026-09-26).** §17's MCP surface and §16's graph plane both landed,
which is what the enterprise example composes.
