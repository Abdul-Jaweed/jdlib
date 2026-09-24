# JDLib successor programme — adoption decisions (ADRs)

Each decision below is binding on the phases that follow. Format: context, decision,
consequences. Status is `Accepted` unless stated. Nothing here is retroactive: the phase
documents under `docs/security/` govern work already delivered, and this record governs what comes
next.

---

## ADR-1 — The query system is scoped to engines without an ORM

**Context.** `docs/jdlib/07-implementation-design.md` §2 lists "generic query DSL" among the
patterns *deliberately rejected*. This programme's directive, in its query-system section, asks for
a declarative specification, AST and SQL compiler.

**Decision.** Both hold, because they are about different surfaces. The query system exists for
access to engines where no ORM path exists — the analytics connector family — and it never
replaces `TenantRepository` on the PostgreSQL tenant plane. On that plane the enforcement stack is
the ORM, RLS, the metadata lint and `TenantSession` stamping; a second query path there would be a
second way to reach tenant data, which is precisely what the rejection protects.

**Consequences.** The compiler is pure and infrastructure-free, so Phase 8 can fuzz it without a
database. Connectors for engines with an ORM (PostgreSQL) do not use it. The phase's gate includes
a test that `TenantRepository` remains the only path to tenant-plane rows.

---

## ADR-2 — Credentials are never cached in a shared cache

**Context.** The capability inventory's most severe finding: the archived library serialises the
fully decrypted tenant document — including database passwords and an RSA private key — into Redis
for twelve hours by default, over an unauthenticated connection, keyed without a tenant namespace,
and its own multi-tenancy document shows the payload.

**Decision.** No credential material enters a shared cache, ever, for any TTL, under any flag.
Secrets resolve per use through `SecretProvider`; a process-local cache of a *resolved* connection
configuration is permitted but keyed by `(SecretRef, SecretVersion)` and invalidated on version
change. Serialised credential documents do not exist in JDLib.

**Consequences.** Phase 3's tests include a mutation check that the guard is load-bearing: a cache
write of a credential-shaped value must fail the suite, not merely be discouraged by a docstring.

---

## ADR-3 — Delegation extends `PrivilegeContext`; there is no second privilege model

**Context.** The directive's delegated-access phase says so directly, and JDLib already implements
privileged access: capability sets per operator level, a `PrivilegeContext` descriptor with
capability, justification, actor and TTL, every use audited as `context.privileged_used`, and the
frozen rule that no principal is authorized by both the platform layer and the tenant PDP.

**Decision.** Delegation is `PrivilegeContext(kind="delegation")` with the same descriptor fields
and the same audit obligations. `DelegationContext`, `PrivilegedAccess` and `RequestSecurityContext`
as *new* public types are rejected (`03-api-naming.md` §2).

**Consequences.** Phase 5 cannot add an enforcement point; it adds a capability and the
revalidation rules around an existing one. The adversarial suite attacks the *existing* descriptor
(TTL expiry, justification absence, capability mismatch, replay), which is also where a
delegation-specific bug would live.

---

## ADR-4 — New public API in new namespaces; pinned surfaces frozen

**Context.** `tests/unit/security/test_security_public_surface.py:68` pins
`jdlib.security.__all__` by exact equality and asserts `SecurityConfig not in jdlib.__all__`; the
top-level list is 13 curated symbols.

**Decision.** No new symbol enters either pinned list. New surfaces are new subpackages with their
own `__all__` and their own exact-equality surface test.

**Consequences.** Additive by construction; a consumer pinned to today's surface cannot break. The
cost is that some genuinely useful names are reachable at a deeper import path — accepted.

---

## ADR-5 — Object storage: one verified provider, no shells

**Context.** The archived library exports GCS and Azure classes whose every method raises
`NotImplementedError`, and its README claims multi-provider support including versioning and
lifecycle.

**Decision.** v1 ships the provider abstraction and one implementation verified against a real
service. A provider without a running service to verify against is `DEFER`, and its class is not
exported. Documentation describes only providers that exist — §18 of the directive and the
hardening programme's failure-honesty rule agree.

**Consequences.** Phase 9's evidence includes a live round-trip (put/get/list/delete) against the
verified backend, with the unverified backends named as deferred rather than absent.

---

## ADR-6 — Data connectors: one in v1, the rest deferred with reasons

**Context.** The archived library's relational engine support is effectively Snowflake-only;
BigQuery and StarRocks are partial; each carries duplicated cache/ORM logic that produced real
defects. This environment has no Snowflake, MongoDB, StarRocks or BigQuery service to verify
against, and no JDLib consumer requests one.

**Decision.** v1 implements the connector *framework* plus the PostgreSQL connector (which reuses
the existing engine and strategies). Snowflake, MongoDB, StarRocks and BigQuery are `DEFER`, and
each is adopted only with: a contract test suite it passes, a test double for consumers, and a
verified run against a real service.

**Consequences.** The framework is what Phase 6/7 deliver; "connector count" is explicitly not a
success measure (§38: parity is not the objective). Adopting one later is a small, bounded piece of
work because the framework exists.

---

## ADR-7 — Cryptography fails closed, and a decryption failure is an error

**Context.** The archived implementation returns the ciphertext as if it were plaintext when
decryption fails, and returns an empty string on a backend encrypt failure — contradicting its own
backend contract.

**Decision.** `EncryptedValue` carries ciphertext plus key/version metadata. Decryption either
returns plaintext or raises `CryptographicError`. Rotation follows shadow-write → prefer-new →
new-failure-fails-closed. A downgrade to an older key happens only where a written security model
permits it, and no such permission exists in v1.

**Consequences.** Phase 4 tests include: wrong key, corrupted ciphertext, rotation race, downgrade
prevention, and a mutation check that removing the fail-closed branch fails the suite.

---

## ADR-8 — Cache keys are tenant-scoped by construction and never global-flushed

**Context.** The archived cache keys were built by unseparated string concatenation
(`xxh128(f"{instance}{role}{schema}{db}")`), one engine omitted the tenant entirely, serialisation
wrote Python `repr()` values that can never be parsed back, and invalidation's fallback was a
global `FLUSHALL`.

**Decision.** `ScopedKeyFactory` is the only key constructor in the library; it produces
delimiter-safe, version-tagged, namespace-explicit keys and refuses to build a tenant-scoped key
without a tenant. Values serialise through a versioned envelope that round-trips. Invalidation is
per-namespace and tenant-scoped; a global flush is not offered.

**Consequences.** Phase 2's tests include cross-tenant poisoning attempts, TTL expiry, version
skew, Redis unavailability with local fallback semantics, and a serialisation round-trip test — the
test the archived library lacked, which is why its defect survived.

---

## ADR-9 — The duplicate port declarations stay; unification is out of scope

**Context.** Two namespaces declare `PolicyDecisionPoint` and two declare `SecurityEventSink`
(foundation and security-programme surfaces).

**Decision.** Both stay for this programme. They are deliberate: the security programme's ports
were added beside, not inside, the foundation's so that existing consumers and the pinned surfaces
stayed intact. Merging them is a breaking change to a verified surface and is not required by any
phase in this programme.

**Consequences.** New code uses the port appropriate to its layer and does not introduce a third.
A future unification gets its own ADR and its own compatibility story.

---

## ADR-10 — Background execution revalidates; a serialized context is a claim

**Context.** The directive's background-jobs section specifies: verify envelope → validate
TTL/signature → reload principal/membership → reload tenant status → re-authorize → fresh context.

**Decision.** Adopted as written. A `JobEnvelope` is never sufficient authority; execution always
ends in a freshly created context. Envelopes are signed and TTL'd, and replay is bounded by both.

**Consequences.** Phase 10's adversarial tests include envelope forgery, TTL lapse, replayed
envelope after membership revocation, and tenant suspension between enqueue and execution.

---

## ADR-11 — gRPC is deferred, and the directive's conditional is taken at face value

**Context.** The directive lists gRPC under framework integrations; §19's background-jobs and CLI
requirements are concrete, while gRPC has no consumer in this repository, the reference application
or the CI matrix.

**Decision.** `DEFER`, flagged to the product owner. Building a gRPC surface with no consumer
produces an unexercised path — the failure mode the hardening programme spent a programme
eliminating. If a consumer appears, the work is bounded: metadata authentication, context creation,
authorization, delegation handling, propagation.

**Consequences.** Recorded in `05-roadmap.md` as an open product question rather than silently
dropped or silently built.

---

## ADR-12 — One dependency source of truth, and a test that keeps it true

**Context.** JDLib has one packaging defect today (`starlette`, imported and undeclared). The
archived library has worse: an undeclared `orjson` imported 46 times, an undeclared `pulsar`, two
competing requirements files, and unused declared packages.

**Decision.** `pyproject.toml` is the only dependency list. Optional integrations arrive as extras;
core installs nothing new for a PostgreSQL-only consumer. A test fails when a first-party source
import is neither declared nor standard library.

**Consequences.** The `starlette` fix lands in roadmap §1 with the test that would have caught it.
Adding a dependency becomes a deliberate, visible act.

---

## ADR-13 — Contexts are immutable; tenant switching requires a new context

**Context.** Existing JDLib rules: tenant context immutable for the session lifetime; no tenant
switching inside an existing session; the audit trail records the actor, not an ambient guess.

**Decision.** Extended unchanged to every new subsystem. A connector, cache entry, query or
background job is bound to the context it was created with and cannot be re-pointed.

**Consequences.** Phase 1's hydration tests include "wrong tenant" and "missing context" as
refusals, not as fallbacks; Phase 10's job tests include a context re-pointing attempt.

---

## ADR-14 — Async-first; sync adapters only where the driver offers nothing

**Context.** The archived library is sync throughout — every engine call blocks the event loop —
and its own architecture document admits it.

**Decision.** New ports are async. A sync adapter is permitted only where a driver has no async
API, and it must then run in a worker thread rather than blocking the loop.

**Consequences.** Connector contract tests assert the async surface; a blocking-call test (an
event-loop tick counter around a connector call) makes the rule checkable rather than aspirational.

---

## ADR-15 — Three hygiene fixes precede the first capability phase

**Context.** Phase 0 recon found: an undeclared import (`starlette`); no coverage measurement; and
`tests/integration` raising rather than skipping when Docker is absent.

**Decision.** Roadmap §1 delivers all three before Phase 1 begins: the dependency fix plus the
import/declaration test; coverage measurement wired into the gate (with a recorded baseline, not a
target invented up front); and a skip guard so a missing service appears as a skip with a reason
instead of an error.

**Consequences.** Every later phase's gate reports a coverage figure and an honest skip count,
which is what makes "tests pass" a measurement rather than an assertion.
