# JDLib successor programme — reliability and resilience inventory

**Question this document answers:** what reliability and resilience capability does JDLib *already* have, at file:line, and what must happen to each piece before any new reliability code is written?

Method: read-only source inspection at HEAD `902c16499451a08690ccb1921da5efdede7017a7` (the Phase-0 documents were measured at `15a7058`; the tree is clean). No test suite and no container was run for this note. Paths are relative to the repository root. Classification vocabulary is the directive's: **KEEP** · **EXTEND** · **IMPROVE** · **REDESIGN**, with **ABSENT** where nothing exists.

## Summary — the single most important finding

JDLib does not lack reliability machinery; it deliberately lacks a reliability *framework*. Timeout enforcement, bounded retry, exponential full-jitter backoff, retry classification and fail-closed dependency-failure handling already exist — inside the outbound auth adapters (`src/jdlib/security/authn/provider.py:249-284`, `src/jdlib/security/authn/transports.py:110-120`) and one persistence path (`src/jdlib/persistence/strategies/rls.py:92-105`) — while the public retryability contract `is_retryable()` (`src/jdlib/security/errors.py:260`) has **no call site anywhere in `src/`**. The directive's architectural rule is explicit and already implemented for retry: outbound transport policy "live[s] with the HTTP adapters that use them" (`src/jdlib/security/config.py:17-20`). The consequence for `ConnectionPolicy` is precise: wire the existing error taxonomy into the existing adapter-local retry idiom and extend both to connectors. Seven areas are genuinely absent — retry budgets, circuit breaking, half-open recovery, worker/background retry, dead-letter handling, security-context preservation during retries, and shutdown/drain (searches in §1.2).

## 1. Inventory

### 1.1 Areas with a source footprint

| Area | Where (file:line) | State | What it actually does | Classification |
|---|---|---|---|---|
| Timeout enforcement | `src/jdlib/security/authz/cerbos.py:51,63-64,112-114`; `src/jdlib/security/authz/transports.py:15,41-49`; `src/jdlib/security/authn/provider.py:94,110-111,256-258`; `src/jdlib/security/authn/transports.py:31,65,100`; `src/jdlib/authn/oidc.py:53,76`; `src/jdlib/security/config.py:33,63,134-138,143-147`; `src/jdlib/persistence/strategies/rls.py:12,96` | Implemented, per adapter; two-layer | every outbound call is bounded twice — `asyncio.wait_for` around the adapter call and an httpx/DDL timeout in the transport; config rejects a non-positive timeout in every environment and caps the authorization timeout at 10 s in production | **EXTEND** |
| Retry policy | `src/jdlib/security/authn/provider.py:96-97,249-278`; `src/jdlib/security/authn/transports.py:9-16,32,110-120`; `src/jdlib/persistence/strategies/rls.py:12-15,70-76,92-105` | Implemented, two independent loops; no shared abstraction | token acquisition retries only transient failures (`max_attempts=3`, backoff, then fails closed); RLS DDL retries transient lock conflicts (3 attempts, linear 0.25 s × attempt); permanent failures raise on the first attempt | **EXTEND** |
| Exponential backoff | `src/jdlib/security/authn/provider.py:280-284`; `tests/unit/security/test_token_provider.py:181-204` | Implemented (token path); DDL path is deliberately linear | `ceiling = retry_backoff * 2**(attempt-1)`, delay clamped to `[0, ceiling]`; sleeper injected for tests (`provider.py:150,156`); the RLS loop uses `_DDL_RETRY_DELAY * (attempt + 1)` (`rls.py:105`) | **KEEP** |
| Jitter | `src/jdlib/security/authn/provider.py:151,157,280-284` | Implemented, injectable | full jitter (delay = `uniform(0, ceiling)`), with the jitter callable injected so a test can pin it | **KEEP** |
| Retry classification | `src/jdlib/security/errors.py:81-96,108-220,238-252,260-262`; `src/jdlib/security/authn/transports.py:32,114-120`; `src/jdlib/security/authn/provider.py:259-272`; `src/jdlib/persistence/strategies/rls.py:15,70-76` | Implemented; two different mechanisms | the descriptor table marks transient failures retryable (`PoolCapacityError`, `TenantOperationInProgress`, `RelocationPhaseError`, `AuthorizationUnavailable`, `AuthenticationUnavailable`) and security failures not; unknown failures fall back to non-retryable `INTERNAL_ERROR`; the HTTP transports classify on status (408/425/429/5xx); the DDL path classifies by exception class *name* against a two-name set | **EXTEND** |
| Retry budgets | — | **ABSENT** | no budget, no token-bucket or percentage-of-traffic limit; the only limit is the per-call `max_attempts` | **ABSENT** |
| Circuit breaking | `src/jdlib/security/config.py:17-20` (comment only) | **ABSENT** | the phrase occurs once in `src/`, in the rule that such policy belongs to the adapters; there is no breaker, no open/half-open state, no failure-rate tracking | **ABSENT** |
| Half-open recovery | `src/jdlib/authn/oidc.py:39-40,100-108,105-108` (nearest analogue) | **ABSENT** | the closest thing is the JWKS refresh floor (`min_refresh_interval`) plus stale-if-available — an outage-storm guard for one cache, not a recovery state machine | **ABSENT** |
| Dependency-failure handling | `src/jdlib/security/authz/decision.py:104-108,150-159`; `src/jdlib/security/authz/cerbos.py:3-7,115-119,156-159`; `src/jdlib/security/authz/pep.py:66-73`; `src/jdlib/security/errors.py:202-219`; `src/jdlib/authn/oidc.py:82-85,128-133,325-332`; `src/jdlib/tenancy/middleware.py:31-53` | Implemented, fail-closed | a counterpart failure is typed and never becomes success: a degraded decision can never be ALLOW, the PEP raises `AuthorizationUnavailable` (503, retryable) instead of 403, an IdP outage raises `AuthenticationUnavailable` (503) instead of 401 or anonymous, and telemetry failure is swallowed so an observability outage cannot change a decision (`src/jdlib/security/telemetry.py:251-270`) | **EXTEND** |
| Health/readiness | `src/jdlib/security/interfaces.py:55-57`; `src/jdlib/security/authn/jwt.py:15-17,140-142`; `src/jdlib/authn/oidc.py:135-137,144-147` | Implemented for authentication only | `ready()` on the validator port asks the key source whether key material is loaded, so a health check can separate "cannot validate tokens" from "no traffic yet"; `JwksCache.stale` is an operational signal; the library exposes no HTTP health endpoint, and no data connector has `health_check` yet (that is roadmap §6/§7: `docs/jdlib/successor/05-roadmap.md:91`) | **EXTEND** |
| Graceful degradation | `src/jdlib/security/authz/decision.py:104-108`; `src/jdlib/authn/oidc.py:39-40,114-133`; `tests/unit/security/test_jwks_hardening.py:175-187`; `docs/threat-model/README.md:67` | Implemented, fail-closed | "degrade" means degrade to the safe answer, never serve stale authority: stale keys may still verify a known `kid`, an unreachable policy engine denies and says so, and the documented position is that a PDP outage is a denial of service by design (`docs/threat-model/README.md:67`) | **KEEP** |
| Idempotency | `src/jdlib/persistence/strategies/rls.py:86-90`; `src/jdlib/authz/access.py:595`; `tests/integration/test_access_grants.py:363`; `tests/integration/test_migrations.py:56` | Partial, by construction only | retry-safety rests on operations being idempotent by construction — `DROP POLICY IF EXISTS` + `CREATE POLICY` re-run whole under transactional DDL, and grant insertion uses `on_conflict_do_nothing()` — and `rls.py:86-90` is the only written retry-safety argument; there is no idempotency-key mechanism anywhere | **IMPROVE** |
| Durable writes | `src/jdlib/persistence/uow.py:26-41`; `src/jdlib/persistence/session.py:280-315`; `src/jdlib/persistence/models.py:33-38`; `src/jdlib/models/audit_recorder.py:60-75`; `src/jdlib/security/audit/emitters.py:44-80`; `src/jdlib/security/config.py:180-183` | Implemented | `UnitOfWork` commits on a clean exit, rolls back on any exception and always closes the session; the write fence admits writes per tenant; audit rows are staged only on a session whose `add` is awaited, so a row cannot be discarded silently; audit cannot be disabled in production | **KEEP** |
| Worker/background retry | `src/jdlib/tenancy/jobs.py:40-68`; `src/jdlib/control/audit.py:120-126` | **ABSENT** | background execution has context reconstruction (verify signature → reload principal → reload tenant status → fresh context) but no retry, no queue, no backoff; the only "worker" mentioned is a consumer-side sink draining a queue (`control/audit.py:123`) | **ABSENT** |
| Dead-letter handling | — | **ABSENT** | no dead-letter store, poison-message path or failed-work record exists | **ABSENT** |
| Silent-failure prevention | `src/jdlib/models/audit_recorder.py:60-75`; `src/jdlib/security/authz/pep.py:12-15`; `src/jdlib/security/authn/provider.py:19-21,245-256`; `src/jdlib/security/telemetry.py:246-270`; `src/jdlib/persistence/session.py:39-43` | Implemented | a lost audit record can never be traded for a served request (an observer failure propagates), failed acquisitions are never cached, telemetry failure is reported once and never raised into a decision, and a session without tenant context refuses to operate | **KEEP** |
| Structured errors | `src/jdlib/errors.py:1-142`; `src/jdlib/security/errors.py:25-96,108-220`; `src/jdlib/security/responses.py`; `src/jdlib/tenancy/middleware.py:36-53` | Implemented | every library failure carries a stable code, HTTP status, retryable flag and security classification; `describe_error` walks the MRO; the middleware maps 503 (outage) against 403/401 (refusal) by class, with the more specific class listed first | **KEEP** |
| Retryability metadata | `src/jdlib/security/errors.py:87,260-262`; `src/jdlib/security/__init__.py:48,93`; `tests/unit/security/test_security_errors.py:119-126` | Implemented public contract, **no production caller** | `is_retryable(target)` returns the descriptor's flag for a class or instance; within `src/` it is defined and re-exported but consulted by nothing — the retry loops classify locally instead | **EXTEND** |
| Observability of retries (metrics/tracing/logging) | `src/jdlib/security/telemetry.py:137-151,78-131`; `src/jdlib/security/tracing.py:235`; `src/jdlib/security/audit/emitters.py:85-103` | Primitives exist; retries are invisible | `KNOWN_METRICS` contains no attempt/retry counter and the structured log record has no retry fields, so a retried success is indistinguishable from a first-attempt success; `security_span` has zero call sites inside `src/`; the only retry-adjacent signal reaching audit is `AUTHZ_PDP_ERROR` for a degraded decision (`emitters.py:102-103`) | **IMPROVE** |
| Tenant isolation during retries | `src/jdlib/context.py:122-140`; `tests/unit/security/test_adversarial.py:121-192` | Implemented (isolation); no retry-specific rule | tenant context lives in a `contextvars.ContextVar`, so a retry inside the same task keeps exactly one tenant and a new task or raw thread inherits nothing (both tested); no existing retry path carries tenant data — the token loop is service-identity, the DDL loop runs at provisioning time on a bound engine | **KEEP** |
| Security-context preservation during retries | — | **ABSENT** | no code or comment states what must survive a retry (tenant, authorization, correlation ids, audit attribution); searches in §1.2 return nothing | **ABSENT** |
| Cancellation | `src/jdlib/security/authz/cerbos.py:115-119` | Partial — one written rule, no test | the broad `except Exception` that makes a failure a denial must not swallow `CancelledError` (a `BaseException`), so cancellation propagates; the retry loops depend on the same language-level property implicitly; nothing asserts it | **IMPROVE** |
| Shutdown behaviour | `src/jdlib/tenancy/middleware.py:122-150`; `tests/unit/test_middleware.py:265-273`; `src/jdlib/persistence/session.py:306` | **ABSENT** | the library defines no shutdown, drain or close lifecycle: lifespan scope passes through the middleware untouched, sessions expose `close()`, and nothing states what happens to an in-flight retry or a pending audit write on shutdown | **ABSENT** |

Counts: **KEEP 7 · EXTEND 6 · IMPROVE 3 · REDESIGN 0 · ABSENT 7** (23 areas).

### 1.2 Searches that establish ABSENT

Run over `src/` and `tests/` at HEAD; the counts are total matches, so 0 means no occurrence:

| Search | Result |
|---|---|
| `circuit`, `breaker` | 1 in `src/`, the placement comment at `src/jdlib/security/config.py:17-20`; 0 in `tests/` |
| `half[_-]open` | 0 in `src/` and `tests/` |
| `dead[_-]?letter`, `dlq`, `requeue` | 0 in `src/` and `tests/` |
| `retry budget`, `budget` (retry sense) | 0; the single `budget` match is a test comment about a Docker probe (`tests/unit/test_infra_guard.py:73`) |
| `bulkhead`, `hedge`, `backpressure` | 0 in `src/` and `tests/` |
| `graceful`, `drain`, `shutdown`, `lifespan` in `src/` | 2: a comment about a consumer-side sink draining a queue (`src/jdlib/control/audit.py:123`) and session `close()`; no lifecycle handling |
| `idempoten*` in `src/` | 1: `src/jdlib/persistence/strategies/rls.py:87` (comment); the rest of the matches are integration tests of provisioning/grants |
| `is_retryable` in `src/` | definition (`security/errors.py:260`) and re-export (`security/__init__.py:48,93`) only — no caller |
| `retry` within 80 characters of any of `tenant`, `security context`, `correlation`, `actor`, `audit` in `src/` | 0 |
| `CancelledError` in `tests/` | 0 |

No recommendation to build any absent area is made in this document; the directive's decision about them belongs to the programme, not to this inventory.

## 2. The architectural decision as written

### 2.1 The rule, and who implements it

> "Outbound transport settings (TLS verification, certificate verification, retry and circuit-breaker policy) live with the HTTP adapters that use them (phases 2-4), not here, so the core configuration stays free of vendor concerns."
> — `src/jdlib/security/config.py:17-20`; restated in `docs/security/security-core.md:116-117`.

Places that implement it today:

| Implementation | Evidence | What it owns |
|---|---|---|
| Token acquisition policy | `src/jdlib/security/authn/provider.py:10-13` ("The provider owns everything security-relevant around it (claim building, caching, single-flight, retry policy, timeouts) and never performs I/O itself") | attempts, backoff, jitter, per-attempt timeout, failure caching rules |
| Transport classification | `src/jdlib/security/authn/transports.py:9-16,32,110-120` | which statuses/errors are transient vs permanent, and the timeout |
| PDP timeout policy | `src/jdlib/security/authz/cerbos.py:40-65,112-119`; `src/jdlib/security/authz/transports.py:15,41-49` | 2 s default timeout, positive-value validation, fail-closed mapping |
| Config validation idiom | `src/jdlib/security/authn/provider.py:100-117` (`SecurityConfigurationError` on non-positive timeout, `max_attempts < 1`, bad endpoint) | fail-fast, immutable, schema-locked config |
| The one non-HTTP policy | `src/jdlib/persistence/strategies/rls.py:79-106` | DDL lock timeout and retry, local to the operation that needs it |

### 2.2 What `ConnectionPolicy` should reuse

1. **`is_retryable` as the classification oracle** — `src/jdlib/security/errors.py:260`; new connector failures join the same descriptor table (`security/errors.py:108-220`), which is also what `docs/jdlib/successor/03-api-naming.md:88-89` requires ("`describe_error` is the single mapping the security surface tests assert over, and these entries join it rather than evade it").
2. **The adapter-local, constructor-validated policy idiom** — positive timeouts and `max_attempts >= 1` rejected at construction with `SecurityConfigurationError` (`security/authn/provider.py:100-117`), config frozen (`provider.py:83`), never a global knob.
3. **Two-layer timeout enforcement** — a per-call `asyncio.wait_for` around the whole attempt plus a transport-level timeout (`provider.py:256-258`; `cerbos.py:112-114`; `transports.py:65`).
4. **Full-jitter exponential backoff with injectable time** — `provider.py:280-284` with `sleeper`/`jitter` injected (`provider.py:144-158`); reuse the shape so the connector tests need no real sleeps.
5. **Fail-closed exhaustion** — after the last attempt, raise the typed unavailable error and never cache the failure (`provider.py:19-21,245-256`).
6. **Existing pool semantics** — `PoolCapacityError` and the never-evict-a-checked-out-engine rule are already the connector pool contract (`docs/jdlib/successor/03-api-naming.md:40`; `docs/jdlib/successor/02-target-architecture.md:148-150`).
7. **The error-taxonomy mapping** — connector failures should map to 503-vs-permanent exactly as `tenancy/middleware.py:31-53` and `security/errors.py:202-219` already do.

### 2.3 Names it must not introduce

- **`RetryManager` / `ResilienceManager` / `TimeoutManager` / `CircuitBreakerV2`** — a second reliability framework or an aggregate manager over subsystems is exactly what the programme's naming rule forbids: "no verb-noun managers that accrete responsibilities, and no aggregate 'manager' object that spans subsystems" (`docs/jdlib/successor/03-api-naming.md:15-16`).
- **New public symbols in pinned surfaces** — `jdlib.__all__` (13 symbols) and `jdlib.security.__all__` are pinned by exact-equality tests; new API arrives in new namespaces with their own surface tests (`docs/jdlib/successor/04-adoption-decisions.md:63-73`).
- **A new exception base or a parallel error taxonomy** — new failures join `jdlib.errors` / `jdlib.security.errors` (`docs/jdlib/successor/03-api-naming.md:75-89`).
- **Retry/budget knobs in core configuration** — `SecurityConfig` stays free of transport policy (`src/jdlib/security/config.py:17-20`); `ConnectionPolicy` is where they belong (`docs/jdlib/successor/02-target-architecture.md:79`).
- **A service locator, DI container or global mutable state** — constructor injection only (`docs/jdlib/successor/02-target-architecture.md:27-30`).

## 3. Security constraints on retry

### 3.1 What already governs a retry

- **Never retry authentication failures** — `src/jdlib/security/authn/provider.py:5` ("retry policy for network dependencies; never retry authentication failures") and `src/jdlib/security/authn/transports.py:13-16` ("4xx credential/policy failures are permanent … an invalid client must not be hammered"); asserted at `tests/unit/security/test_token_provider.py:207-216`.
- **Transient ≠ security failure** — the descriptor table marks only operational failures retryable and pins security failures non-retryable (`src/jdlib/security/errors.py:108-220`; `tests/unit/security/test_security_errors.py:119-126`).
- **A degraded decision is never an allow** — `src/jdlib/security/authz/decision.py:104-108`; and it is reported as 503-with-backoff for clients (`docs/security/error-responses.md:136-137`).
- **Failed acquisitions are not cached** — `src/jdlib/security/authn/provider.py:19-21`, tested at `tests/unit/security/test_token_provider.py:245-256`; a retry that reuses a failed result would be the alternative and is refused.
- **Replay and backdating are refused at the audit boundary** — `src/jdlib/models/audit_recorder.py:14-20` ("an event that predates the write by more than ordinary clock jitter is either backdated or a replay of an old event, and this path refuses to store the claim"), exercised at `tests/unit/security/test_adversarial_audit_integrity.py:128-159`.
- **Audit attribution is taken from the bound context, never guessed** — `src/jdlib/models/audit_recorder.py:23-35`; a background writer supplies explicit identifiers instead of ambient ones (`src/jdlib/control/audit.py:120-126`).
- **Tenant and security context are contextvar-bound and fail closed** — `src/jdlib/context.py:122-140`, `src/jdlib/security/context.py:204-229`; isolation across tasks/threads is tested (`tests/unit/security/test_adversarial.py:121-192`), which means a retry inside one task keeps the same tenant by construction.
- **Cross-tenant queries are refused before any engine is consulted** — `src/jdlib/security/authz/pep.py:88-93`.

### 3.2 What is NOT governed — ABSENT

Nothing in the source states what must survive a retry, what a retry must never duplicate, or where a retried operation re-binds context. Specifically absent, with the search that shows it:

- **No rule about duplicate writes or duplicate audit records under retry** (§1.2 `idempoten*` in `src/` = one comment; no idempotency key exists).
- **No rule that a retry must preserve or re-derive tenant / authorization context** (§1.2: `retry` near `tenant|security context|correlation|actor` = 0 matches).
- **No cancellation/replay rule for retried work beyond the audit timestamp window.**
- **No requirement that a retry be observably attributed** (retries emit no event or metric; §1.1 row 19).

This is a finding, not a gap this document fills: the directive's decision on those rules is not pre-empted here.

## 4. Tests

### 4.1 Tests that exercise reliability behaviour

| Test file | Asserts (with the behaviour it pins) |
|---|---|
| `tests/unit/security/test_token_provider.py:181-204` | two transient 503s are retried; exactly 2 sleeps; each delay within the exponential ceiling (full jitter) |
| `tests/unit/security/test_token_provider.py:207-216` | a permanent failure is not retried (1 attempt) |
| `tests/unit/security/test_token_provider.py:219-242` | exhaustion fails closed after 3 attempts; a hanging endpoint does not hang the caller |
| `tests/unit/security/test_token_provider.py:245-256` | a failed acquisition is not cached |
| `tests/integration/test_authn_http_integration.py:361-392` | over real HTTP: permanent 4xx never retried; outage fails closed and recovers; a 5xx is retried exactly 3 times then fails closed |
| `tests/unit/security/test_jwks_hardening.py:85-187` | thundering-herd single flight; refresh timeout does not hang the request; a timeout after success still serves cached keys |
| `tests/unit/security/test_cerbos_pdp.py:287-323` | any transport failure is denied and marked degraded; a hanging transport times out, denies and does not raise |
| `tests/unit/security/test_authz_pep.py:140-146`; `tests/unit/security/test_error_responses.py:261-267` | a degraded decision surfaces as 503 and is marked retryable |
| `tests/unit/security/test_security_errors.py:119-126` | retryability distinguishes transient capacity/conflict errors from security failures |
| `tests/unit/security/test_security_config.py:167-183` | authorization timeout must be positive; production caps it at the validated maximum |
| `tests/unit/security/test_jwt_validator.py:268-280` | `ready()` reflects whether key material is loaded |
| `tests/unit/security/test_adversarial_authn_outage.py:1-30` (+ cases) | an IdP outage is 503, never a 401 "bad credential" and never a fabricated anonymous principal |
| `tests/unit/test_jobs.py:98-174` | background envelope revalidation after principal deactivation, revoked membership, suspension; context cleared even on error |
| `tests/unit/security/test_adversarial.py:121-192` | tenant context is not inherited by unrelated tasks, siblings cannot observe each other's tenants, a raw thread inherits nothing |
| `tests/unit/security/test_adversarial_audit_integrity.py:86-159` | mis-attributed, absent-actor, backdated and future-dated events are refused; the clock-tolerance boundary is closed |
| `tests/unit/test_uow.py:87-124`; `tests/unit/test_session.py:84-123` | commit on clean exit, rollback on exception, write fence blocks admission; tenant-scoped statement enforcement |
| `tests/unit/test_middleware.py:260-273` | non-HTTP scopes (including `lifespan`) pass through untouched |

### 4.2 Areas with no test coverage at all

The brief's checklist enumerates 23 named areas (each has a row in §1.1; there is no 24th distinct item in the list as written). Of those, these have no test of any kind: **retry budgets; circuit breaking; half-open recovery; dead-letter handling; worker/background retry; observability of retries** (nothing asserts a retry is observable — no such emission exists); **security-context preservation during retries; cancellation** (`CancelledError` appears nowhere in `tests/`); **shutdown behaviour**. Two more are only partially covered: the RLS DDL retry has no unit test of its loop or of `_retryable_ddl_error` (it is exercised only through the integration helper `tests/integration/rls_support.py:67-87`, which imports the private constants), and idempotency is covered only at the integration layer for provisioning and grants.

## 5. Contradictions

1. **The placement rule is half-true, and its second half is unbacked.** `src/jdlib/security/config.py:17-20` and `docs/security/security-core.md:116-117` place "retry and circuit-breaker policy" with the HTTP adapters. Retry policy also lives in the persistence layer (`src/jdlib/persistence/strategies/rls.py:12-15,92-105`), which is not an HTTP adapter; and no circuit breaker exists anywhere in the tree (§1.2).
2. **`docs/security/security-core.md:137-138` says the accessors are "used by middleware, audit and metrics".** `security_code()` and `www_authenticate()` are (`src/jdlib/tenancy/middleware.py:36-53`; `src/jdlib/security/errors.py:265-270`), but `is_retryable()` has no caller in `src/` at all — the doc describes a capability of the contract, not a wiring that exists.
3. **Two adapters over the same JWKS cache disagree on outage semantics.** `docs/security/authentication-hardening.md:77-85` records that a key-source failure raises `AuthenticationUnavailable` (503) and "never `InvalidToken`" — true of the application authenticator (`src/jdlib/authn/oidc.py:325-332`), but the security-programme validator converts the same failure into `InvalidToken` (401): `src/jdlib/security/authn/jwt.py:123-126`; no test covers that path (`tests/unit/security/test_jwt_validator.py` has no outage case).
4. **The successor matrix reads as though timeouts and retries do not exist.** `docs/jdlib/successor/01-capability-matrix.md:98` records "Timeouts, retries, circuit breaking | source: ABSENT … | **ADOPT**", but the "Today" column describes the comparison source, not JDLib: JDLib implements timeouts and retries (§1.1 rows 1-5). For JDLib the correct dispositions are **EXTEND** (timeouts, retries, classification) and adoption only for circuit breaking. `docs/jdlib/successor/01-capability-matrix.md:142` similarly claims tracing "on security decisions" while `security_span` has no call site in `src/` (`src/jdlib/security/tracing.py:235`) — emission is consumer-side today.
5. **The validated authorization timeout is not the enforced one.** `SecurityConfig.authorization.timeout` is bounded (`src/jdlib/security/config.py:63,143-147`) and reported as evidence (`src/jdlib/security/compliance/evidence.py:164`), but nothing in `src/` constructs `CerbosPDP` from it: the adapter takes its own `CerbosConfig.timeout` (`src/jdlib/security/authz/cerbos.py:51`), which only checks positivity and has **no maximum** (`cerbos.py:63-64`). A deployment can therefore satisfy the production bound on one object while the enforced timeout lives on another.
