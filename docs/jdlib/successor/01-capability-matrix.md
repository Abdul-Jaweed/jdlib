# JDLib successor programme — capability matrix

Every capability discovered during Phase 0 reconnaissance carries **exactly one** status:
`KEEP` · `ADOPT` · `REDESIGN` · `IMPROVE` · `REJECT` · `DEFER`.

Legend for the *Today* column: **JDLib** = present in this repository, **source: REAL** = a working
implementation exists in the archived library, **source: PARTIAL/STUB/ABSENT** = the archived
implementation is limited, a shell, or documented only. Full evidence, file:line and code quotes:
`.recon/capability-inventory.md` (133 capabilities; 78 REAL, 31 PARTIAL, 3 STUB, 21 ABSENT).
JDLib's own baseline: `00-current-state.md`.

Two rows were corrected after `06-reliability-inventory.md` (the reliability precondition this
programme's directives require) found existing implementations this matrix had recorded as absent;
the corrections are marked in place rather than silently rewritten.

A status is a decision about **this library**, not a compliment to the source. `REJECT` means
adopting it would damage JDLib; `KEEP` means implementing it again would duplicate JDLib.

## 1. Identity, authentication, authorization

| Capability | Today | Status | Why |
|---|---|---|---|
| OIDC/JWT authentication with JWKS | JDLib: `jdlib.authn` + `jdlib.security.authn` | **KEEP** | implemented with `JwksCache`, `SigningKeySource`, kid rotation; source's `TokenClient` defaults to `verify_signature=False` and passes the algorithm string as the key |
| JWKS caching and key rotation | JDLib | **KEEP** | the source has no correct equivalent; its verified-token helper has no call site |
| Principal extraction (user, service account, API key) | JDLib: `Principal`, `PrincipalDirectory` | **KEEP** | source's principal handling is ad-hoc per service |
| API-key authentication with scopes | JDLib: `ApiKeyAuthenticator`, scope narrowing | **KEEP** | scopes already narrow but never expand authority |
| AutHorization: one PDP/evaluator | JDLib: `PolicyDecisionPoint`, `DefaultPDP`, guards | **KEEP** | source relies on an external Cerbos service without a JDLib-side evaluator contract |
| Cerbos as a PDP adapter | JDLib: `CerbosPDP` | **KEEP** | already implemented and live-verified in the hardening programme |
| Permission catalog, role inheritance, resource grants, additive authorization | JDLib: `authz.permissions`, `reader`, `ownership` | **KEEP** | source has role-ish grants without the anti-escalation algebra JDLib enforces |
| Anti-escalation rules (subset, namespace, scope compatibility) | JDLib: `AccessControl` | **KEEP** | source's ABAC has no equivalent; JDLib's is executable-tested |
| Privileged/platform-operator access with capability sets, TTL, justification, audit | JDLib: `PrivilegeContext`, `platform_operator`, `OperatorAuthorizer` | **KEEP** | source's equivalent is a per-service admin credential with no time-box or audit descriptor |
| Delegated tenant access (principal acts *for* a tenant) | JDLib: absent; operator path exists | **ADOPT** | a real product capability JDLib lacks; must extend `PrivilegeContext` (`kind='delegation'`), never add a second privilege model |
| Service identities (non-human principals) | JDLib: `ServiceAccount`, `ApiKey` | **KEEP** | source's service credentials are per-service config blobs |
| Fail-closed verification defaults | JDLib | **KEEP** | source: `verify_signature=False` default, decrypt failure returns ciphertext, unknown lifecycle stage defaults to `operate` |
| Source's ambient/per-service auth helpers | source: REAL but divergent | **REJECT** | adopting them would create a second authentication path beside `Authenticator` |

## 2. Multi-tenancy

| Capability | Today | Status | Why |
|---|---|---|---|
| Tenant identification and immutable tenant context | JDLib: `TenantContext`, `ContextFactory`, resolver chain | **KEEP** | source threads `org_id` through arguments and cache keys, inconsistently |
| Tenant lifecycle (provision, suspend, migrate, deprovision) | JDLib: `TenantRegistry`, lifecycle services | **KEEP** | source has no lifecycle state machine |
| Isolation strategies (shared / schema / database) + RLS | JDLib: `persistence.strategies`, `install_rls`/`verify_rls` | **KEEP** | source is single-target per client; no isolation model |
| Hybrid placement as configuration | JDLib: `TenantPlacement` | **KEEP** | — |
| Control-plane / tenant-plane separation | JDLib: `control` vs models | **KEEP** | source mixes control metadata into tenant documents |
| Tenant configuration storage | JDLib: `TenantSetting` | **KEEP** | source's attribute documents are a god object (below) |
| Tenant-specific credentials and connections | JDLib: `target_handle` + `SecretProvider.resolve` | **IMPROVE** | the seam exists and is specified; it needs credential *versions*, rotation hooks and a provider set (Phase 3) |
| Resource hydration (tenant → resource → connector → session) | JDLib: absent | **ADOPT** | Phase 1; `05-tenant-lifecycle.md` §7 already specifies the contract it must implement |
| Tenant resource cache with deterministic identity | JDLib: absent | **ADOPT** | Phase 1/2; must be keyed by resolved handle + credential version, never by tenant alone |
| Tenant relocation | JDLib: documented manual procedure | **KEEP** | source: absent |
| Tenant-scoped cache keys | JDLib: absent | **ADOPT** | Phase 2; source's key is `xxh128(f"{instance}{role}{schema}{db}{warehouse}{sql}")` — no delimiters, and BigQuery omits `org_id` entirely, so two tenants share cache entries |
| Source's `_Customer_Internal` aggregate (1,238 LOC, 13 service types, duplicated dispatch chains) | source: REAL | **REJECT** | the anti-pattern this programme exists to avoid; its own tests reach around it with unbound-method calls |

## 3. Caching

| Capability | Today | Status | Why |
|---|---|---|---|
| Local in-memory cache | JDLib: absent | **ADOPT** | Phase 2 `LocalCache` |
| Redis cache | JDLib: absent | **ADOPT** | Phase 2 `RedisCache`; source uses an unauthenticated, non-TLS Redis with `FLUSHALL` |
| Versioned, unambiguous cache-key construction | JDLib: absent | **ADOPT** | Phase 2 `ScopedKeyFactory`; keys must make omitting tenant scope impossible, not merely discouraged |
| TTL policy | source: REAL (TTL-only) | **IMPROVE** | adopt TTL as one policy among several, with explicit max-age per namespace |
| Cache invalidation | source: PARTIAL (per-key delete + global flush) | **REDESIGN** | invalidation must be policy-driven per namespace, tenant-scoped, and never require a global flush |
| Cache serialization safety | source: PARTIAL (writes `repr()`, which cannot be read back — verified `json.loads("[{'NAME': 'x'}]")` raises) | **REDESIGN** | serialization must round-trip and be version-tagged; a cache write that can never be read is a defect, not a style preference |
| Credential/secret caching in a shared cache | source: REAL and dangerous (fully decrypted tenant document, incl. private keys, `json.dumps` to Redis for 12h, no namespace) | **REJECT** | the single worst finding in the inventory; credentials are resolved per use from a provider, and any caching happens in-process with versioned keys |
| Request-scoped authorization cache | JDLib: `AuthzCache`, invalidation frozen | **KEEP** | already conservative; source has none |
| Cache metrics (hit rate) | source: ABSENT (documented only) | **DEFER** | worth having, but only once a cache exists to measure |
| Cache warming | source: ABSENT (documented only) | **DEFER** | no demonstrated need in JDLib's consumers yet |

## 4. Secrets and credentials

| Capability | Today | Status | Why |
|---|---|---|---|
| `SecretProvider` interface (handle → connection config) | JDLib: `persistence/secrets.py`, `EnvSecretProvider`, `MemorySecretProvider` | **IMPROVE** | Phase 3 extends it with versions, rotation signals and provider composition; the interface and its fail-closed rule (`StrategyCapabilityError`, never a silent fallback) already exist |
| Environment-backed secrets | JDLib: `EnvSecretProvider` | **KEEP** | — |
| External secret manager (Vault/cloud KMS-style) | source: ABSENT (GCP implementation commented out) | **ADOPT** | Phase 3 provider abstraction; **no vendor is wired without a running service to verify against** |
| Encrypted configuration | source: PARTIAL | **ADOPT** | Phase 4 builds on the crypto provider, not on a config-embedded key |
| Credential hydration with explicit lifecycle | JDLib: partially via `SecretProvider` | **IMPROVE** | Phase 1/3; resolution must be lazy, cached safely and audited |
| Credential rotation | source: ABSENT (documented only) | **ADOPT** | Phase 3/4; the design doc already requires pools to rebuild on credential-version change |
| Revocation behaviour | source: ABSENT | **ADOPT** | Phase 3; a revoked credential must fail closed and be observable |
| Secret redaction in logs/exceptions/audit | JDLib: audit and telemetry redaction | **IMPROVE** | extend the existing sanitiser to connector and credential paths (one sanitiser, never a second) |
| Env-gated secret dumps (`…_DEBUG_AUTH=full` printing passwords) | source: REAL | **REJECT** | never; secrets are never printable on any flag |
| INFO-level logging of SQL with bind values | source: REAL | **REJECT** | the hardening programme's telemetry rules already forbid payload text |

## 5. Cryptography

| Capability | Today | Status | Why |
|---|---|---|---|
| `CryptographicProvider` abstraction (encrypt/decrypt/version metadata) | JDLib: absent | **ADOPT** | Phase 4 |
| Key/version metadata on encrypted values | source: PARTIAL (no algorithm choice, no key metadata) | **ADOPT** | Phase 4; metadata is what makes rotation possible at all |
| Key rotation with zero-downtime migration | source: ABSENT (docs claim it) | **ADOPT** | Phase 4; shadow-write then prefer-new, per the directive's model |
| Fail-closed crypto migration (never silently downgrade) | source: PARTIAL (fail-open is the house style) | **ADOPT** | Phase 4; new-key failure must fail closed, and the security model must say so explicitly |
| Wrong-key / corrupted-ciphertext behaviour | source: PARTIAL (returns ciphertext as plaintext) | **REDESIGN** | a decryption failure is an error, never a value |
| Provider abstraction (HSM/KMS/software) | source: ABSENT (docs claim HSM) | **DEFER** | the seam is Phase 4; a vendor backend waits for a service to verify against |
| Tenant-specific keys | source: ABSENT | **DEFER** | meaningful only once the tenant credential store exists |

## 6. Data access and connectors

| Capability | Today | Status | Why |
|---|---|---|---|
| PostgreSQL via ORM, tenant-scoped, RLS-backed | JDLib: `TenantSession`, `TenantRepository`, strategies | **KEEP** | the enforcement point; never bypassed by any new subsystem |
| Connection lifecycle, pooling, caps, eviction safety | JDLib: strategies + `PoolCapacityError` | **KEEP** | source never tunes, pre-pings or bounds pools |
| Timeouts, retries, circuit breaking | JDLib: **already implemented adapter-locally** — per-call `asyncio.wait_for` plus a transport timeout, bounded retry with full-jitter backoff and injected clock/sleeper (`security/authn/provider.py:96-158,254`), transient-vs-permanent classification, fail-closed exhaustion; source: ABSENT | **IMPROVE** | Phase 6's `ConnectionPolicy` **extends this idiom** rather than building a framework: the frozen-config validation, the two-layer timeout, the jittered backoff and `is_retryable()` as the classification oracle. Corrected from ADOPT after the reliability inventory (`06-reliability-inventory.md`) found the implementation this row had assumed absent |
| Connector abstraction (`DataConnector` protocol, registry, factory) | JDLib: absent | **ADOPT** | Phase 6 |
| Connector capability declarations | JDLib: `StrategyCapabilities` pattern exists for isolation | **ADOPT** | Phase 6 `ConnectorCapabilities`, mirroring the existing capability-table idiom |
| Snowflake | source: REAL (the only genuinely implemented relational engine) | **DEFER** | Phase 7 candidate; no JDLib consumer or test target exists in this environment |
| StarRocks | source: PARTIAL (`SET CATALOG`/`USE` only) | **DEFER** | same reason; the lakehouse layer above it is a false claim |
| BigQuery | source: PARTIAL | **DEFER** | same reason; its cache asked for cross-tenant collision |
| MongoDB | source: REAL | **DEFER** | same reason |
| ClickHouse / others | source: ABSENT | **REJECT** | nothing to adopt |
| Serverless invocation (AWS Lambda only in practice) | source: PARTIAL | **DEFER** | not a data capability; revisit if a product requirement appears |
| If-Match / optimistic concurrency across engines | source: REAL | **DEFER** | the concept is sound; JDLib's tenant plane does not need it yet |
| Health checks per connector | source: PARTIAL (per-service ad hoc) | **ADOPT** | Phase 6/7, uniform contract |

## 7. Query system

| Capability | Today | Status | Why |
|---|---|---|---|
| Declarative query specification (Pydantic-validated) | source: REAL (`MLQuery` model) | **ADOPT** | Phase 8, scoped by ADR-1: it exists for engines with no ORM, not as a general DSL |
| Query AST | source: PARTIAL | **ADOPT** | Phase 8 |
| Parameterized value binding | source: REAL (`bindparam`) | **ADOPT** | adopt the property, not the implementation |
| Validated identifiers as a first-class type | source: PARTIAL — the repo owns an allowlist (`sql_safety.py`) but `ORDER BY`/`GROUP BY`/JSON paths interpolate request-supplied names via raw `text()` | **IMPROVE** | make validated identifiers the *only* way to express an identifier, at parse time; JDLib already has `RawSqlValidator` (pglast) for the SQL path |
| Filters, ordering, pagination limits | JDLib: repository-level | **ADOPT** | Phase 8; pagination must be bounded (source's is not) |
| Joins | source: REAL, including a dedicated analysis doc | **DEFER** | Phase 8 scope decision: joins only if a reviewed consumer needs them; they widen the tenant-constraint surface |
| Window functions, aggregates | source: PARTIAL | **DEFER** | same scope rule |
| Nested/JSON paths | source: PARTIAL (hand-rolled quote doubling) | **REDESIGN** | must be expressed through validated identifiers, never string quoting |
| Dialect handling | source: PARTIAL | **ADOPT** | Phase 8; small, explicit dialect registry |
| Dangerous-construct rejection, query complexity limits | source: ABSENT | **ADOPT** | Phase 8; extends the existing `RawSqlValidator` posture |
| Tenant constraints applied during compilation | source: ABSENT (tenant is a filter at best) | **ADOPT** | Phase 8; the tenant is a compile-time parameter, never a caller option |
| Generic query DSL over the ORM/tenant plane | JDLib: deliberately rejected by `07-implementation-design.md` §2 | **REJECT** | ADR-1 below: `TenantRepository` + RLS + metadata lint stay the authority for PostgreSQL |

## 8. Framework integrations

| Capability | Today | Status | Why |
|---|---|---|---|
| FastAPI integration (authN, context, guards, exception mapping, correlation, audit attribution) | JDLib: `integrations/fastapi.py`, `tenancy/middleware.py` | **KEEP** | the hardening programme already fixed its defect classes |
| CLI integration | JDLib: `integrations/cli.py` + console script | **KEEP** | explicit administrative context; no implicit tenant |
| Background jobs / workers | JDLib: `tenancy/jobs.py` | **IMPROVE** | Phase 10: explicit signed context envelopes with revalidation (verify → TTL/signature → reload principal → reload tenant status → re-authorize → fresh context) |
| Context envelope forgery/replay resistance | JDLib: absent | **ADOPT** | Phase 10; an envelope is a claim to be revalidated, never a trusted serialized context |
| gRPC | JDLib: absent | **DEFER** | flagged for the product owner: no gRPC consumer exists, and §19's requirement is conditional on integrations being built. Building it with no consumer means an unexercised surface |
| AI/agent integrations | source: PARTIAL (`langgraph` attributes, LangChain reach-through) | **DEFER** | no product requirement; the archived implementation is attribute-passing, not an integration |

## 9. Observability

| Capability | Today | Status | Why |
|---|---|---|---|
| OpenTelemetry tracing at meaningful boundaries | JDLib: `security/tracing.py` defines the span helper (`security_span` at `:235`) and the safety rules, but **the helper has no call site in `src/`** | **IMPROVE** | wire the existing helper at the boundaries Phase 11 lists rather than defining another span API; the archived system's rejected pattern is the opposite error — a decorator on every method, self-reported 15–30% overhead |
| Structured logging with correlation/request IDs | JDLib | **KEEP** | — |
| Metrics | JDLib: `security/metrics.py` + Prometheus/collector verification | **KEEP** | source: no metrics |
| No secret or payload leakage into telemetry | JDLib: telemetry-safety rules | **KEEP** | source exports `db.statement`/`db.parameters` with bind values |
| Boundary instrumentation policy (no span per helper) | JDLib | **KEEP** | Phase 10 extends the *existing* boundary list (hydration, connector acquisition, query compilation are new boundaries) |
| Trace-context propagation across gateway → app → PDP → engine | JDLib: measured gaps (gateway→app, PDP→engine) | **IMPROVE** | Phase 10; the gaps are already quantified, with the stopping points cited |
| Blanket per-method span decorators | source: REAL | **REJECT** | a tax paid by every call for data nobody reads |

## 10. Object storage

| Capability | Today | Status | Why |
|---|---|---|---|
| Object storage provider abstraction (put/get/delete/list/stream) | source: REAL (ABC + S3 backend) | **ADOPT** | Phase 9; the ABC is one of the inventory's genuinely reusable assets |
| S3 backend | source: REAL | **ADOPT** | Phase 9, independently implemented against the abstraction |
| GCS backend | source: STUB (`NotImplementedError` from every method, yet exported publicly) | **DEFER** | never expose an API claiming a provider whose implementation is a shell; adopted only with a service to verify against |
| Azure Blob backend | source: STUB (`NotImplementedError`, exported) | **DEFER** | same |
| Versioning/lifecycle/encryption claims in object storage | source: ABSENT (documented, not implemented) | **REJECT** | do not document provider features that are not implemented |
| Tenant-scoped object keys and access | source: ABSENT | **ADOPT** | Phase 9; keys and credentials resolve through the Phase 1 hydration path |

## 11. Configuration

| Capability | Today | Status | Why |
|---|---|---|---|
| Typed, validated configuration | JDLib: `TenancyConfig` + sub-models, `jdlib.security` config | **KEEP** | source's attribute documents are untyped dicts hydrated from a credential document |
| Environment loading with precedence | JDLib | **KEEP** | — |
| Config-embedded secrets | source: REAL | **REJECT** | secrets come from providers; config carries references |
| Package configuration: declared dependencies matched to imports | JDLib: one defect (`starlette`, §6 of the baseline) | **IMPROVE** | fix in roadmap §1 and gate it: a test that fails when a source import is neither declared nor stdlib |
| Two competing dependency lists | source: REAL (`requirements-pypi.txt` + `requirements-hackershut.txt`) | **REJECT** | one source of truth (pyproject) |
| Committed internal package-repository config and build-time tokens | source: REAL | **REJECT** | never; see the hardening programme's secret rules |

## 12. Testing and engineering practice

| Capability | Today | Status | Why |
|---|---|---|---|
| Unit / integration / security test layers | JDLib: 869 unit + 331 integration collected | **KEEP** | source's tests call unbound internal methods to avoid constructing the god object |
| Strategy-matrix behavioural suite | JDLib: `testing/fixtures.py` strategy matrix | **KEEP** | — |
| Adversarial/security tests as a first-class layer | JDLib: `docs/security/`, security suites | **KEEP** | source has no adversarial layer |
| Contract tests for every connector/provider | JDLib: partially (protocol doubles) | **ADOPT** | §24 requires one contract suite per connector and provider family |
| Consumer-shaped end-to-end verification | JDLib: the private reference application + lab | **KEEP** | this is how the hardening programme found its defect classes |
| Coverage measurement | JDLib: absent | **ADOPT** | roadmap §1: measure it before claiming anything about it |
| Infrastructure-dependency honesty (skip cleanly, never silently) | JDLib: partially — `tests/integration` raises without Docker instead of skipping | **IMPROVE** | roadmap §1; a missing service must appear as a skip with a reason, not an error, and never as a pass |
| Typed public surface (mypy strict, ruff) | JDLib: clean at HEAD | **KEEP** | — |

## 13. Anti-patterns explicitly not adopted

Each is a `REJECT` decided by evidence in the inventory, listed once here so no later phase
re-litigates it: the 1,238-LOC god object and its duplicated dispatch chains; decrypted
credential documents in a shared cache; fail-open security defaults; identifier interpolation
from request data; duplicated per-service cache/ORM/cache-key logic; unseparated cache keys and
tenant-omitted keys; no timeouts/retries and blocking sync IO in an async library; blanket span
decoration; env-gated secret dumps and INFO credential logging; undeclared, duplicated or unused
dependencies; committed registry config and CI tokens; docstrings and README claims describing
unimplemented features.

## 14. Summary

Counted from this file's own rows (script-verified, not estimated):

| Status | Rows |
|---|---|
| **KEEP** | 36 |
| **ADOPT** | 32 |
| **IMPROVE** | 13 |
| **REDESIGN** | 5 |
| **DEFER** | 17 |
| **REJECT** | 13 |
| **Total classified rows** | **116** |

The matrix classifies by capability **family**: where the inventory recorded several
implementations of one capability (the per-engine cache logic, the per-service connection
handling), the row's decision applies to every member, and the inventory remains the
per-capability record with its own implementation states and file:line evidence. §13 restates
the rejections by theme; a capability and its anti-pattern are one decision, so the same
rejection may appear both as a row above and in that list.
