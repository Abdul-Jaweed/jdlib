# JDLib Security Core (Phase 1)

Status: **IMPLEMENTED** · Scope: `jdlib.security` · Baseline: 568 tests → 640 tests

This document describes the security foundation added by Phase 1 of the
hardening program: a request-scoped `SecurityContext`, strongly typed security
configuration, a stable machine-readable error model, and the ports
(protocols) that authentication, gateway and rate-limiting adapters implement.

Source: `src/jdlib/security/{__init__,context,config,errors,interfaces}.py`
Tests: `tests/unit/security/` (72 tests)

---

## 1. SecurityContext

`SecurityContext` is the request-scoped authentication record. It answers
"who is this request, how were they authenticated, and under which tenant".

```python
SecurityContext(
    principal=Principal(kind=PrincipalKind.USER, id=...),
    request_ids=RequestIds(request_id="...", correlation_id="...", trace_id=None),
    auth_method=AuthMethod.JWT,
    tenant=TenantContext(...) | None,
    token_metadata=TokenMetadata(...) | None,
)
```

### Ownership (no duplicated state)

| Concern | Owner |
|---|---|
| tenant_id, slug, strategy, privilege | `TenantContext` (unchanged) |
| principal identity | `TenantContext.principal`; `SecurityContext.principal` is the same object |
| request / correlation / trace identifiers | `SecurityContext.request_ids`, derived from `TenantContext` by `from_tenant_context()` |

A security context that has resolved a tenant keeps a **reference** to it, and
its derived accessors (`request_id`, `correlation_id`, `trace_id`, `tenant_id`,
`privilege`) read through to it, so the two records cannot diverge. An invariant
test asserts `context.principal is tenant.principal` and
`context.request_id == tenant.request_id`.

### Fail-closed construction rules

* Direct construction with an anonymous principal or `AuthMethod.NONE` raises
  `AuthenticationError` (401, code `AUTHENTICATION_REQUIRED`).
* The **only** way to obtain an unauthenticated context is
  `SecurityContext.anonymous()`, which is deliberately explicit and reports
  `authenticated is False`.
* `principal` and `request_ids` are required constructor arguments — a context
  cannot exist without an identity; there is no silent default.
* `require_tenant()` raises `MissingTenantContext` rather than returning `None`
  on the paths that need a tenant. The `tenant` field itself is typed
  `TenantContext | None` so type checkers force callers to handle both cases.
* `current_security_context()` raises `AuthenticationError` when no context is
  bound (never a silent anonymous fallback);
  `current_security_context_or_none()` is the explicit "may be absent" accessor.

### Async safety

Binding uses `contextvars` (`security_context_scope`), so a context is visible
only inside the task/context that bound it. A test runs two concurrent tasks
with different contexts and asserts each observes its own — no leakage across
`asyncio.gather`.

### Credential hygiene

`TokenMetadata` has fields for iss/aud/sub/typ/jti/exp/scopes/client_id and
**no field for a raw token**, and `TokenMetadata(access_token=...)` raises
`TypeError`. Anything downstream (logs, spans, audit, exception messages)
cannot leak a credential it never received.

---

## 2. Security configuration

`SecurityConfig` is frozen and validated on construction; unsafe combinations
fail at startup rather than at runtime.

| Section | Secure defaults |
|---|---|
| `authentication` | `enabled=True`, `require_authentication=True` |
| `authorization` | `enabled=True`, `require_authorization=True`, `fail_closed=True`, `allow_all=False`, `timeout=2s` |
| `tenancy` | `require_tenant_context=True`, `trust_tenant_header=False`, `allow_privileged_bypass=False` |
| `gateway` | `trust_identity_headers=False`, `require_identity_envelope=True` |
| `audit` | `enabled=True` |
| `observability` | `debug_security_errors=False`, `trace_propagation=True` |

### Production posture (fails closed)

With `compliance.environment = production`, these raise
`SecurityConfigurationError` at construction:

disabled or optional authentication · disabled or optional authorization ·
allow-all authorization · non-fail-closed authorization · trusted tenant
headers · privileged bypass · trusted gateway identity headers · disabled
audit · debug security errors · authorization timeout above 10s.

`validate_security_config()` re-checks a configuration that may have been built
with `model_construct` (bypassing validation) or loaded from an external source.

### Rules that hold in *every* environment

* trusting gateway identity headers **without** a required signed identity
  envelope is rejected — forgeable identity is never acceptable,
* authorization timeout must be positive (no unbounded PDP call),
* signing keys must be at least 32 bytes (`assert_strong_signing_key`), and the
  error reports only lengths, never key material.

### Deliberate absences

There is no option to enable secret logging, token logging or authorization
header dumps; a test pins the field set of every configuration section so
adding such a knob requires an explicit, reviewed change. TLS/certificate
verification, retry policy and circuit breakers belong to the HTTP adapters
that use them (phases 2–4) and are not core configuration.

---

## 3. Stable security error model

Every exported `jdlib.errors` class carries a `SecurityDescriptor`:

```python
SecurityDescriptor(
    code=SecurityCode.INVALID_TOKEN,
    http_status=401,
    retryable=False,
    classification=SecurityClassification.AUTHENTICATION,
)
```

* `describe_error()` accepts a class or an instance and walks the MRO, so a
  consumer subclass inherits the nearest declared descriptor; unknown failures
  fall back to `INTERNAL_ERROR`.
* `security_code()`, `is_retryable()` and `www_authenticate()` are the accessors
  used by middleware, audit and metrics.
* `www_authenticate()` returns an RFC 6750 challenge for 401 codes
  (`Bearer realm="jdlib", error="invalid_token"`, plus
  `error_description` for expired tokens) and `None` for everything else.
* Retryability distinguishes transient operational failures
  (`PoolCapacityError`, `TenantOperationInProgress`, `RelocationPhaseError`)
  from security failures, which are never retryable.

**Drift control:** a test asserts, for every exported error class, that
`descriptor.http_status == http_status_for(instance)`. The declarative model
therefore cannot silently disagree with what the runtime actually returns.
Codes cover the full spec #21 set, including codes that later phases will
attach (`INVALID_AUDIENCE`, `INVALID_ISSUER`, `INSUFFICIENT_SCOPE`,
`POLICY_DENIED`, `POLICY_UNAVAILABLE`).

---

## 4. Ports (interfaces)

| Port | Purpose | Fail-closed property |
|---|---|---|
| `TokenValidator` | inbound token validation (`validate`, `ready`) | raises on any failure; returns metadata only |
| `TokenProvider` | outbound service credentials (`token`, `invalidate`) | returns `OutboundToken` with `SecretStr` value |
| `GatewayAdapter` | verified gateway identity (`verify_identity`, `name`) | returns `None` for unsigned/absent assertions |
| `RateLimiter` | adapter-delegated rate limiting (`check`) | `RateLimitDecision()` defaults to **denied** |

All four are `runtime_checkable` protocols: structural conformance is verified
by a test, and no adapter implementation is required by the core.

Inbound (`TokenValidator`) and outbound (`TokenProvider`) authentication are
separate types — they are never interchanged (spec #7).

---

## 5. Import safety

`import jdlib.security` pulls in no optional dependency (no fastapi, typer,
httpx, cerbos or opentelemetry). The regression test runs the import in a
subprocess and inspects `sys.modules`; it was verified to fail when a
violating import is introduced, so the guard has teeth.

---

## 6. Self-evaluation (spec #88)

1. **What changed?** New `jdlib.security` package (5 modules), one additive enum
   member (`PrincipalKind.ANONYMOUS`), and 72 tests. No existing module changed
   behaviour; `jdlib.__all__` is unchanged.
2. **What security boundary changed?** No boundary was weakened. New: request
   identity is now an explicit, validated, immutable record; unauthenticated
   state is explicit and loud; configuration cannot express an insecure
   production posture.
3. **What assumptions were introduced?** Request identifiers are ≤128 chars and
   free of control characters; `from_tenant_context` is the bridge between
   tenancy and security records; adapters are supplied by the application.
4. **What could bypass the new control?** `SecurityContext.anonymous()` used on
   a path that should require authentication — mitigated by the fail-closed
   accessors (`require_tenant`, `current_security_context`) and by middleware
   wiring in phase 5; `model_construct` bypassing configuration validation —
   mitigated by `validate_security_config()` and its test.
5. **What tests prove the control?** 72 tests in `tests/unit/security/`,
   including negative tests (silent anonymous construction, missing identity,
   weak signing keys, unsafe production configuration, credential fields on
   metadata) and a mutation-checked import-safety guard.
6. **What regression risk exists?** Low: additive package, no touched behaviour.
   The only shared file changed is `jdlib/context.py`, where an enum member was
   added (existing members and their values are untouched).
7. **What documentation is stale?** Nothing now. This item originally recorded
   that `knowledge_base/` (built before this phase) did not yet describe
   `jdlib.security`; the Phase 11 sweep has since refreshed it —
   `knowledge_base/README.md` names the security layer and points at
   `docs/security/` for the phase documents.
8. **What remains incomplete?** Only the `SecurityContext` binding: the library
   provides the scope (`security_context_scope`) and the factory, and the
   consumer binds it in its own middleware — the reference application does, and
   `data/policy.py` binds it on the data path. Everything else this item listed
   has since landed: the response envelope and `WWW-Authenticate` emission
   (`install_error_envelope`, G10), token validation and JWKS hardening
   (`authn/wiring.py`), PDP/Cerbos (`CerbosPDP`, and the PEP in
   `integrations/fastapi.py`), the gateway adapters (shipped; the consumer wires
   them), and audit/observability (Phases 6–7).
