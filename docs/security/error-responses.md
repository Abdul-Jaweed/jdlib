# Security Error Responses (Phase 5)

Status: **COMPLETE** (directive §20)

Source: `src/jdlib/security/errors.py`, `src/jdlib/security/responses.py` (new),
`src/jdlib/security/authz/pep.py`
Tests: `tests/unit/security/test_error_responses.py` (new),
`tests/unit/security/test_security_errors.py`, `test_authz_pep.py`

| Evidence | Result |
|---|---|
| Unit (error model + responses + PEP) | 272 passed in `tests/unit/security` |
| Whole suite (`-W error`) | 876 passed, 6 skipped |
| `ruff check .` / `mypy src/jdlib` | clean (86 source files) |

---

## 1. Stable codes and the HTTP mapping

Every failure the security layer can raise carries a stable code, an HTTP
status, a retryability flag and a classification. The table below is generated
from the descriptor table itself, so it cannot drift from what the runtime
produces; `test_security_errors.py` separately asserts that every descriptor
agrees with the runtime `http_status_for()` mapping.

| Error | Code | Status | Retryable | Classification |
|---|---|---|---|---|
| `AuthenticationError` | `AUTHENTICATION_REQUIRED` | 401 | no | authentication |
| `ExpiredToken` | `EXPIRED_TOKEN` | 401 | no | authentication |
| `InvalidToken` | `INVALID_TOKEN` | 401 | no | authentication |
| `UnknownPrincipal` | `UNKNOWN_PRINCIPAL` | 401 | no | authentication |
| `AuthorizationError` | `PERMISSION_DENIED` | 403 | no | authorization |
| `PermissionDenied` | `PERMISSION_DENIED` | 403 | no | authorization |
| `RoleEscalationBlocked` | `ROLE_ESCALATION_BLOCKED` | 403 | no | authorization |
| `TenantAccessDenied` | `TENANT_ACCESS_DENIED` | 404 | no | tenancy |
| `TenantNotFound` | `TENANT_NOT_FOUND` | 404 | no | tenancy |
| `CrossTenantReferenceError` | `CROSS_TENANT_ACCESS` | 409 | no | data boundary |
| `InvalidReference` | `INVALID_REFERENCE` | 409 | no | data boundary |
| `TenantNotWritable` | `TENANT_NOT_SERVABLE` | 423 | no | tenancy |
| `TenantSuspended` | `TENANT_SUSPENDED` | 423 | no | tenancy |
| `InvalidResourcePermission` | `SECURITY_CONFIGURATION_ERROR` | 500 | no | configuration |
| `MigrationError` | `MIGRATION_ERROR` | 500 | no | internal |
| `MissingTenantContext` | `MISSING_TENANT_CONTEXT` | 500 | no | tenancy |
| `PoolCapacityError` | `CAPACITY_EXCEEDED` | 500 | yes | availability |
| `ProvisioningError` | `PROVISIONING_ERROR` | 500 | no | internal |
| `RelocationPhaseError` | `RELOCATION_IN_PROGRESS` | 500 | yes | tenancy |
| `RoleScopeMismatch` | `SECURITY_CONFIGURATION_ERROR` | 500 | no | configuration |
| `SchemaLintError` | `SCHEMA_LINT_FAILED` | 500 | no | configuration |
| `SecurityConfigurationError` | `SECURITY_CONFIGURATION_ERROR` | 500 | no | configuration |
| `StrategyCapabilityError` | `INTERNAL_ERROR` | 500 | no | internal |
| `TenantOperationInProgress` | `TENANT_OPERATION_IN_PROGRESS` | 500 | yes | tenancy |
| `UnknownPermission` | `SECURITY_CONFIGURATION_ERROR` | 500 | no | configuration |
| `UnknownResourceType` | `SECURITY_CONFIGURATION_ERROR` | 500 | no | configuration |
| `UnscopedBulkOperation` | `UNSCOPED_DATA_OPERATION` | 500 | no | data boundary |
| `UnscopedRawSql` | `UNSCOPED_DATA_OPERATION` | 500 | no | data boundary |
| `AuthorizationUnavailable` | `POLICY_UNAVAILABLE` | 503 | yes | authorization |

All seven statuses the directive lists (401, 403, 404, 409, 423, 500, 503) are
exercised by the test suite, and a matrix test walks the whole descriptor table
asserting that each entry yields a status from that set and a complete envelope.

## 2. The safe response envelope

`error_response(exc, request_ids=...)` returns

```json
{"code": "PERMISSION_DENIED", "message": "...",
 "request_id": "req-1", "correlation_id": "corr-1"}
```

with exactly those four keys — plus a `WWW-Authenticate` header for 401s and
nothing else. `correlation_id` falls back to the request id when no correlation
id was supplied, so a client always has something to quote in a support request.

| Rule | Why it matters | Test |
|---|---|---|
| 4xx messages are the error's own text, **redacted** and made printable and capped at 300 chars | control characters cannot be used to forge log lines or UI output; unbounded text cannot be used to bloat responses; and an error that quotes a header, a connection string or a query while explaining itself cannot become a credential-disclosure channel | `test_client_messages_are_sanitized_and_capped`, `test_no_response_leaks_a_sensitive_value` |
| 5xx messages are a fixed, classification-derived description | an internal message can legitimately contain key material, an internal host or a query fragment; it belongs in the logs, not in a response body | `test_server_side_failures_never_echo_their_own_message` |
| unclassified exceptions become a generic 500 | exception type names, module paths and stack shapes are implementation detail | `test_unclassified_exceptions_become_a_generic_500` |
| no `Traceback`, `File "`, `/src/`, `jdlib.`, `site-packages` and no known secret value in any response | the whole point of the phase | `test_responses_never_leak_internals` |

### Leak corpus (directive §3)

A 50-case matrix — ten categories × five failure shapes (4xx authentication,
4xx authorization, 4xx tenancy, 5xx, unclassified) — asserts that none of these
survives into a response body, in whole or as the fragments that identify them:

| Category | Example shape |
|---|---|
| JWT | a three-segment `eyJ…` token |
| API key | `apikey=sk-live-…` |
| password | `password=…` |
| client secret | `client_secret=…` |
| private key | a `-----BEGIN PRIVATE KEY-----` block |
| SQL | `SELECT … FROM tenant_policy WHERE …` |
| stack trace | `File "/srv/jdlib/src/…/pep.py", line 42` |
| internal policy details | `resource.document.vdefault rule 3 …` |
| database credentials | `postgresql+asyncpg://user:pass@host:5432/db` |
| authorization header | `Bearer …` |

Because client-visible messages are echoed by design, this is enforced by a
redaction pass (`_SECRET_PATTERNS` in `responses.py`): PEM blocks, JWTs, bearer
credentials, URL-embedded credentials, `key=value` secret assignments, SQL
statements, stack frames and fully-qualified policy names are replaced with
`[redacted]` before the message leaves the process. Two tests keep it honest —
redaction must not empty a message, and it must not mangle an ordinary one
(`principal user-1 may not read document doc-42` passes through unchanged).
Disabling the redaction pass makes 28 of the 75 tests fail, so the guard is
load-bearing rather than decorative.

## 3. `WWW-Authenticate` (RFC 6750)

A 401 carries the challenge for its code, and no other status carries one:

| Code | Challenge |
|---|---|
| `AUTHENTICATION_REQUIRED` | `Bearer realm="jdlib"` |
| `INVALID_TOKEN`, `UNKNOWN_PRINCIPAL` | `Bearer realm="jdlib", error="invalid_token"` |
| `EXPIRED_TOKEN` | `Bearer realm="jdlib", error="invalid_token", error_description="The access token expired"` |

## 4. Behaviour change: a decision that could not be taken is a 503

Directive §90 requires behaviour changes to be documented; this is one, and it
was made deliberately.

**Before:** a policy decision point that could not reach a verdict produced
`PermissionDenied` — `403`, marked non-retryable and indistinguishable from a
real policy denial.

**Now:** the enforcement point raises the new `AuthorizationUnavailable`
(`POLICY_UNAVAILABLE`, **503**, retryable) in that case. It is still a denial —
nothing is ever allowed because an engine was down, which remains the §16
property the Phase 3 tests assert — but:

* a client can distinguish "you may not" (stop) from "we could not decide"
  (retry with backoff),
* operators get an alertable signal instead of a stream of 403s that look like
  policy denials,
* the message never names the engine or its endpoint, so the 503 does not leak
  architecture.

`AuthorizationUnavailable` lives in `jdlib.errors` with the other error classes
and is re-exported by `jdlib.security.errors`; the 503 mapping uses the
`POLICY_UNAVAILABLE` code that already existed in the code enum, which is what
it was reserved for.

## 5. Public surface

`jdlib.security.__all__` gains exactly three names in this phase —
`AuthorizationUnavailable`, `ErrorResponse`, `error_response` — and
`test_security_public_surface.py` pins the surface as an exact set, so any
further addition is a deliberate, reviewable act. `jdlib.__all__` is unchanged
(the core's 13 exports are asserted to be exactly unchanged, including the
negative assertion that `SecurityConfig` is not among them).

## 6. Deferred

* The envelope is produced by the library but is not yet wired into a FastAPI
  exception handler; the request-edge rework (handlers, `WWW-Authenticate`
  emission, correlation-id extraction from headers) belongs to the integration
  phase together with the PEP and gateway wiring.
* Response *sizes* are not compressed or padded; no timing side channel
  hardening beyond what is described here is claimed.
