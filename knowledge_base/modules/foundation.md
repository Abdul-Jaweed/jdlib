# Module: Foundation (`errors.py`, `config.py`, `context.py`, `_uuid.py`, `lint.py`)

Five modules that import nothing else from jdlib (except `context` →
`config`/`control.enums`/`errors`) and are safe to use anywhere.

## `errors.py` — 27 exceptions

```
JdlibError
├── MissingTenantContext            no active tenant context
├── TenantNotFound(tenant)          "tenant not found: <slug-or-id>"
├── TenantAccessDenied
├── TenantSuspended
├── TenantNotWritable
├── CrossTenantReferenceError(reference, expected_tenant, actual_tenant)
├── UnscopedBulkOperation
├── InvalidReference
├── InvalidResourcePermission
├── UnknownResourceType
├── UnknownPermission
├── RoleScopeMismatch
├── AuthenticationError
│   ├── InvalidToken
│   ├── ExpiredToken
│   └── UnknownPrincipal
├── AuthorizationError
│   ├── PermissionDenied
│   └── RoleEscalationBlocked
├── StrategyCapabilityError
├── PoolCapacityError
├── TenantOperationInProgress
├── RelocationPhaseError            (defined, never raised — see below)
├── UnscopedRawSql
├── SchemaLintError(issues: list[str])
├── ProvisioningError
└── MigrationError                  (defined, never raised — see below)
```

Rules the code follows:

- Only `JdlibError` subclasses cross module boundaries; driver exceptions are
  expected to be mapped at the persistence boundary
  (`docs/jdlib/07` §16; `README.md` "Extension points → Errors").
- `CrossTenantReferenceError` and `SchemaLintError` build their own messages and
  keep structured data (`TenantAccessDenied` etc. take a plain message).
- Two classes are currently dead: `RelocationPhaseError` and `MigrationError` are
  exported but no `raise` statement in `src/` uses them (verified by scanning for
  `raise <Name>`). They belong to the unwritten relocation service and to
  migration error propagation respectively — see
  [../limitations_and_edge_cases.md](../limitations_and_edge_cases.md).

Where each error is raised (src-side, verified):

| Error | Raised in |
|---|---|
| `MissingTenantContext` | `context.py`, `persistence/session.py`, `authz/pdp.py` |
| `TenantNotFound` | `context.py`, `control/registry.py`, `tenancy/middleware.py`, `tenancy/jobs.py` |
| `TenantAccessDenied` | `context.py`, `tenancy/jobs.py` |
| `TenantSuspended` / `TenantNotWritable` | `control/registry.py` |
| `CrossTenantReferenceError` | `persistence/session.py`, `authz/access.py` |
| `UnscopedBulkOperation` / `UnscopedRawSql` | `persistence/session.py`, `persistence/rawsql.py` |
| `AuthorizationError` | `context.py`, `persistence/session.py`, `authz/access.py` |
| `PermissionDenied` | `authz/guards.py` |
| `RoleEscalationBlocked`, `InvalidReference`, `RoleScopeMismatch` | `authz/access.py` |
| `StrategyCapabilityError` | `strategies/*`, `persistence/router.py`, `control/registry.py` |
| `PoolCapacityError` | `persistence/strategies/database.py` |
| `TenantOperationInProgress`, `ProvisioningError` | `control/registry.py` |
| `SchemaLintError` | `lint.py` |

## `config.py` — `TenancyConfig`

`TenancyConfig` is a `pydantic-settings` `BaseSettings` with
`env_prefix="JDLIB_"` and `env_nested_delimiter="__"`.

| Field | Type | Default | Notes |
|---|---|---|---|
| `control_dsn` | `SecretStr \| None` | `None` | Control-plane DSN; the CLI uses `JDLIB_CONTROL_DSN` as the default `--database-url`. |
| `context` | `ContextConfig` | **required** | |
| `resolvers` | `ResolverConfig` | `ResolverConfig()` | |
| `oidc` | `OidcConfig \| None` | `None` | Absent ⇒ no OIDC authenticator is built. |
| `api_keys` | `ApiKeyConfig` | `ApiKeyConfig()` | |
| `rls` | `RlsConfig` | `RlsConfig()` | |

`ContextConfig`: `signing_key: SecretStr` (**required** — the envelope HMAC key),
`envelope_ttl: timedelta = 5 min`, `operator_ttl: timedelta = 30 min`,
`allow_test_contexts: bool = False`.

`ResolverConfig`: `order` (default `[JWT_CLAIM, SUBDOMAIN, PATH, HEADER, API_KEY]`),
`base_domain: str | None = None`, `path_prefix: str = "/t/"` (validator requires a
non-empty absolute path), `header_name: str = "X-Tenant-Slug"`, `jwt_claim: str = "tid"`.

`OidcConfig`: `issuer`, `audience`, `algorithms=["RS256"]`, `jwks_url=None`
(derived by `resolved_jwks_url()` as `<issuer>/.well-known/jwks.json`),
`jwks_ttl=1 h`, `leeway=60 s`, `email_trusted=False`.

`ApiKeyConfig`: `prefix: str = "jd"` — the first segment of every API key token.
`RlsConfig`: `enabled: bool = False`, `app_role: str | None = None`.

The design doc `docs/jdlib/07` §5 shows a larger config (`default_strategy`,
`strategies`, `pools`, `secrets`, `strict_schema`). Those fields do **not**
exist; see [../reference/design_docs_map.md](../reference/design_docs_map.md).

## `context.py` — identity and context creation

### Value objects (all `@dataclass(frozen=True, slots=True)`)

- `Principal`: `kind` (`PrincipalKind`: `user`/`service_account`/`platform_operator`),
  `id`, `user_id`, `tenant_id` (pin for service accounts), `api_key_id`,
  `scopes: frozenset[str] | None` (`None` = no narrowing), `operator_level`.
- `PrivilegeContext`: `kind` (`PrivilegeKind`: `operator`/`system`/`test`),
  `capability`, `justification`, `actor`, `issued_at`, `expires_at`.
- `TenantContext`: `tenant_id`, `tenant_slug`, `strategy`, `principal`,
  `request_id`, `correlation_id`, `trace_id`, `privilege`.
- `TenantRef` (`id` and/or `slug`), `TenantRecord` (`id`, `slug`, `status`,
  `strategy`, `target_handle`), `TenantContextEnvelope` (signed payload).

### Accessors and scoping

- `current_tenant()` raises `MissingTenantContext` when no context is active;
  `current_principal()`, `current_privilege()` delegate to it (so a missing
  context fails closed instead of returning `None`).
- `context_scope(context)` is a context manager that sets/resets the
  `contextvars.ContextVar` (token-based, exception-safe).
- `scoped_key(namespace, *parts)` → `jdlib:v1:<tenant_id>:<ns>:<part>...` with
  `urllib.parse.quote(..., safe="")` on the namespace and every part, so `:`
  can never appear inside a part (collision-free key convention, invariant I8).

### `ContextFactory` — the only sanctioned creator

Constructor takes ports: `config: ContextConfig`, `principals:
PrincipalDirectory`, `tenants: TenantDirectory`, `servability:
ServabilityChecker`, `entitlements: EntitlementChecker`, `operators:
OperatorAuthorizer`, `audit: PrivilegeAudit`, `clock: Clock | None`.

| Method | Gates applied (in order) | Result |
|---|---|---|
| `for_principal(principal, tenant_ref, *, request_id, correlation_id=None, trace_id=None)` | principal active → tenant exists → **service-account pin equals tenant** → entitlement → servability | `TenantContext` with `privilege=None` |
| `for_operator(operator, tenant_ref, capability, *, justification, ttl=None, request_id, ...)` | kind is `platform_operator` → non-blank justification → `0 < ttl ≤ config.operator_ttl` → capability authorized → tenant exists → servability | context with `PrivilegeKind.OPERATOR` privilege; **audited** via `record_privilege` |
| `for_system(tenant, *, purpose, issuer)` | requires the module-private `PRIVILEGE_ISSUER` sentinel | context with `PrivilegeKind.SYSTEM` privilege, capability = purpose, no expiry; audited |
| `for_test(tenant, *, principal, issuer)` | requires the `PRIVILEGE_ISSUER` sentinel **and** `config.allow_test_contexts` | context with `PrivilegeKind.TEST`; audited |

Ordering is security-relevant and asserted by tests: for a
service account, the pin mismatch is checked **before** entitlement and
servability, so a pinned service account never reaches another tenant and a
non-entitled principal never learns tenant state
(`tests/unit/test_context_factory.py::test_for_principal_denies_mismatched_pin_before_entitlement_and_servability`).

The sentinel `PRIVILEGE_ISSUER = _PrivilegeIssuer()` is intentionally private:
application code cannot fabricate system/test contexts, only code that can
import the object (framework internals, e.g. `TenantPlanePurger`) can.

### `EnvelopeCodec` — signed cross-boundary identity

- Format: `<urlsafe-b64(payload)>.<urlsafe-b64(HMAC-SHA256)>`, payload is
  canonical JSON (`sort_keys=True`, compact separators) of `tenant_id`
  (string), `principal_type`, `principal_id`, `request_id`, `correlation_id`,
  `trace_id`, `issued_at` (ISO-8601 via the injected clock).
- `decode()` verifies the HMAC with `hmac.compare_digest`, rejects
  future-issued (>60 s skew) and expired (> `envelope_ttl`) envelopes, and maps
  every parse failure to `InvalidToken`/`ExpiredToken`.
- It carries **identity only** — no permissions, no scopes, no privileges
  (asserted by `tests/unit/test_envelope.py::test_token_does_not_contain_permissions_or_scopes`).
- Key material comes from `ContextConfig.signing_key.get_secret_value()`.

## `_uuid.py` — `uuid7()`

14-line RFC 9562 version-7 generator: 6-byte big-endian millisecond timestamp
prefix, `os.urandom` for the remaining bytes, version nibble `0x7` and variant
bits `10` patched in. No dependency, no monotonic counter — ordering is
timestamp-granular (same-millisecond order is random; the test only asserts
ordering across a 2 ms sleep).

## `lint.py` — metadata invariants L1–L19

`lint_metadata(controls: list[MetaData], rls_enabled: bool = False) ->
list[LintIssue]` and `assert_clean(...)` (raises `SchemaLintError`). Issues are
`LintIssue(rule, table, message)` dataclasses.

Implemented rules and their exact checks: see
[../reference/invariants_and_lint.md](../reference/invariants_and_lint.md)
(that page is the canonical rule→code map, including which of L1–L19 are
implemented as lint vs enforced at write time vs not implemented).

Two whitelists/config points in code:

- `GLOBAL_UNIQUE_WHITELIST = {("api_keys","uq_api_keys_key_prefix"),
  ("invitations","uq_invitations_token_id"), ("tenants","uq_tenants_slug")}` —
  the only unique constraints allowed to be non-tenant-scoped (L12).
- `TENANT_ID_REFERENCE_ONLY = {"platform_audit_events"}` — a nullable
  `tenant_id` reference, not a scoped table.

`alembic_version` tables are skipped. Model identity checks (`L11`, `L17`,
`L19`) first consult `table.info["jdlib_model"]` (set by `ResourceTypeRegistry`
consumers) and fall back to a reflective walk of `ControlBase`, `TenantBase`,
`TenantOwned` subclasses.

Invocation points: `jdlib schema lint [--rls]` (`integrations/cli.py:325`) and
`tests/unit/test_lint.py` (one test per rule).
