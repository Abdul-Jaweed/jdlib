# JDLib successor programme — public API naming

## 1. The two rules this document exists to enforce

**Reuse before invention.** JDLib declares 34 extension points (`00-current-state.md` §5). A new
name for something JDLib already has is not a design decision, it is a duplicate responsibility.

**New API goes in new namespaces.** `jdlib.__all__` (13 symbols) is curated, and
`tests/unit/security/test_security_public_surface.py:68` pins `jdlib.security.__all__` by exact
equality. Appending to either list breaks a test that encodes intent. New surfaces therefore arrive
as new subpackages with their own `__all__`, and the pinned lists stay untouched.

Names follow JDLib's existing style: capability-oriented, no abbreviations except established ones
(`PDP`, `JWKS`, `RLS`, `TTL`), no vendor names in public API, no `Compat`/`Legacy`/`V1` suffixes,
no verb-noun managers that accrete responsibilities, and no aggregate "manager" object that spans
subsystems — the archived library's 1,238-LOC god object is the reason this rule is written down.

## 2. Names proposed, revised, rejected

This programme's directive proposes a conceptual name set. Each proposed name is reconciled
against what exists before it is accepted.

| Proposed | Decision | Final name | Reason |
|---|---|---|---|
| `TenantResourceManager` | **REJECT** | — | an aggregate manager over registry, resolution, credentials and lifecycle is the god object by another name. Split into the four rows below |
| `ResourceRegistry` | **REVISE** | `ResourceDefinitionRegistry` | `ResourceTypeRegistry` already exists in `jdlib.authz` for *authorization* resource types. Two registries named "resource" would be indistinguishable at a call site; the new one registers **hydration definitions** |
| `ResourceDefinition` | **ACCEPT** | `ResourceDefinition` | typed description of one hydratable resource: kind, connector, secret reference, config schema |
| `ResourceResolver` | **ACCEPT** | `ResourceResolver` | tenant context → resolved, authorized resource instance |
| — | **NEW** | `ResourceHandle` | the deterministic identity of a resolved resource; the cache key derives from it. (The design docs' `target_handle` names the *placement* target in the database strategies; the hydration layer's handle is a different concept and gets a different name) |
| `CredentialProvider` | **REVISE** | `SecretProvider` (existing) + `SecretRef` | `SecretProvider.resolve(handle) -> ConnectionConfig` is already specified in `docs/jdlib/05-tenant-lifecycle.md` §7 and implemented for environment/memory. A second credential-provider abstraction would be the duplicate this programme forbids; what is missing is a **versioned reference** and a rotation seam |
| `SecretProvider` | **KEEP** | `SecretProvider` | as specified above |
| — | **NEW** | `SecretVersion`, `RotatingSecretProvider` | version metadata carried on resolution (so pools rebuild on rotation, per the design doc) and an explicit rotation wrapper |
| `ScopedCache` | **ACCEPT** | `ScopedCache` | facade over providers, tenant-aware by construction |
| `CacheProvider`, `LocalCache`, `RedisCache`, `ScopedKeyFactory`, `CachePolicy` | **ACCEPT** | unchanged | no clash with existing vocabulary; the names describe exactly what they are |
| `CryptographicProvider` | **ACCEPT** | `CryptographicProvider` | new capability, no existing equivalent |
| — | **NEW** | `EncryptedValue`, `KeyVersion` | ciphertext plus the key/version metadata that makes rotation possible. `EncryptedValue` is a value type: a decryption failure raises, it never returns the ciphertext |
| `DataConnector` | **ACCEPT** | `DataConnector` | protocol with `connect` / `health_check` / `close` |
| `ConnectorRegistry`, `ConnectorFactory` | **ACCEPT** | unchanged | — |
| `ConnectorCapabilities` | **ACCEPT** | `ConnectorCapabilities` | mirrors the existing `StrategyCapabilities` idiom rather than inventing a second capability vocabulary |
| `ConnectionPolicy` | **ACCEPT** | `ConnectionPolicy` | timeout, retry, circuit-breaking, pool bounds — the last of which already exists as `PoolCapacityError` semantics in the database strategy |
| `QuerySpecification` | **ACCEPT, SCOPED** | `QuerySpecification` | scoped by ADR-1: engines without an ORM, never the PostgreSQL tenant plane |
| `QueryCompiler` | **ACCEPT, SCOPED** | `QueryCompiler` | same scope |
| — | **NEW** | `CompiledQuery`, `QueryDialect` | `CompiledQuery` carries SQL text **and** its bound parameters as one value, so "parameterized" is structural rather than a convention; `QueryDialect` is a small explicit registry |
| `DelegationContext` | **REJECT** | `PrivilegeContext` (existing) | §14 of the directive says it: do not create a second privilege model. Delegation is `PrivilegeContext(kind='delegation', capability=…, justification=…, expires_at=…)`, exactly as operator access already is `kind='operator'` |
| `PrivilegedAccess` | **REJECT** | `PrivilegeContext` + `platform_operator` | already implemented, capability-mapped, TTL'd and audited |
| `RequestSecurityContext` | **REJECT** | `SecurityContext` (existing) | the hardening programme already ships `SecurityContext` and `security_context_scope`; a second request-security type would fork the security boundary |
| `ObjectStorageProvider` | **ACCEPT** | `ObjectStorageProvider` | protocol: put / get / delete / list / stream |
| — | **NEW** | `StoredObject`, `ObjectMetadata` | value types; a provider that is a shell is never exported (GCS and Azure are `DEFER`, not adopted) |
| — | **NEW** | `JobEnvelope` | the revalidated context envelope for background execution: verify → TTL/signature → reload principal → reload tenant status → re-authorize → fresh context |

Counted from this table's own rows: 12 rows accepted (10 unchanged, 2 accepted with the ADR-1 scope), 2 revised in place, 1 kept as-is against a second abstraction, 4 rejected in favour of an existing type or as an aggregate, and 6 rows introducing 10 names that had no predecessor to reuse.

## 3. Namespaces

New subsystems get new subpackages. Existing namespaces are **not** renamed — a rename would break
consumers and the pinned surfaces for no functional gain (the directive's §1.2 forbids preserving
the archived library's names; it does not ask JDLib to rename its own).

| Namespace | Status | Contents |
|---|---|---|
| `jdlib.resources` | **new** | `ResourceDefinitionRegistry`, `ResourceDefinition`, `ResourceResolver`, `ResourceHandle` |
| `jdlib.credentials` | **new** | `SecretRef`, `SecretVersion`, `RotatingSecretProvider`, `CryptographicProvider`, `EncryptedValue`, `KeyVersion` |
| `jdlib.caching` | **new** | `ScopedCache`, `CacheProvider`, `LocalCache`, `RedisCache`, `ScopedKeyFactory`, `CachePolicy` |
| `jdlib.data` | **new** | `DataConnector`, `ConnectorRegistry`, `ConnectorFactory`, `ConnectorCapabilities`, `ConnectionPolicy`, `ObjectStorageProvider` |
| `jdlib.query` | **new** | `QuerySpecification`, `QueryCompiler`, `CompiledQuery`, `QueryDialect` |
| `jdlib.authn`, `jdlib.authz`, `jdlib.control`, `jdlib.persistence`, `jdlib.security`, `jdlib.tenancy`, `jdlib.models`, `jdlib.migrations`, `jdlib.integrations`, `jdlib.testing` | **existing, unchanged** | the successor phases attach at their ports; they do not restructure them |
| `jdlib.identity` | **rejected** | the directive's tree proposes it; JDLib's equivalent is `authn` (+ `security.authn`). Introducing `identity` beside `authn` would give one concept two names |

Placement rule: a new subsystem that *extends* an existing seam lives in that seam's namespace
(credential rotation extends `SecretProvider`, so rotation wrappers may also be re-exported from
`jdlib.persistence` for continuity); a new subsystem with its own ports gets its own namespace.

## 4. Errors

No new exception base. New failures join the existing taxonomy in `jdlib.errors` /
`jdlib.security.errors`, following the established `*Error` naming and the
`describe_error` mapping that the security surface tests pin:

| Situation | Error |
|---|---|
| Resource definition unknown or not hydratable by this tenant | `ResourceUnavailableError` |
| Credential unresolvable, revoked, or version retired | `CredentialUnavailableError` |
| Decryption or key-version failure | `CryptographicError` (fail closed; never a downgrade) |
| Connector cannot be acquired or is unauthorized | `ConnectorUnavailableError` (the connector never decides authorization; the PDP does) |
| Query rejected (identifier, complexity, dangerous construct) | `QueryRejectedError` |
| Object storage provider not implemented | `ProviderNotImplementedError` — raised by an API that cannot exist, which is exactly why shell providers are not exported |

Each carries a stable code and a redacted message: `describe_error` is the single mapping the
security surface tests assert over, and these entries join it rather than evade it.

## 5. Stability promise

- The 13 top-level symbols and the pinned security surface are **frozen** for this programme.
- New namespaces are public and may gain members; nothing in them is removed in this programme.
- Internal modules stay internal: a class is public when its namespace's `__all__` names it.
- Every new public namespace gets its own surface test in the style of
  `tests/unit/security/test_security_public_surface.py`, asserting exact membership, so growth is
  a deliberate edit rather than an accident.
