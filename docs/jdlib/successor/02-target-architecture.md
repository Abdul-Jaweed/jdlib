# JDLib successor programme — target architecture

## 1. What this architecture is, and what it is not

It is an **extension** of JDLib as it exists: five new subpackages that attach to the 34 existing
ports, plus targeted improvements inside two existing ones. It is not a re-layout. The tenancy,
authorization, persistence and audit cores are specified in `docs/jdlib/` (the approved design
documents) and are treated here as constraints, not as candidates for redesign — §38 of this
programme requires existing security guarantees to survive intact, and a re-layout would put every
one of them back on the table.

The directive's proposed tree (§7) is followed where JDLib has nothing, adapted where JDLib has
something, and rejected where it would duplicate a namespace (`03-api-naming.md` §3 records each).

## 2. Layering, with the new packages placed

The existing style is ports-and-adapters with dependencies pointing inward:

```
integrations (fastapi, cli)                    ← adapters
resources · tenancy · authn · audit            ← application services (use cases)
credentials · data · caching                   ← domain ports + their adapters
authz · persistence · control · query          ← domain services and persistence ports
context · models · errors · config             ← foundation (no I/O)
```

Rules carried forward unchanged: dependencies point inward only; every external concern enters
through a `Protocol` port; constructor injection, no DI container, no service locator, no global
mutable state beyond the fail-closed `contextvars` contextvar; async-first, with sync confined to
Alembic invocation and the CLI; one concrete implementation per port in v1.

Rules the new packages add:

| Package | Layer | Rule |
|---|---|---|
| `jdlib.query` | domain, **pure** | compiles to a value (`CompiledQuery`: SQL text + bound parameters). It performs no I/O, holds no connection and knows no engine. Purity is what makes it fuzzable |
| `jdlib.credentials` | ports + adapters | the port is `SecretProvider` (existing, extended); adapters are `EnvSecretProvider` (existing), `RotatingSecretProvider`, and the `CryptographicProvider` implementations. No vendor is bound without a service to verify against |
| `jdlib.caching` | adapters | `ScopedCache` is a facade over `CacheProvider` implementations; the only place a cache key is constructed is `ScopedKeyFactory` |
| `jdlib.data` | adapters | connectors are the only code that opens a non-database connection. They receive an already-authorized, already-resolved context and never evaluate authorization |
| `jdlib.resources` | application service | resolution is tenant-scoped and authorization-aware; it is the only place that joins tenant context → definition → credentials → connector |

## 3. Module layout (actual, not aspirational)

Existing packages are listed unchanged to make the additions unambiguous:

```
src/jdlib/
├── __init__.py            # frozen 13-symbol surface
├── config.py  errors.py  lint.py  context.py  _uuid.py
├── authn/  authz/  control/  models/  migrations/  tenancy/  testing/  integrations/
├── persistence/           # session, router, uow, repository, secrets, strategies/
├── security/              # audit, authn, authz, compliance, gateway, tracing, metrics
│
├── resources/             # NEW — tenant resource hydration
│   ├── __init__.py        # public surface, pinned by its own surface test
│   ├── definitions.py     # ResourceDefinition, ResourceDefinitionRegistry
│   ├── resolver.py        # ResourceResolver: TenantContext → ResourceHandle → instance
│   └── handles.py         # ResourceHandle (deterministic identity, cache-key input)
│
├── credentials/           # NEW — secret and cryptographic providers
│   ├── __init__.py
│   ├── refs.py            # SecretRef, SecretVersion (versioned handles)
│   ├── rotation.py        # RotatingSecretProvider (rotation behind the provider)
│   ├── crypto.py          # CryptographicProvider port, EncryptedValue, KeyVersion
│   └── software.py        # the one software implementation shipped in v1
│
├── caching/               # NEW — scoped caching
│   ├── __init__.py
│   ├── keys.py            # ScopedKeyFactory — the ONLY key constructor
│   ├── policy.py          # CachePolicy (TTL, max-age, invalidation scope)
│   ├── local.py           # LocalCache
│   ├── redis.py           # RedisCache
│   └── scoped.py          # ScopedCache facade
│
├── data/                  # NEW — connectors and object storage
│   ├── __init__.py
│   ├── connector.py       # DataConnector protocol, ConnectorCapabilities
│   ├── registry.py        # ConnectorRegistry, ConnectorFactory
│   ├── policy.py          # ConnectionPolicy (timeout, retry, circuit breaking, pool bounds)
│   ├── relational.py      # the v1 relational connector (PostgreSQL, existing engine)
│   └── objectstore.py     # ObjectStorageProvider, StoredObject, ObjectMetadata
│
└── query/                 # NEW — bounded query specification and compilation
    ├── __init__.py
    ├── specification.py   # QuerySpecification (Pydantic-validated)
    ├── ast.py             # the intermediate representation
    ├── compiler.py        # QueryCompiler → CompiledQuery
    ├── dialects.py        # QueryDialect registry
    └── safety.py          # identifier validation, construct rejection, complexity limits
```

## 4. The security boundary model

JDLib's authority model has exactly two enforcement points, per
`docs/jdlib/04-authorization-model.md` §7: the framework guards (`@requires`, `authorize()`) and
`AccessControl`. **Nothing in this programme adds a third.** The new subsystems sit on one side or
the other of that line, and the document states which:

| New component | Relationship to authority |
|---|---|
| `ResourceResolver` | **consumer**: calls `authorize()` before hydrating a resource; a denial is a denial, never a "resource not found" that hides it, and never a fallback to a default resource |
| `ConnectorFactory` | **non-authoritative**: receives an authorized context; §15 is explicit that a connector must never decide authorization. A connector that cannot verify it was handed a context refuses to open |
| `QueryCompiler` | **safety-enforcing, not authority-enforcing**: it guarantees the tenant constraint is present and identifiers are validated; it does not decide *whether* the caller may read, which remains the PDP's answer |
| `ScopedKeyFactory` | **safety by construction**: keys cannot be built without tenant scope where the namespace requires it. This prevents a class of bug (cross-tenant read-through) rather than granting authority |
| `SecretProvider` / `CryptographicProvider` | **fail-closed**: unresolvable handle raises (`StrategyCapabilityError` semantics); a decryption failure raises and never downgrades to an older key unless the security model explicitly permits it |
| `ObjectStorageProvider` | **non-authoritative**: keys are tenant-scoped by construction and credentials arrive resolved; it never sees a tenant id it must trust |
| `JobEnvelope` | **claim, not authority**: an envelope is revalidated on execution (TTL/signature → principal → tenant status → re-authorization → fresh context). A serialized context is never trusted |

Two rules that follow, and that the phases are gated on:

1. **No new subsystem becomes an authorization oracle.** If a component starts answering "may
   this principal do X?", it has become a second evaluator and the phase fails its gate.
2. **No new subsystem caches an authority decision across requests.** `AuthzCache` is
   request-scoped by design; the caching phase must not extend its lifetime, and §25 of the
   directive's rule about revocation windows is satisfied by that design rather than by a new
   mechanism.

## 5. The hydration model

This programme implements the contract the design documents already specify
(`docs/jdlib/05-tenant-lifecycle.md` §7) rather than inventing a parallel one:

```
TenantContext
   → ResourceResolver            (1) registry lookup by kind; unknown kind refuses
                                 (2) authorize(principal, "resource:use", target)   ← PDP
                                 (3) SecretProvider.resolve(SecretRef) → ConnectionConfig + SecretVersion
   → ConnectorFactory            (4) connector for the kind, with ConnectorCapabilities
   → DataConnector.connect       (5) under ConnectionPolicy (timeout, retry, health)
   → ResourceHandle              (6) deterministic identity; the cache key derives from it
```

Properties the model guarantees, each of which becomes a test in Phase 1: tenant-aware;
security-context aware; authorization-aware; no credential leakage (no repr, no logs, no audit
payload); explicit lifecycle (`close()` is a documented obligation, not a garbage-collector hope);
lazy initialization; deterministic resource identity; safe cache integration; provider
abstraction; async-first, with sync adapters only where a driver offers nothing else.

`target_handle` semantics from the design doc are preserved: an opaque handle, never a DSN or a
credential; resolution failures raise rather than falling back to a shared target.

## 6. The connector and query models

**Connectors** (§15, §16): a `DataConnector` protocol with `resource_type`, `connect`,
`health_check`, `close`; a `ConnectorRegistry` that validates at startup (the same discipline as
`PermissionCatalog` and `ResourceTypeRegistry` — a registry that can be wrong at runtime is a
registry that will be); `ConnectorCapabilities` in the same shape as the existing
`StrategyCapabilities`; `ConnectionPolicy` supplying timeout, retry, and circuit-breaking, with
pool bounds inheriting the existing `PoolCapacityError` semantics and eviction rules (never evict a
pool with a checked-out connection). Every connector ships with a **contract test suite** that any
implementation must pass, and a **test double** so consumers are not forced to run a real engine to
test their own code.

**The query system** is scoped by ADR-1 (`04-adoption-decisions.md`): it exists for engine access
where no ORM path exists — the analytics connector family — and it never replaces
`TenantRepository` on the PostgreSQL tenant plane, where the ORM, RLS, and metadata lint are the
enforcement stack. Within its scope it is strict: values are always bound;
identifiers are validated against an allowlist **at parse time** (the archived library's defect was
an allowlist that existed but was bypassed on the `ORDER BY`/`GROUP BY` paths); the tenant
constraint is applied by the compiler, not requested of the caller; dangerous constructs
(DDL/DML in a read specification, multiple statements, unbounded pagination) are rejected; and
complexity is bounded. The compiler is pure, which is what allows the adversarial phase to fuzz it
without infrastructure.

## 7. Dependency boundaries

- **Core stays small.** The new packages must not add a mandatory dependency to
  `[project.dependencies]` unless the capability is core. `redis` arrives via an extra,
  object-storage clients via an extra, analytics drivers via their own extras — a
  PostgreSQL-only consumer installs nothing new.
- **One source of truth for dependencies**: `pyproject.toml`. No second requirements file exists
  in this repository, and this programme will not create one.
- The `starlette` defect in `00-current-state.md` §6 is fixed and then gated by a test that fails
  when a source import is neither declared nor standard library — the archived library shipped the
  same defect with `orjson` (46 imports, undeclared, arriving transitively) and it is exactly the
  rework this programme should make structurally impossible.

## 8. What does not change

The 13-symbol top-level surface; `jdlib.security.__all__`; the two enforcement points; the PDP
contract and `Decision` shape; the isolation strategies and their capabilities; `TenantSession`
scoping and stamping; the audit planes and fail-closed mandatory events; the error taxonomy and
`describe_error`; migrations (programmatic Alembic, one head constant); the FastAPI and CLI
integrations. A consumer that works today keeps working with no code change, and the programme's
additive-surface rule makes that checkable rather than promised.
