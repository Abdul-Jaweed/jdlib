# Directory Structure

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

Annotated tree of the repository at commit `a30601d`. Line counts are from
`wc -l` over tracked Python/Markdown files (excluding caches, `.venv`, `.git`).

```
jdlib/
├── pyproject.toml              56 lines   build (hatchling), deps, ruff, mypy, pytest config
├── README.md                  390 lines   user-facing guide: install, quickstart, strategy table
├── JDLib-Architecture.md     4715 lines   UNTRACKED generated architecture document (see below)
├── .gitignore                             .venv, caches, dist/build, .env, .worktrees, .superpowers/
├── .github/workflows/ci.yml    14 lines   CI: pip install -e ".[dev]" → ruff → mypy → pytest
├── .superpowers/sdd/            (ignored) planning artifacts: 3 report .md + 2 review .diff files
├── docs/
│   ├── jdlib/                  design contracts, docs 02–07 (~2.4k lines)
│   └── superpowers/
│       ├── specs/              foundation design spec (492 lines)
│       └── plans/              9 phase plans, ~15.6k lines total
├── src/jdlib/                  7,447 lines across 64 modules
└── tests/                     13,023 lines across 68 Python files
```

## `src/jdlib` — shipped package

```
src/jdlib/
├── __init__.py                 27   the only public re-export surface (13 names + __version__)
├── _uuid.py                    14   uuid7() — RFC 9562 v7 UUIDs, generated in-process
├── config.py                   78   TenancyConfig + ContextConfig/ResolverConfig/Oidc/ApiKey/Rls
├── context.py                 447   Principal/TenantContext/PrivilegeContext, ContextFactory,
│                                    current_* accessors, scoped_key, EnvelopeCodec, ports
├── errors.py                  147   27 exceptions, all rooted at JdlibError
├── lint.py                    194   metadata lint L1–L19 (LintIssue, lint_metadata, assert_clean)
├── authn/                           authentication
│   ├── __init__.py              0
│   ├── base.py                 33   Authenticator protocol, bearer_token, record_authn_failure
│   ├── apikey.py              103   parse/hash/verify API keys, ApiKeyAuthenticator
│   ├── composite.py            19   CompositeAuthenticator (first non-None wins)
│   ├── oidc.py                268   JwksCache, TokenVerifier, ClaimMapper, UserLinker, OidcAuthenticator
│   └── wiring.py               87   build_authenticator + ContextFactory port adapters
├── authz/                           authorization
│   ├── __init__.py              0
│   ├── access.py             1027   AccessControl: roles, bindings, grants, invitations, transfers
│   ├── cache.py                19   AuthzCache (request-scoped memo, one-way invalidation)
│   ├── guards.py               58   Enforcer, requires(), authorize(), tenant_target()
│   ├── pdp.py                 150   DefaultPDP — gated evaluation, Decision, MatchedRule
│   ├── permissions.py          66   Permission + PermissionCatalog + 13 builtins
│   ├── reader.py              193   AccessReader protocol + ControlAccessReader
│   ├── resource_types.py       56   ResourceTypeDefinition + ResourceTypeRegistry
│   └── scopes.py               83   ScopeRef/ResourceRef/Target + ScopeResolver (chain walk)
├── control/                         control plane (no __init__.py — namespace package)
│   ├── audit.py               172   PlatformAudit protocol, Database/Composite/Recording sinks,
│   │                                PrivilegeAuditAdapter
│   ├── base.py                 21   CONTROL_SCHEMA = "jd_control", NAMING_CONVENTION, ControlBase
│   ├── enums.py                92   all StrEnums + sql_in() CHECK-constraint helper
│   ├── models.py              487   the 16 control-plane ORM models
│   ├── purge.py                61   TenantPlanePurger (shared-schema privileged purge)
│   ├── registry.py            652   TenantRegistry, RegistryWriteFence, transition table
│   └── session.py              41   ControlPlaneSession (framework-internal wrapper)
├── integrations/                    optional-dependency adapters
│   ├── __init__.py              3   docstring only ("import a submodule to opt in")
│   ├── cli.py                 337   Typer app: tenant/db/rls/schema commands
│   └── fastapi.py              98   install(), JdlibContainer, get_context, get_uow, require
├── migrations/                      programmatic Alembic
│   ├── __init__.py              0
│   ├── runner.py              119   MigrationRunner (sync psycopg URL normalization + version reads)
│   ├── control/                     Alembic script location for jd_control
│   │   ├── env.py              45
│   │   └── versions/0001_control_baseline.py        22
│   └── tenant/                      Alembic script location for tenant schemas
│       ├── env.py              48
│       └── versions/0001_tenant_baseline.py         18
├── models/                          tenant plane (no __init__.py — namespace package)
│   ├── base.py                 74   TenantBase, TenantOwned/Routed, Timestamped, SoftDelete,
│   │                                OwnableByOrg/Team, ownership_constraints()
│   ├── org.py                  62   Organization (self-nesting), Team
│   ├── settings.py             25   TenantSetting (JSONB value, PK (tenant_id, key))
│   ├── audit.py                40   AuditEvent (tenant-plane audit rows)
│   └── audit_recorder.py       36   TenantAuditRecorder (records through current context)
├── persistence/                     data access
│   ├── __init__.py              0
│   ├── models.py               47   tenant_table_map(), WriteFence, NullWriteFence, privileged_bypass
│   ├── rawsql.py              256   RawSqlValidator: pglast-based structural proof
│   ├── repository.py           77   TenantRepository[ModelT]
│   ├── router.py               23   SessionRouter
│   ├── secrets.py              31   SecretProvider, MemorySecretProvider, EnvSecretProvider
│   ├── session.py             363   TenantSession + the event handlers that do the enforcement
│   ├── uow.py                  41   UnitOfWork
│   └── strategies/
│       ├── __init__.py          0
│       ├── base.py             37   IsolationStrategy protocol, StrategyCapabilities
│       ├── database.py        203   DatabasePerTenantStrategy (LRU engine cache, invalidate())
│       ├── deprovision.py       9   DeprovisionMode(archive/purge/destroy)
│       ├── rls.py             136   install_rls/verify_rls/emit_rls_policies/rls_eligible_tables
│       ├── schema.py          107   SchemaPerTenantStrategy (search_path per transaction)
│       └── shared.py           65   SharedSchemaStrategy (optional per-transaction RLS binding)
├── tenancy/                         request/background tenancy
│   ├── __init__.py              0
│   ├── jobs.py                 81   ContextPropagator, tenant_job decorator
│   ├── middleware.py          134   TenantMiddleware (pure ASGI), http_status_for, error JSON
│   └── resolution.py          127   RequestInfo + 5 resolvers + ResolverChain + build_chain
└── testing/                         consumer test kit
    ├── __init__.py             13   exports the three assertions
    ├── assertions.py           82   assert_scoped_count / assert_tenant_isolated /
    │                                assert_cross_tenant_write_rejected
    └── pytest_plugin.py        93   jdlib_database_url/schema/models/engine/session_factory
```

Two packages (`jdlib.control`, `jdlib.models`) and the two Alembic script
locations (`jdlib.migrations.control`, `jdlib.migrations.tenant`) contain **no
`__init__.py`** — they are implicit namespace packages. Every other subpackage
has one (all empty except `testing/`, `integrations/`). This is harmless but
inconsistent; see
[limitations_and_edge_cases.md](limitations_and_edge_cases.md).

## `tests` — 13,023 lines · 68 Python files · 527 test functions (568 collected cases)

```
tests/                                   62 test modules + 3 support modules
├── unit/          36 test modules · 268 test functions — no database required
│   ├── test_access.py equivalents: test_pdp.py (16), test_guards.py (8),
│   │   test_permissions.py (5), test_resource_types.py (4)
│   ├── test_rawsql.py (24)          validator matrix: OR/NOT, CTE, subquery, INSERT values
│   ├── test_database_strategy.py (22) engine cache, LRU, invalidate(), secret rotation
│   ├── test_context_factory.py (18) the four context constructors and their gates
│   ├── test_envelope.py (9)         sign/decode, tamper, expiry, future-dated
│   ├── test_lint.py (15)            one test per implemented lint rule
│   └── … config, errors, uuid, public API, testing kit, authn, migrations runner
├── integration/   26 test modules · 259 test functions — real PostgreSQL via testcontainers
│   ├── conftest.py              session-scoped container + schema/engine fixtures
│   ├── strategy_support.py      tenant records, schema/database handles, cleanup helpers
│   ├── rls_support.py           RLS DDL retry helper (lock-timeout aware)
│   ├── test_registry.py (46)    the lifecycle state machine end to end
│   ├── test_session_isolation.py (39) the event-handler enforcement matrix
│   ├── test_access_invitations.py (24), test_access_grants.py (19),
│   │   test_access_bindings.py (14), test_access_roles.py (12)
│   ├── test_strategy_matrix.py (6×4) the same behaviour under
│   │   shared / shared-rls / schema / database
│   ├── test_rls_db.py (9), test_oidc_linking.py (9), test_tenant_purge.py (7),
│   │   test_fastapi_integration.py (7), test_migrations.py (6), …
│   └── test_repository.py (1), test_cli_integration.py (1), test_role_action_matrix.py (2)
└── support/
    ├── __init__.py
    ├── invoice.py           consumer-style models: Invoice (ownable, soft-delete), LineItem
    └── context_fakes.py     FrozenClock, StaticPrincipals, DictTenants, ServabilityStub,
                             EntitlementsStub, ServiceAccountEntitlementsStub,
                             OperatorsStub, RecordingPrivilegeAudit
```

`tests/support/invoice.py` doubles as the canonical example of a consumer
resource model — it mixes `TenantRouted`, `Timestamped`, `SoftDelete`,
`OwnableByOrg`, `OwnableByTeam` and uses `ownership_constraints()`.

## `docs` — pre-existing documentation (not part of the KB)

```
docs/jdlib/02-relational-schema.md        538   table-by-table schema contract
docs/jdlib/03-isolation-invariants.md     293   I1–I13 invariants + isolation matrix
docs/jdlib/04-authorization-model.md      360   precedence chain, effective-permission algorithm
docs/jdlib/05-tenant-lifecycle.md         304   states, provisioning, deprovisioning, relocation
docs/jdlib/06-strategy-matrix.md          201   per-strategy capabilities and failure modes
docs/jdlib/07-implementation-design.md    839   code-level blueprint (partly aspirational)
docs/superpowers/specs/…foundation-design.md   492   the original design spec
docs/superpowers/plans/*.md               9 files · 15,644   phased TDD implementation plans
JDLib-Architecture.md                    4715   root-level generated architecture doc (untracked)
```

The design docs are *contracts written before implementation*: they describe
intended behaviour, including features that were not built (relocation service,
`jdlib.audit` package, `MigrationRunner.upgrade_all`, extra config blocks). The
per-file differences are enumerated in
[reference/design_docs_map.md](reference/design_docs_map.md). Treat this
knowledge base + the source as authoritative, and use those docs for rationale.

## Root-level files that matter

| Path | Why it matters |
|---|---|
| `pyproject.toml` | Dependency truth: 10 runtime deps, `dev`/`fastapi`/`cli` extras, `pytest11` entry point for the plugin, ruff/mypy/pytest config. |
| `.github/workflows/ci.yml` | The exact gate CI enforces: `ruff check .`, `mypy src/jdlib`, `pytest -q` on Python 3.12. Integration tests need Docker in CI (testcontainers). |
| `.gitignore` | Excludes `.venv`, caches, `dist/`, `build/`, `*.egg-info`, `.env`, `.worktrees/` and the whole `.superpowers/` directory. `JDLib-Architecture.md` and `knowledge_base/` are **not** ignored — they show as untracked until committed. |
| `JDLib-Architecture.md` | Untracked, 238 KB, generated by an earlier analysis pass. Useful as a cross-check but **not** a source of truth; it is not shipped or versioned. |
| `.superpowers/sdd/` | Agent working notes: `completion-sweep-report.md`, `debt-closure-report.md`, `post-review-fix-report.md`, review diffs. Historical context only. |
