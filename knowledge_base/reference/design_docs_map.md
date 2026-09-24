# Reference: Repository Docs Map (and Drift)

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

The repository carries three documentation layers plus two large planning
artifacts. This page says what each one is for, and — importantly — where the
design docs no longer match the shipped code.

## Inventory

| Artifact | Size | Role |
|---|---|---|
| `README.md` | 390 lines / 16 KB | Consumer-facing: install, the seven setup steps, quickstart wiring, CLI, testing. Authoritative for *usage*. |
| `docs/jdlib/02-relational-schema.md` | 538 lines | Schema specification: ERD, identifier scopes, per-table definitions, application-resource rules, the L1–L19 rule list, migration artifacts. |
| `docs/jdlib/03-isolation-invariants.md` | 293 lines | The I1–I13 invariants, the isolation matrix (placement × surface), failure semantics, and the intended test-suite shape. |
| `docs/jdlib/04-authorization-model.md` | 360 lines | Principals, status precedence, effective-permission algorithm, anti-escalation rules, ownership transfer, platform-operator capabilities, PDP contract, role templates. |
| `docs/jdlib/05-tenant-lifecycle.md` | 304 lines | States, provisioning pipeline, migration state machine, suspension, deprovisioning, the **manual** relocation runbook, secret/target resolution, lifecycle test gates. |
| `docs/jdlib/06-strategy-matrix.md` | 201 lines | Capabilities per strategy, routing, shared/schema/database specifics, RLS, hybrid placement, the strategy-independent surface, failure modes. |
| `docs/jdlib/07-implementation-design.md` | 839 lines | Code-level design: architectural style, patterns used/rejected, the (design-time) file map, foundation types, config, ORM design, services, authn/authz, pipeline, audit, migrations, integrations, testing design, build order. |
| `docs/superpowers/specs/2026-09-21-jdlib-multitenancy-foundation-design.md` | 30 KB | The original foundation design specification. |
| `docs/superpowers/plans/2026-09-21-jdlib-*.md` (9 files) | 21–102 KB | Phase plans: foundation, context-resolution, persistence, registry, authorization, access-control, authentication, strategies, integrations. Historical process artifacts. |
| `JDLib-Architecture.md` (repo root, **untracked**) | 238 KB | Consolidated architecture document; superset-sized amalgam, not referenced by any code or CI. |
| `knowledge_base/` (this KB) | — | Source-derived description of the code as it exists, with verification evidence. |

Precedence when they disagree: **code + tests** > this KB > `README.md` >
`docs/jdlib/*` (design) > `docs/superpowers/*` (planning).

## How the design docs map onto the code

| Design doc | Implemented in | Fidelity |
|---|---|---|
| 02 §3 control-plane tables | `control/models.py` (16 tables) + `reference/schema_tables.md` | High — column sets match; naming/constraints match. |
| 02 §4–5 tenant-plane + application resources | `models/org.py`, `models/settings.py`, `models/audit.py`, `models/base.py`, `tests/support/invoice.py` | High for the model contract; the "application resources" section is a contract, not code. |
| 02 §6 L-rules | `lint.py` (12 of 19 emitted) + write-path validators | Partial — see drift D3. |
| 03 I1–I13 | `persistence/session.py`, `rawsql.py`, `context.py`, `authz/*`, `tenancy/jobs.py` | High; I8 and I10 are policy-level (documented, not enforced by code). |
| 04 authorization model | `authz/pdp.py`, `reader.py`, `scopes.py`, `permissions.py`, `access.py`, `guards.py` | High — precedence chain and anti-escalation rules are directly visible in `DefaultPDP`/`AccessControl`. |
| 05 lifecycle | `control/registry.py`, `control/purge.py`, `persistence/strategies/*`, `migrations/runner.py` | High for create/provision/migrate/suspend/archive/deprovision; §6 relocation is a runbook with no implementation (drift D1). |
| 06 strategy matrix | `persistence/strategies/{shared,schema,database,rls}.py` | High for §1–§6 and §8–§9; `hybrid` placement (§7) is expressible via handles but has no dedicated code. |
| 07 implementation design | the whole package | Structural drift in the design-time file map (drift D2). |

## Drift: design docs vs shipped code

### D1. The relocation runbook has no implementation

`docs/jdlib/05` §6 describes a full procedure — lock, `TenantRelocation(status=pending)`,
destination provisioning, quiesce via write-fence transition, **drain bounded by
`relocation_drain_grace` (default 2× the max transaction duration)**, copy, verify,
atomic flip, rollback, per-phase audits. In the shipped code there is:

- the `tenant_relocations` table (phases, partial unique index),
- `CRITICAL_RELOCATION_PHASES` and the `_relocating()` check inside
  servability/writability,
- `privileged_bypass()` for capability `relocation.manage`,
- `RelocationPhaseError` (never raised).

There is no lock step, no drain, no `relocation_drain_grace` config key (the config
model has no such field), and no relocation command. Treat §6 as an operator
runbook you execute by hand with your own tooling.

The doc also claims "the write fence is checked at session/transaction start by
`TenantSession`, `UnitOfWork`, and tenant job execution". In code only
`UnitOfWork` consults the fence (`TenantSession` has no fence parameter), so a
consumer that opens a `TenantSession` directly gets scoping but **not** the
lifecycle gate — the intended pattern is to always go through `UnitOfWork`.

### D2. The design-time file map differs from the implemented layout

`docs/jdlib/07` §3 lists files that do not exist and misses files that do:

| Doc says | Reality |
|---|---|
| `control/access.py` (AccessControl, ownership validation) | `authz/access.py`; ownership helpers are `models/base.py::ownership_constraints()` |
| `authz/ownership.py` | does not exist |
| `persistence/events.py` | event handlers live in `persistence/session.py` |
| `audit/base.py`, `audit/sinks.py`, `audit/recorder.py` | `control/audit.py` (sinks + adapter), `models/audit.py`, `models/audit_recorder.py` |
| `testing/fixtures.py`, `testing/fakes.py` | `testing/pytest_plugin.py` + `testing/assertions.py` (fakes are in `tests/support/`) |
| `control/registry.py` exports `DeprovisionMode`, `MigrationState` | `DeprovisionMode` is in `persistence/strategies/deprovision.py`; migration state is `MigrationStatus` in `control/enums.py` |
| `authn/apikey.py` exports `KeyParser` | exports `parse_api_key`, `ParsedApiKey`, `hash/verify_api_key_secret` |
| — | `_uuid.py`, `persistence/models.py`, `authz/resource_types.py` are missing from the doc's map |
| `lint.py` "metadata lint L1-L19" | 12 rules emitted (L1–L4, L6, L9, L11–L13, L15, L17, L19) |

Use [directory_structure.md](../directory_structure.md) for the real tree.

### D3. Lint coverage is partial

`docs/jdlib/02` §6 lists L1–L19. The linter emits L1, L2, L3, L4, L6, L9, L11,
L12, L13, L15, L17, L19. L5/L10 are folded into L9/L2; L7/L8/L14/L16 are
write-path checks; L18 appears in neither. Details:
[invariants_and_lint.md](invariants_and_lint.md).

### D4. Seeding is a hook, not a seed migration

`docs/jdlib/02` §7 lists a "Seed migration (built-in roles + TenantSetting
defaults)". In code, provisioning calls the injected `SeedHook` (`_NoopSeedHook`
by default) — the library does not ship built-in roles or settings defaults.

### D5. Purge vs destroy, and archive's meaning

`docs/jdlib/05` §5 distinguishes `purge` and `destroy`; the strategies implement
them identically (see [limitations_and_edge_cases.md](../limitations_and_edge_cases.md) §3).
Also, in code `deprovision(mode=archive)` is just a transition to `archived`
(with child-detach handling), not a data-retention operation.

### D6. Small naming mismatches

- `docs/jdlib/04` §8 "role templates" — no templates ship; the reference role set
  exists only as test fixtures (`tests/integration/test_role_action_matrix.py`).
- `docs/jdlib/07` §9/§10 contain inline comments about future additions (e.g.
  carrying `user_id` on envelopes for USER principals); those are notes, not
  behaviour.
- `docs/jdlib/07` describes a `strategy_matrix` and `rls_on_off` testing fixture
  set; the shipped pytest plugin offers only `jdlib_database_url`,
  `jdlib_schema`, `jdlib_models`, `jdlib_engine`, `jdlib_session_factory`. The
  matrix lives in this repo's own `tests/integration/strategy_support.py`, not in
  the consumer kit.

### D7. The documented config model is larger than the implemented one

`docs/jdlib/07` §5 shows a `TenancyConfig` with `control_dsn: SecretStr`
(required), `default_strategy`, `strategies`, `pools` (`max_targets`, `cap`,
`health_check_interval`), `rls.owner_role`, `resolvers: list[ResolverName]`,
`api_keys.pepper`, `secrets`, and `strict_schema`. The implemented model
(`config.py`) has: optional `control_dsn`, required `context` (`signing_key`,
`envelope_ttl`, `operator_ttl`, `allow_test_contexts`), `resolvers` as a
`ResolverConfig` object (`order`, `base_domain`, `path_prefix`, `header_name`,
`jwt_claim`), optional `oidc`, `api_keys.prefix` only, and `rls.enabled`/`app_role`
only.

Consequences to be aware of: there is no config-driven default strategy (the
caller passes `strategy=` to `create`), no pool/capacity settings (pass an engine
you configured), no `api_keys.pepper` (the secret is the token's own random
component, hashed with Argon2id), no `rls.owner_role`, and no schema-strictness
flag. `docs/jdlib/07` §6's claim that invalid resource-type definitions fail at
*startup* is likewise not implemented — they fail at registration time
(`ResourceTypeDefinition.__post_init__`), which is whenever your app registers
them.

## Planning artifacts worth reading

`docs/superpowers/plans/` is a per-phase history of how the library was built
(foundation → context → persistence → registry → authorization → access control →
authentication → strategies → integrations). They are useful for *intent*
(why a rule exists) and misleading for *state* (several describe work that was
later reshaped, e.g. the audit package and the file map). Read them with the code
open.

## Keeping this KB honest

When the code changes, the pages that claim behaviour must be re-derived:

| Claim type | Source of truth |
|---|---|
| Public surface, config fields, protocols | `src/jdlib/**` (and this KB's module pages) |
| Table columns/constraints | regenerate [schema_tables.md](schema_tables.md) from the metadata |
| Lint rules | `lint.py` |
| Error hierarchy, HTTP mapping | `errors.py`, `tenancy/middleware.py` |
| Test counts, gates | run `pytest -q`, `ruff check .`, `mypy src/jdlib` |
