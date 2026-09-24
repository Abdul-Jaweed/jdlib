# jdlib Knowledge Base

A deep, source-derived technical knowledge base for **jdlib** — a reusable
multi-tenant foundation for PostgreSQL + SQLAlchemy applications
(`pyproject.toml`, version `0.1.0`).

Everything here was written by reading the repository at commit `a30601d`
(`main`), not from filenames or the README alone. Claims are labelled by how
they were established:

| Label | Meaning |
|---|---|
| **Documented** | Stated in `README.md` or `docs/`; may or may not match the code. |
| **Verified** | Confirmed by executing something (test suite, linter, interpreter). |
| **Inferred** | Read out of the source itself (`src/jdlib/...`) and traceable to a line. |
| Unlabelled prose | Ordinary explanation; every statement is traceable to a file referenced nearby. |

Where the design documents (`docs/`) and the source disagree, the source wins
and the divergence is recorded in
[reference/design_docs_map.md](reference/design_docs_map.md). That file is the
first place to look before trusting any *Documented* claim.

## Verification snapshot

| Check | Command | Result (Verified) |
|---|---|---|
| Test suite | `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python.exe -m pytest -q` | `568 passed in 46.98s` |
| Lint | `.venv/Scripts/python.exe -m ruff check .` | `All checks passed!` |
| Types | `.venv/Scripts/python.exe -m mypy src/jdlib` | `Success: no issues found in 64 source files` |
| Size | `wc -l` over `src/` / `tests/` | 7,447 / 13,023 lines |

That snapshot is the one taken at `a30601d`. **Current** (phase 11, with the
local Kong/Cerbos/ZITADEL stack up and its `JDLIB_INFRA_*` variables exported):

| Check | Command | Result (Verified) |
|---|---|---|
| Test suite | `.venv/Scripts/python.exe -m pytest -q -W error` | `1215 passed, 6 skipped in 69.22s` — the six skips are the documented Tyk coprocess limitation |
| Lint | `.venv/Scripts/python.exe -m ruff check .` | `All checks passed!` |
| Types | `.venv/Scripts/python.exe -m mypy src/jdlib` | `Success: no issues found in 101 source files` |
| Infrastructure layer | `.venv/Scripts/python.exe -m pytest -q tests/infra -rs` | `29 passed, 6 skipped` against real Cerbos 0.37.0, Kong 3.6, ZITADEL, PostgreSQL 16 and an OpenTelemetry collector |
| Security gates | `.github/workflows/ci.yml` job `security` | dependency scan, full-history secret scan, SAST, SBOM and a clean-install smoke test — `docs/security/ci-security.md` |

## What changed after `a30601d` (the security-hardening programme)

The documents below still describe the library's structure, but the programme
added a security layer on top and changed behaviour in places. A reader who
needs the current state should use, in this order:

- `docs/security/` — one document per hardening phase (authentication,
  authorization, gateway, audit, observability, adversarial review, compliance,
  CI), each carrying its own `Status:` line.
- `SECURITY.md` — responsibilities, what is deliberately left to a deployment,
  known limitations, how to report a vulnerability.
- `docs/threat-model/README.md` — assets, trust boundaries and twenty threats
  with the control, the test and the residual-risk owner.
- `docs/compliance/README.md` and `docs/operations/README.md` — the
  assessor-facing and operator-facing views.
- `JDLib-Architecture.md` — the module inventory, public interfaces and flows,
  synchronised with the programme.
- `CHANGELOG.md` — the programme phase by phase with commit SHAs.

Named in one place: `jdlib.security` gained `compliance`
(`CONTROL_REGISTRY` with 19 controls over 7 frameworks, evidence collectors,
posture evaluation) and a `security` CLI group; `jdlib.persistence.strategies.rls`
gained `RlsInspection`/`inspect_rls` with `verify_rls` built on them; the package
now installs a `jdlib` console script; and the audit trail's attribution and
timestamp rules became fail-closed.

The integration suite starts a real PostgreSQL (`postgres:16`) via
testcontainers, so the 568 passes include live isolation-strategy behaviour, not
just mocks.

## Map of this knowledge base

**Orientation**

- [project_overview.md](project_overview.md) — what jdlib is, the problem it
  solves, capability inventory, status, non-goals.
- [architecture.md](architecture.md) — two planes, layering, component map,
  dependency rules, enforcement core.
- [directory_structure.md](directory_structure.md) — annotated repository tree.
- [dependencies.md](dependencies.md) — runtime/optional/dev dependencies and how
  each is actually used.

**Modules** (one document per package)

- [modules/README.md](modules/README.md) — module index and layering table.
- [modules/foundation.md](modules/foundation.md) — `errors`, `config`,
  `context`, `_uuid`, `lint`.
- [modules/control_plane.md](modules/control_plane.md) — `control/*`.
- [modules/models.md](modules/models.md) — `models/*` (tenant plane).
- [modules/persistence.md](modules/persistence.md) — `persistence/*` core.
- [modules/strategies.md](modules/strategies.md) — `persistence/strategies/*`.
- [modules/tenancy.md](modules/tenancy.md) — `tenancy/*` (resolution,
  middleware, jobs).
- [modules/authn.md](modules/authn.md) — `authn/*`.
- [modules/authz.md](modules/authz.md) — `authz/*`.
- [modules/migrations.md](modules/migrations.md) — `migrations/*`.
- [modules/integrations.md](modules/integrations.md) — `integrations/*`.
- [modules/testing_kit.md](modules/testing_kit.md) — `testing/*`.

**API surface**

- [api/README.md](api/README.md) — API index and stability rules.
- [api/public_api.md](api/public_api.md) — the 13 top-level exports.
- [api/data_access.md](api/data_access.md) — `UnitOfWork`, `TenantSession`,
  `TenantRepository`, `raw_sql`.
- [api/fastapi.md](api/fastapi.md) — middleware, dependencies, error mapping.
- [api/cli.md](api/cli.md) — `jdlib` Typer commands.
- [api/extension_points.md](api/extension_points.md) — protocols to implement.

**Behaviour**

- [data_flow.md](data_flow.md) — how data moves through the system.
- [execution_flows.md](execution_flows.md) — end-to-end traces of the main
  workflows.
- [configuration.md](configuration.md) — every config field and env var.
- [testing.md](testing.md) — test architecture, fixtures, what is covered.
- [examples.md](examples.md) — copy-pasteable usage examples.
- [design_decisions.md](design_decisions.md) — why the code looks the way it
  does, with evidence.
- [error_handling.md](error_handling.md) — error hierarchy, mapping, fail-closed
  semantics.
- [limitations_and_edge_cases.md](limitations_and_edge_cases.md) — known gaps,
  drifts, sharp edges.
- [development_guide.md](development_guide.md) — workflow, commands, how to
  extend safely.

**Reference**

- [reference/schema.md](reference/schema.md) — the two planes, conventions, table
  map, RLS policy shape, deletion order.
- [reference/schema_tables.md](reference/schema_tables.md) — generated
  column/constraint/index tables for all 22 tables.
- [reference/invariants_and_lint.md](reference/invariants_and_lint.md) — the
  I1–I13 isolation invariants and L1–L19 lint rules, each mapped to the code
  that implements it.
- [reference/design_docs_map.md](reference/design_docs_map.md) — inventory of
  the pre-existing design docs plus the documented-vs-implemented drift list.

## How to keep this current

1. When a module changes, update its page under `modules/` — that page is the
   canonical description; other documents link to it rather than repeat it.
2. When a documented-vs-code divergence is fixed, delete the row in
   [reference/design_docs_map.md](reference/design_docs_map.md).
3. Re-run the three verification commands above and refresh the snapshot table
   when behaviour changes.
