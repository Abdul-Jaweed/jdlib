# Development Guide

How to work on jdlib itself (as opposed to building an application on it).

## Environment

```bash
cd J:/ai-agents-resources/jdlib

# interpreter: the repository venv (Python 3.12.10)
.venv/Scripts/python.exe -V

# full suite (Docker required for the testcontainers fixtures)
TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python.exe -m pytest -q

# fast loop
.venv/Scripts/python.exe -m pytest tests/unit -q

# gates, both clean at commit a30601d
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m mypy src/jdlib
```

Set `JDLIB_TEST_DATABASE_URL` to skip testcontainers and use an existing
PostgreSQL 15+ instance (the `citext` extension must be installable). On Windows,
`TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` is required because the container IP is
not routable from the host.

## Conventions enforced by tooling

| Tool | Config | Implication for new code |
|---|---|---|
| ruff | `line-length = 100`, `target-version = "py312"`, select `E,F,I,UP,B,SIM` | Import order is enforced (`I`); `UP` pushes modern syntax (`X \| None`, `StrEnum`); `SIM` rejects needless branches. |
| mypy | `strict = true`, `files = ["src/jdlib"]`, `python_version = "3.12"` | Every function in `src/` needs annotations; `disallow_untyped_defs`-class errors are real failures. Tests are *not* type-checked. |
| pytest | `asyncio_mode = "auto"`, `testpaths = ["tests"]` | Async tests need no marker. |
| hatchling | `packages = ["src/jdlib"]` | src layout; new subpackages must be importable (see the namespace-package note below). |

## Style conventions seen throughout the codebase

- **Frozen, slotted dataclasses for value objects** (`TenantContext`, `Principal`,
  `PrivilegeContext`, `TenantRecord`, `RequestInfo`, `ParsedApiKey`, `Binding`,
  `MatchedRule`, `Decision`, `LintIssue`), `StrEnum` for enums.
- **Protocols over ABCs** for ports (`WriteFence`, `IsolationStrategy`,
  `PrincipalProvider`, `TenantResolver`, `AccessReader`, `PlatformAudit`,
  `SecretProvider`, `Authenticator`, `RawSqlAuditor`, `Clock`, `SeedHook`,
  `Migrator` duck-type). Implementing classes never inherit them.
- **`from __future__ import annotations`** at the top of every module; keyword-only
  arguments (`*`) once a signature has more than two positional parameters.
- **Typed errors, never bare exceptions**: raise a `JdlibError` subclass with a
  message that names the sanctioned alternative (`"use raw_sql for text
  statements"`).
- **Docstrings state the contract, not the implementation**: class/method
  docstrings explain why a guard exists and what a caller must do (e.g.
  `DatabasePerTenantStrategy.invalidate`, `integrations/fastapi.py`'s TOCTOU note).
- **No `print`** outside `integrations/cli.py`; logging is the consumer's job.
- **Secret material never reaches a message.** Use `SecretStr`, audit reason tags
  (`invalid_api_key`) and exception class names.
- Commit messages follow conventional commits, imperative, scoped: `fix: typed
  error for unknown placement strategy`, `feat: fastapi and cli integrations`,
  `chore: close tracked debt (...)`.

## Where to change what

| Task | Files | Watch out for |
|---|---|---|
| New tenant-plane model | `src/jdlib/models/*.py` or your own app models | Must subclass `TenantBase` + `TenantRouted`; use `ownership_constraints()` if it can be owned by org/team; run `schema lint --rls`. |
| New control-plane table | `src/jdlib/control/models.py` | Add to `ControlBase`; give it a `tenant_id` if tenant-scoped (L1/L4/L9); never inherit `TenantRouted` (L19); add an index or partial unique as needed. |
| New permission | `src/jdlib/authz/permissions.py` (builtins) or your catalog | Declare `allowed_scopes`; add a role-matrix row in `tests/integration/test_role_action_matrix.py`. |
| New resource type | consumer code via `ResourceTypeRegistry` | Namespace must match its permissions (`InvalidResourcePermission`). |
| New isolation strategy | `src/jdlib/persistence/strategies/` | Implement all five protocol methods; declare `capabilities`; register in the strategy mapping and extend `_validate_target_handle` if the handle format differs. |
| New raw-SQL rule | `src/jdlib/persistence/rawsql.py` | Add the reject **and** a rule-by-rule test in `tests/unit/test_rawsql.py`; keep `PRIVILEGED` semantics (predicate waived, structure kept). |
| New lint rule | `src/jdlib/lint.py` | Emit `LintIssue(rule, table, message)`; add a positive and a negative test in `tests/unit/test_lint.py`. |
| New error type | `src/jdlib/errors.py` | Add to `__all__`, decide its HTTP status in `tenancy/middleware.py::http_status_for` (order matters), and document the raise site in this KB's [error_handling.md](error_handling.md). |
| New config field | `src/jdlib/config.py` | Give it a default where possible (required fields break `TenancyConfig()` construction), document the env var in [configuration.md](configuration.md). |
| New CLI command | `src/jdlib/integrations/cli.py` | Accept `--database-url`/`--json`; catch `JdlibError`/`SQLAlchemyError` and exit 1; dispose any engine you open. |
| New audit action | wherever you call `self._audit.record(action=...)` | Use the `noun.verb` style already in use (`tenant.activated`, `role.created`, `privilege.operator`) and note it in this KB. |

## Architectural rules to preserve

1. **Do not add a bypass to `TenantSession`.** No flag, no keyword, no "admin
   session". Cross-tenant work belongs in `TenantPlanePurger` (system capability)
   or `platform.raw_sql` (audited).
2. **Keep placement out of application code.** Strategies provide connections;
   nothing above `SessionRouter` may branch on `context.strategy`.
3. **Adapters stay thin.** `integrations/*` translate; policy lives in
   `context.py`, `authz/*`, `control/*`.
4. **Optional dependencies stay optional.**
   `tests/unit/test_public_api.py::test_import_does_not_pull_optional_dependencies`
   will fail if `jdlib/__init__` (transitively) imports fastapi/typer.
5. **Any new authority must be audited and capsuled.** New privileged operations
   need a capability name, a `PrivilegeAudit` record, and a test that an
   unprivileged caller is refused.
6. **Fail closed.** When unsure about a statement, a reference or a credential,
   raise — do not "best effort" it.

## Testing conventions

- Unit tests (`tests/unit/`) must not need Docker or a database; use the fakes in
  `tests/support/context_fakes.py` (`FrozenClock`, `StaticPrincipals`,
  `DictTenants`, stubs, `RecordingPrivilegeAudit`).
- Integration tests (`tests/integration/`) get a real PostgreSQL from the
  fixtures in `tests/integration/conftest.py`; put new strategy/RLS coverage in
  the relevant `*_db.py` file and add the case to `test_strategy_matrix.py` when
  it must hold for **every** placement.
- Isolation claims get an assertion from `jdlib.testing`: `assert_tenant_isolated`
  / `assert_cross_tenant_write_rejected` (they are the executable form of I2/I4).
- Mutation/authority claims get a row in the role × action matrix rather than a
  one-off test, so an added permission shows up as an explicit allow/deny pair.
- When you fix a bug, add the regression test in the same commit (the git log is
  consistent about this: every `fix:` commit carries test changes).

## Namespace-package quirk

`src/jdlib/control/` and `src/jdlib/models/` have **no `__init__.py`** (implicit
namespace packages), while `authn`, `authz`, `persistence`, `persistence/strategies`,
`tenancy`, `testing` and `integrations` do. Imports work in both directions, but
tools that walk packages via `__init__.py` (some import sorters, coverage configs,
`pkgutil.iter_modules` in the classic sense) will skip those two directories. If
you add tooling, either handle namespace packages or add the missing files — but
note that adding `__init__.py` files changes nothing about imports, only about
tooling.

## Release state

- Version `0.1.0` in `pyproject.toml` and `jdlib/__init__.py`; no changelog, no
  tag, no publish workflow.
- CI (`.github/workflows/ci.yml`) runs on push/PR: install `.[dev]`, `ruff check .`,
  `mypy src/jdlib`, `pytest -q` on Python 3.12 with the runner's Docker daemon.
  No coverage gate, no PostgreSQL matrix, no Windows/macOS job.
- `JDLib-Architecture.md` is untracked at the repo root; `knowledge_base/` (this
  documentation set) is also untracked as of commit `a30601d`. Decide whether
  either should be committed — they are large and neither is referenced by code.
