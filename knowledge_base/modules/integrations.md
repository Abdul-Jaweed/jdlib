# Module: Integrations (`src/jdlib/integrations/`)

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

Adapters that make jdlib usable from a web framework and from an operator
terminal. Both are **optional**: `fastapi` and `typer` are extras
(`pip install "jdlib[fastapi]"`, `pip install "jdlib[cli]"`), and importing
`jdlib` never pulls them in (asserted by
`tests/unit/test_public_api.py::test_import_does_not_pull_optional_dependencies`).
`integrations/__init__.py` contains only a docstring telling you to import a
submodule to opt into its dependency.

## `fastapi.py` (98 lines)

The module docstring documents the one subtle behavioural contract in the file
(the guard/handler TOCTOU window), reproduced below.

```python
@dataclass(frozen=True, slots=True)
class JdlibContainer:
    session_factory: Callable[[], AsyncSession]
    uow_factory: Callable[[], UnitOfWork]
    enforcer: Enforcer

def install(app, *, factory: ContextFactory, chain: ResolverChain,
            principal_provider: PrincipalProvider,
            container: JdlibContainer | None = None) -> None
```

`install` does three things:

1. stores `container` on `app.state.jdlib_container` (when given),
2. adds `TenantMiddleware` with the supplied factory/chain/principal provider,
3. registers the `JdlibError` exception handler.

Dependencies:

| Name | Returns | Notes |
|---|---|---|
| `get_context()` | `TenantContext` | `current_tenant()` — the context the middleware installed. |
| `get_uow(request)` | `AsyncIterator[UnitOfWork]` | Yields the request-scoped `UnitOfWork` built by the app container. **One `UnitOfWork` per request**; each gets its own session and transaction. |
| `require(permission, target_factory=None)` | a FastAPI dependency | Opens `container.uow_factory()` **inside the guard**, then `container.enforcer.require(permission, target, session=session)`. Raises `PermissionDenied` (→ 403) on denial. Via `target_factory(request)` you can derive a `ResourceRef`/`ScopeRef` from the path. |

`_container(request)` raises `RuntimeError("jdlib container is not installed on
the app")` when the app was not installed with a container — a loud failure
instead of a `None` attribute error.

Error handling: `_handle_jdlib_error` returns
`{"error": <ClassName>, "detail": <message>}` with the status from
`tenancy.middleware.http_status_for`; non-`JdlibError` exceptions are re-raised
unchanged.

### The guard/handler transaction contract (read this before relying on `require`)

> `require` authorizes in its own unit of work: the guard opens
> `container.uow_factory()`, so the `RegistryWriteFence` applies to guarded reads
> too, and a guarded read during a relocation quiesce fails with 423
> (`TenantNotWritable`). The guard authorizes once, in that transaction;
> `get_uow` opens a separate session for the handler, so the guard's decision is
> not re-validated there: a permission revoked after the check is observed only
> by a fresh evaluation in the handler's own session, not by re-checking the
> guard's decision (a TOCTOU window between the guard and the handler).

Practical consequences:

- A handler that mutates data should re-authorize inside its own transaction
  (`authorize(...)` on the handler's session) when revocation latency matters.
- The fence still protects against lifecycle races (suspension, relocation)
  because it is checked when the handler's `UnitOfWork` is entered, not only in
  the guard.

## `cli.py` (337 lines)

A Typer app (`app`) with four command groups; every command accepts
`--database-url` (env fallback `JDLIB_CONTROL_DSN`) and `--json`.

| Group | Command | Effect |
|---|---|---|
| `tenant` | `create --slug --name [--strategy shared\|schema\|database] [--target-handle default] [--region] [--shared-schema public]` | `TenantRegistry.create(...)` → prints `id`, `slug`, `status`. |
| | `provision <tenant-id>` | `TenantRegistry.provision(...)` → prints `id`, `slug`, `status`. The docstring states that only `shared` and `schema` are registered; a `database` placement needs the database strategy registered programmatically. |
| | `list` | Joins `tenants` × `tenant_placements`, ordered by slug, prints `id`, `slug`, `status`, `strategy`, `target_handle`. |
| `db` | `upgrade-control` | `MigrationRunner(url).upgrade_control()`. |
| | `upgrade-tenants` | Iterates all tenants, `registry.migrate(id)` each, prints one row per tenant. |
| `rls` | `install --schema --app-role` | `install_rls(bound_engine, metadata=TenantBase.metadata, app_role=...)` (emits + verifies policies). |
| | `verify --schema --app-role` | `verify_rls(...)` only. |
| `schema` | `lint [--rls/--no-rls]` | `lint_metadata([ControlBase.metadata, TenantBase.metadata], rls_enabled=rls)`; prints one line per issue to stderr and exits 1, otherwise `{"status": "clean", "issues": 0}`. |

Implementation details worth knowing:

- `_registry(engine, url, shared_schema)` builds a `TenantRegistry` with
  `SharedSchemaStrategy(engine, shared_schema)` and
  `SchemaPerTenantStrategy(engine, runner)` plus a `DatabaseAuditSink` — i.e. the
  CLI hard-codes those two strategies and a real audit sink.
- `_async_url()` rewrites plain/psycopg DSNs to `postgresql+asyncpg`;
  `_bound_engine()` additionally sets `search_path` to `<schema>, public`
  (used by the RLS commands).
- `_import_framework_models()` imports control + tenant model modules before
  lint/RLS so the metadata is complete.
- Output is either `key=value` lines (lists print one row per line) or JSON via
  `--json`; failures print `error: <message>` to stderr and exit 1
  (`JdlibError` and `SQLAlchemyError` are both caught).
- Every command opens a fresh engine and disposes it in a `finally` — no global
  engine, no implicit connection reuse.

Entry point: `[project.scripts] jdlib = "jdlib.integrations.cli:app"` (the README
shows adding it to a consumer `pyproject.toml`; the shipped `pyproject.toml` does
not declare it).

## Tests

- `tests/unit/test_cli.py` — help output lists every group, `schema lint` exits 0
  on framework metadata, missing `--database-url` fails cleanly, DB errors fail
  cleanly.
- `tests/integration/test_cli_integration.py` — `tenant create` records a
  platform audit row.
- `tests/integration/test_fastapi_integration.py` — 401/403/404 JSON responses,
  API-key tenant resolution, container dependencies, error-handler mapping.
