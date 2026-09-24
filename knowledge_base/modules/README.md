# Modules

> **Status (refreshed in phase 11).** This document was written at commit
> `a30601d`, before the security-hardening programme (phases 1-11). Its
> structure and design explanations still hold, but the security-relevant
> truth lives in the current documents: `docs/security/`, `SECURITY.md`,
> `docs/threat-model/`, `docs/compliance/`, `docs/operations/` and
> `JDLib-Architecture.md`. Where this document and those disagree, they win.
> The front door (`knowledge_base/README.md`) carries the current snapshot.

The shipped package is 64 modules under `src/jdlib`. Each page below documents
one package: purpose, files, public types, behaviour, and gotchas. Read
[architecture.md](../architecture.md) first for the plane/layering model.

| Page | Package / files | One-line purpose |
|---|---|---|
| [foundation.md](foundation.md) | `errors.py`, `config.py`, `context.py`, `_uuid.py`, `lint.py` | Types, config, context creation, ID generation, schema lint — the layer everything else builds on. |
| [control_plane.md](control_plane.md) | `control/*` | Tenant registry, lifecycle state machine, control-plane models, audit sinks, privileged purge. |
| [models.md](models.md) | `models/*` | Tenant-plane base classes and mixins, org/team tree, tenant settings, tenant audit events. |
| [persistence.md](persistence.md) | `persistence/*` (core) | `TenantSession` enforcement, raw SQL validation, unit of work, repository, routing, secrets. |
| [strategies.md](strategies.md) | `persistence/strategies/*` | The three isolation strategies plus deprovision modes and PostgreSQL RLS helpers. |
| [tenancy.md](tenancy.md) | `tenancy/*` | Resolver chain, ASGI middleware, signed-envelope propagation for jobs. |
| [authn.md](authn.md) | `authn/*` | OIDC and API-key authentication, composite chain, wiring adapters. |
| [authz.md](authz.md) | `authz/*` | Permission catalog, resource types, scope chains, PDP, cache, guards, `AccessControl`. |
| [migrations.md](migrations.md) | `migrations/*` | Programmatic Alembic runner and the two baseline revision chains. |
| [integrations.md](integrations.md) | `integrations/*` | FastAPI wiring (`install`, `require`, `get_uow`) and the Typer CLI. |
| [testing_kit.md](testing_kit.md) | `testing/*` | Isolation assertions and the autoloaded pytest fixture plugin. |

## Layer rules (verified from static imports)

```
foundation      errors · config · context · _uuid          no jdlib imports
domain          models · lint · persistence.models          foundation + control.base
persistence     session · rawsql · uow · repository · router · secrets · strategies
control         models · session · registry · purge · audit  persistence + foundation
services        tenancy · authn · authz                     everything above
adapters        integrations · testing                      services + optional deps at import time
```

Notes that matter when changing code:

- `context.py` is the seam everything depends on; keep it free of I/O.
- `models/base.py` imports `control/base.py` for `NAMING_CONVENTION` only — do
  not add more edges from the tenant plane into the control plane.
- `control/registry.py` imports strategy modules for **handle validation**
  (`validate_schema_name`, `validate_database_handle`) and `DeprovisionMode`;
  the strategy implementations themselves are injected as a mapping.
- `integrations/*` are the only modules that import `fastapi`/`typer`;
  `jdlib/__init__.py` deliberately avoids them (test:
  `tests/unit/test_public_api.py::test_import_does_not_pull_optional_dependencies`).
