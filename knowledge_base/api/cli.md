# API: CLI

Requires `pip install "jdlib[cli]"`. Internals are in
[../modules/integrations.md](../modules/integrations.md); this page is the
operator-facing contract.

Expose it from your own entry point (the shipped `pyproject.toml` does not):

```toml
[project.scripts]
jdlib = "jdlib.integrations.cli:app"
```

Every command accepts `--database-url` (falling back to `$JDLIB_CONTROL_DSN`) and
`--json`.

## Commands

```bash
# tenant lifecycle
jdlib tenant create --slug acme --name "Acme Inc" \
    --strategy shared --target-handle default [--region eu-west-1] [--shared-schema public]
jdlib tenant provision <tenant-id>
jdlib tenant list

# migrations
jdlib db upgrade-control
jdlib db upgrade-tenants [--shared-schema public]

# row-level security (shared placement)
jdlib rls install --schema public --app-role jdlib_app
jdlib rls verify  --schema public --app-role jdlib_app

# metadata invariants
jdlib schema lint [--rls]
```

| Command | Prints (non-JSON) | Notes |
|---|---|---|
| `tenant create` | `id=… slug=… status=provisioning` | Validates slug format/uniqueness and the target handle; idempotent for the same placement, `ProvisioningError` for a different one or a handle already owned by another tenant. |
| `tenant provision` | `id=… slug=… status=active` | Runs strategy provisioning → migrations → seed hook → version check, then activates. Only `shared` and `schema` strategies are registered by the CLI; a `database` placement needs the database strategy registered programmatically (its `target_handle` resolves through a `SecretProvider` the CLI does not have). |
| `tenant list` | one row per tenant: `id slug status strategy target_handle` | Ordered by slug. |
| `db upgrade-control` | `plane=control status=upgraded` | Creates `jd_control` if missing, then Alembic upgrades the control chain. |
| `db upgrade-tenants` | one `id … status=upgraded` row per tenant | Iterates **all** tenants and calls `registry.migrate`; a failed migration suspends an active tenant with `migration_failed`. |
| `rls install` | `schema=… app_role=… status=installed` | Emits policies for every `TenantRouted` table of the *framework* metadata, then verifies (fails closed on a partial deployment). The engine used is bound to `<schema>, public`. |
| `rls verify` | `… status=verified` | Verification only. |
| `schema lint` | `status=clean issues=0` | With issues: one `L<n> <table>: <message>` line per issue on stderr, exit 1. `--rls` also enforces L13. |

## Exit codes and output

- `0` — success.
- `1` — a `JdlibError` or `sqlalchemy.exc.SQLAlchemyError` occurred
  (`error: <message>` on stderr), a bad/missing `--database-url`
  (`typer.BadParameter`), or lint found issues.
- `--json` serializes the payload with `json.dumps(..., default=str)` — handy for
  scripting; without it, output is `key=value` pairs (one line per row for lists).

## What the CLI deliberately does not do

- It does not expose arbitrary raw SQL, tenant data reads, or authorization
  administration (`AccessControl` has no CLI surface) — the CLI is an operator
  subset, and tenant **administration** is intentionally narrower than tenant
  **data access** (`docs/jdlib/04` §6).
- It does not offer `deprovision` yet: deprovisioning must be driven through
  `TenantRegistry.deprovision(...)` in code.
- It does not manage `database`-placement tenants (no secret resolution).
