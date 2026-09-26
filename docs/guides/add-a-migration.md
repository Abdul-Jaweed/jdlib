# Add a migration

Two planes, two chains, one rule: a migration is applied by an operator command, never by a process
starting up.

## Which plane

| The change | The chain | Applied by |
|---|---|---|
| control-plane tables (tenants, placements, platform audit) | `jdlib.migrations.runner` | `jdlib db upgrade-control` |
| tenant-plane tables | the tenant plane's own chain | `jdlib db upgrade-tenants` |

A change that adds a column to a tenant's table belongs to the tenant plane even though the model may
live beside the control-plane models.

## Writing it

* **Idempotent.** `upgrade-tenants` is designed to be re-run; a revision that fails halfway and
  cannot be re-applied turns a deploy into an incident.
* **Per tenant plane.** A schema-per-tenant deployment applies the revision to every schema, so a
  revision that assumes it is alone in the database is a defect.
* **Paired with its policy.** A new tenant table needs its row-level-security policy installed —
  `jdlib rls install` — and verified, `jdlib rls verify`.

## Running it

```bash
jdlib db upgrade-control --database-url "$JDLIB_CONTROL_DSN"
jdlib db upgrade-tenants
jdlib rls verify --database-url "$JDLIB_CONTROL_DSN" --schema tenant_acme
```

## Test it

| Test | What it proves |
|---|---|
| the revision applies to a fresh database | the forward path works |
| the revision applies twice | idempotence, which the operator command relies on |
| a tenant-plane revision applies per schema | the multi-plane case |
| the policy exists after the migration | isolation is installed, not assumed |

## What goes wrong

| Symptom | The cause |
|---|---|
| a worker migrated the database on start | the migration ran in process start rather than an operator step |
| one tenant's schema has the column and another's does not | the revision went into the control-plane chain |
| the table exists with no policy | `rls install` was not run — `rls verify` is what catches it |
