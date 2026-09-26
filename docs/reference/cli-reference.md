# CLI reference

The operator surface. Every command is idempotent, reads the same `JDLIB_*` configuration as the
application (or takes an explicit `--database-url`), and never prints a secret.

```bash
pip install "jdlib[cli]"
jdlib --help
```

## `jdlib tenant`

| Command | Options | What it does |
|---|---|---|
| `jdlib tenant create` | `--slug`, `--name`, `--strategy`, `--target-handle`, `--region` | create a tenant record in the control plane |
| `jdlib tenant provision <tenant-id>` | — | provision a tenant's plane and run its migrations |
| `jdlib tenant list` | — | list tenants with their placements |

```bash
jdlib tenant create --slug acme --name "Acme Inc" --strategy shared --target-handle default
jdlib tenant provision <tenant-id>
jdlib tenant list
```

`create` records the tenant; `provision` builds its placement, migrates it and activates it. They are
separate on purpose: a create that fails halfway leaves a record an operator can inspect, where a
combined step leaves neither.

## `jdlib db`

| Command | What it does |
|---|---|
| `jdlib db upgrade-control` | upgrade the control plane to the head revision |
| `jdlib db upgrade-tenants` | upgrade every registered tenant to its desired revision |

Both are operator steps, never part of process start: a process that migrates on startup does so on
every worker.

## `jdlib rls`

| Command | Options | What it does |
|---|---|---|
| `jdlib rls install` | `--schema`, `--app-role` | install and verify tenant isolation policies on one schema |
| `jdlib rls verify` | `--schema`, `--app-role` | verify tenant isolation policies on one schema |

`verify` is the one to run in a deployment check: a table that exists without its policy is isolated
only by the application's discipline, and this command is what tells the two apart.

## `jdlib schema`

| Command | What it does |
|---|---|
| `jdlib schema lint` | lint the framework control and tenant metadata |

## Posture

* a separate process with its own credentials; the control plane is operator API by design;
* connection strings are redacted in output, and a failure names the command and the reason rather
  than the DSN;
* the commands call the same code the programmatic path calls (`MigrationRunner`, `TenantRegistry`),
  so an operator who prefers Python is not on a second implementation.
