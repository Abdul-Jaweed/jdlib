# CLI

```bash
pip install "jdlib[cli]"
jdlib --help
```

The console script is the **operator** surface: the commands that create tenants, migrate planes and
install isolation policies. They are deliberately not part of process start — a process that migrates
while it starts does so on every worker, and a provisioning step that a restart retries is the
failure the split avoids.

## Commands

| Command | What it does |
|---|---|
| `jdlib tenant create` | create a tenant record in the control plane |
| `jdlib tenant provision` | provision a tenant's plane and run its migrations |
| `jdlib tenant list` | list tenants with their placements |
| `jdlib db upgrade-control` | upgrade the control plane to the head revision |
| `jdlib db upgrade-tenants` | upgrade every registered tenant to its desired revision |
| `jdlib rls install` | install and verify tenant isolation policies on one schema |
| `jdlib rls verify` | verify tenant isolation policies on one schema |
| `jdlib schema lint` | lint the framework control and tenant metadata |

## The shape of an operator step

```bash
export JDLIB_CONTROL_DSN="postgresql+psycopg://jd:secret@localhost:5432/app"

jdlib db upgrade-control --database-url "$JDLIB_CONTROL_DSN"
jdlib tenant create --slug acme --name "Acme Inc" --strategy shared --target-handle default
jdlib tenant provision <tenant-id>          # provisions the placement, migrates, activates
jdlib rls verify --database-url "$JDLIB_CONTROL_DSN" --schema tenant_acme
jdlib schema lint
```

Every step is idempotent: running `provision` twice does not create a second plane, and
`upgrade-control` to the head revision when it is already there is a no-op that reports so.

## Why an operator surface is part of the library

Because the alternative is every deployment writing these four steps by hand, in a different order,
with different idempotence. The commands call the same code the programmatic path calls
(`jdlib.migrations.runner.MigrationRunner`, `jdlib.control.registry.TenantRegistry`), so an operator
who prefers Python is not on a second implementation:

```python
from jdlib.migrations.runner import MigrationRunner

MigrationRunner(url).upgrade_control()
```

## Posture

* The CLI is **not** reachable from a request path: it is a separate process with its own
  credentials, and the control plane's tables are operator API by design.
* It reads the same `JDLIB_*` configuration as the application, or takes an explicit
  `--database-url`.
* It never prints a secret: connection strings are redacted in output, and a failure names the
  command and the reason rather than the DSN.
