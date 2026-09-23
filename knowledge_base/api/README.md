# API

jdlib's API surface is deliberately small and layered. Read the index below
before reaching into a submodule.

| Page | Covers |
|---|---|
| [public_api.md](public_api.md) | The 13 names exported from `jdlib/__init__.py` — the only guaranteed-stable surface. |
| [data_access.md](data_access.md) | `UnitOfWork`, `TenantSession`, `TenantRepository`, `raw_sql`, bulk helpers. |
| [fastapi.md](fastapi.md) | `install`, `JdlibContainer`, `get_context`, `get_uow`, `require`, error mapping. |
| [cli.md](cli.md) | The `jdlib` Typer commands and their flags. |
| [extension_points.md](extension_points.md) | Protocols a consumer implements, and the registries they feed. |

## Stability rules

1. **`jdlib.__all__` is the public API.** A test asserts it is exactly the 13
   names listed in [public_api.md](public_api.md) — adding or removing an export
   is an explicit, test-visible change.
2. **Submodules are "public by convention, not by guarantee".** Everything the
   README and design docs reference (e.g. `jdlib.authz.*`, `jdlib.persistence.*`,
   `jdlib.control.*`, `jdlib.testing`) is importable and used by the shipped
   tests, but only the 13 exports are protected by a test.
3. **Optional dependencies stay optional.** `fastapi`/`typer` are imported only
   by `jdlib.integrations.*`; importing `jdlib` must not import them
   (`tests/unit/test_public_api.py::test_import_does_not_pull_optional_dependencies`).
4. **Only `jdlib.errors.JdlibError` subclasses cross module boundaries.** Driver
   exceptions are mapped at the persistence boundary; adapters are expected to do
   the same.
5. **Unknown attributes are not a compatibility promise.** `_PrivilegeIssuer`
   /`PRIVILEGE_ISSUER`, `_ACCESS_ROW_DELETION_ORDER`, and other underscore-prefixed
   names are internal even when importable.

## Version

`jdlib.__version__ == "0.1.0"` (`jdlib/__init__.py:27`), asserted by
`tests/unit/test_public_api.py::test_version_is_a_string`. The distribution
declares the same version in `pyproject.toml`. There is no changelog file and no
deprecation policy recorded in the repository.
