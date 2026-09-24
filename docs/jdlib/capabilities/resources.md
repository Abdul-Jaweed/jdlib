---
capability: resources
namespace: jdlib.resources
errors_module: jdlib.resources.errors
modules:
  - src/jdlib/resources/connection.py
  - src/jdlib/resources/errors.py
  - src/jdlib/resources/handle.py
  - src/jdlib/resources/resolver.py
exports:
  - ConnectionConfig
  - ResourceHandle
  - ResourceHydrationError
  - ResourceResolver
refusals:
  - ResourceHydrationError
test_files:
  - tests/unit/test_resource_hydration.py
test_functions: 11
---
# Resource hydration: from handle to target

## What it is

A handle is a name; hydration turns it into a `ConnectionConfig` - what to connect to, which
credential version produced it, and for which tenant:

```python
resolver = ResourceResolver(secrets=provider, cache=cache, check_tenant=..., tracer=tracer)
config = await resolver.hydrate(ResourceHandle("db/reports"))
```

## The decisions that carry weight

**The cache key includes the credential version.** That is what makes a stale target impossible
rather than merely unlikely: a rotation changes the version, hence the key, hence a rebuild.

**Hydration never becomes a third enforcement point.** A wrong-tenant hydration asserts
*isolation* (the target cannot be reached), not a second authorization decision - the design
keeps one enforcement point, and a test asserts the isolation rather than a refusal.

**A target can carry its own connection settings** (`ConnectionConfig.server_settings`). A schema
belongs to the deployment; asyncpg takes a `search_path` only as a connection setting, and
improvising one at a call site would put deployment knowledge in the query path.

**`ConnectionConfig` renders without its target.** Everything that logs a hydrated connection
therefore cannot leak credential material by accident.

## Evidence

11 test functions across `tests/unit/test_resource_hydration.py`, run with the project gate:

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_resource_hydration.py -q
```

Parametrized cases expand these functions further; the counts here are
functions, which is what the documentation check verifies.

## Limits

Hydration does not health-check the target it produces; a connection that fails fails at the
connector, where the connector's own policy applies.
