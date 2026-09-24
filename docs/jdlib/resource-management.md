---
page: resource-management
sources:
  - src/jdlib/resources
  - docs/jdlib/capabilities/resources.md
---
# Resource management

A **handle** names a resource; **hydration** turns it into a `ConnectionConfig` - what to connect
to, which credential version produced it, and for which tenant. Full page:
[`capabilities/resources.md`](capabilities/resources.md).

## The properties that matter

- The cache key includes the credential version, so a rotated credential produces a different key
  and a rebuild rather than a stale target.
- Hydration is not a second enforcement point: a wrong-tenant hydration is asserted as
  *isolation*, not as a refusal.
- A target may carry its own connection settings (`server_settings`), because a schema is part of
  what the target is and asyncpg will not take one from the DSN.
- `ConnectionConfig` renders without its target, so anything that logs a connection cannot leak
  credential material by accident.

## Refusals

`ResourceHydrationError` covers every path: no bound security context, a context without a tenant,
a tenant that is not permitted, a resource not authorized for the tenant, an expired privilege, and
a handle with no registered credential - there is no fallback to a shared target.
