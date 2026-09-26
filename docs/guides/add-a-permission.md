# Add a permission

A permission is a name the library knows and a rule your policy engine decides. Adding one touches
three places, and the third is the one people forget.

## 1. Name it in the catalog

```python
from jdlib.authz.permissions import PermissionCatalog

catalog = PermissionCatalog.with_builtins()
catalog.register("invoice:create", description="Create an invoice in the caller's tenant")
```

The catalog is what makes a permission *exist*: the guard refuses a declaration that names something
the catalog does not have, so a typo is a startup failure rather than a route that is silently
unguarded.

## 2. Decide it in your policy

The library asks the engine; the engine answers. A Cerbos policy for the new permission lives in your
policy repository, not here — `jdlib.security.authz.cerbos.CerbosPDP` sends the question and reads the
answer:

* **allowed** → the operation proceeds;
* **denied** → refused and audited;
* **degraded** (unreachable, unreadable) → refused. An outage is never a permission.

## 3. Declare it where it is used

```python
@require("invoice:create")
async def create_invoice(...): ...
```

Every entry point declares its own: a route on the HTTP surface, a tool on the MCP surface. The
enterprise example walks its routes and tools and fails when one of them needs a permission it does
not declare — a check worth copying, because the failure it prevents is invisible in review.

## 4. Test it

```python
async def test_create_is_denied_for_a_read_only_principal(...):
    """The decision is deny, the handler does not run, and the denial is audited."""
```

## What goes wrong

| Symptom | The cause |
|---|---|
| a route is reachable by anyone | the permission was declared but not added to the catalog, or the route has no declaration at all |
| a new permission is allowed for everybody | the policy has no rule for it and the engine's default is permissive — a policy default is a security decision |
| a permission works on HTTP but not MCP | only one of the two surfaces declares it |
| an outage makes everything allowed | the PDP is not wired, or a degraded answer is being treated as an allow — it must be a refusal |
