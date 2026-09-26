# The MCP flow

How a tool call is served, and why it is the same application rather than a second one.

## The chain

```
a client (fastmcp Client)
        │  a request: the bearer credential, and nothing else that identifies
        ▼
McpSecurityBoundary          the library's authenticator → SecurityContext
        │
        ▼
the invocation binds two scopes: security_context_scope(ctx) + context_scope(ctx.require_tenant())
        │
        ▼
McpInvoker: the declared capability → the policy engine (the caller's tenant as the target)
        │  denial → the handler never runs; the refusal is audited
        ▼
the handler                  the *same* services the HTTP routes call
        │
        ▼
the resource / the graph     the same repository; the graph through GraphRunner (a per-call client)
```

## The three properties the surface owns

**The inventory is the declarations.** No tool exists that is not declared; a declaration without a
capability cannot be registered (`McpToolDefinitionError`); and no schema has a slot for an identity
or a statement — asserted by walking the properties, because that is the claim a reader gets wrong.

**The chain is the HTTP path's.** Every collaborator is the object `create_app` built, asserted by
identity. A tool call and a route ask the same engine the same question about the same tenant.

**The graph tools get a runner, not a client.** A graph client *is* a tenant binding, so a surface
serving every tenant cannot hold one: `TenantGraphRunner` opens the calling tenant's client per
statement, and the tenant still comes from the context.

## Why the question is about the tenant scope

A route declares `require("resource:write")` against a *resource* target, because the route knows
which resource it is about. A tool call does not: the resource id is an argument, and authorization
runs before the handler reads it. So the invocation asks about the caller's **tenant scope** with the
tool's capability — which is why the policy set carries those capabilities on the scope rules, and
why the first live call answered `no_allow` until it did.

## Serving it

```
python -m examples.enterprise.app.mcp.asgi        # streamable HTTP
```

Nothing is built at import: the module can be read by tooling that only wants to read it, and the
process refuses to start when the chain's dependencies are missing.

## What the tests assert

`tests/unit/test_mcp_surface.py` (8): the inventory, the capabilities, the closed schemas, the
identity of the collaborators, the enforcer's tenant source on both surfaces' shapes.
`tests/integration/test_mcp_live.py` (6): a real key in the control plane, the live engine, the
denial measured at the row, an undeclared argument refused, cross-tenant invisibility, the graph
tools over the real Neo4j, and a forged key refused.
