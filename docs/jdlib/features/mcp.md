---
guide: mcp
authority: docs/jdlib/capabilities/mcp.md
modules:
  - src/jdlib/integrations/mcp/__init__.py
  - src/jdlib/integrations/mcp/boundary.py
  - src/jdlib/integrations/mcp/errors.py
  - src/jdlib/integrations/mcp/graph_tools.py
  - src/jdlib/integrations/mcp/invocation.py
  - src/jdlib/integrations/mcp/resources.py
  - src/jdlib/integrations/mcp/server.py
  - src/jdlib/integrations/mcp/tools.py
exports:
  - build_mcp_server
  - McpTool
  - McpToolRegistry
  - McpSecurityBoundary
  - McpInvoker
  - graph_tools
  - health_resource
  - graph_schema_resource
  - McpToolDefinitionError
  - McpArgumentsRefusedError
example:
  - examples/enterprise/app/mcp/tools.py
  - examples/enterprise/app/mcp/server.py
  - examples/enterprise/tests/unit/test_mcp_surface.py
test_files:
  - tests/unit/test_mcp_registry.py
  - tests/unit/test_mcp_boundary.py
  - tests/unit/test_mcp_invocation.py
  - tests/unit/test_mcp_adversarial.py
---
# The MCP surface

> **Design authority:** [`docs/jdlib/capabilities/mcp.md`](../capabilities/mcp.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

A second surface over the same application: tool declarations, a boundary that turns a request's credential into a `SecurityContext`, and an invocation chain -- boundary, authorization, handler, audit -- inside the request's context.

## Why it exists

A model-driven surface is a new entry point to the same data, and the temptation is to give it its own shortcuts. The library's shape is the opposite: the same authenticator, the same policy engine, the same services -- so a decision cannot differ by protocol.

## When to use it

When an agent or an automation needs to act on a tenant's data and the action is something an operator would otherwise do by hand: read a resource, list them, archive one.

## When not to use it

As a second API for humans, and for anything whose effect is not reversible or not authorized the same way an HTTP route would be. If a capability has no HTTP route, ask why it should exist as a tool.

## How it works

A `McpTool` declares its name, schema, capability and handler; `McpToolRegistry` refuses one without a declared capability. `McpSecurityBoundary` authenticates the request, resolves the tenant and builds the context; `McpInvoker` then authorizes the declared capability, runs the handler inside the context scope, and audits the outcome. Arguments that name an identity are refused, not read.

## Architecture

`integrations/mcp/tools.py` (declaration and registry), `boundary.py` (identity), `invocation.py` (the chain), `server.py` (`build_mcp_server`), `graph_tools.py` and the resources (the library's own tools). The application supplies the collaborators, not the policy.

## Example

`examples/enterprise/app/mcp/` declares three tools and builds the server from the *same* collaborators `create_app` uses; the example's unit tests assert that identity, and its live layer drives the whole chain -- a real key in the control plane, the live engine, the real database and the real graph.

## Security

The capability is declared and enforced before the handler; a schema that could carry an identity is refused; a denial raises before execution and the audit trail records it. The chain fails closed: no credential, no tenant, no decision, no execution.

## Reliability

Tool calls share the reliability primitives: the invocation has a timeout, and the graph tools go through the same circuit breaker as any other graph access. A degraded policy engine refuses rather than allowing.

## Observability

`mcp.*` span names carry the tool, the outcome and the tenant; the correlation id is the caller's, so a tool call and the HTTP request that started it join.

## Audit

Three events per refused call in the example's trail -- the boundary's `mcp.request`, the engine's decision and the chain's refusal -- and the same vocabulary on the allowed path.

## Configuration

The `mcp` extra (the framework is imported lazily), the transport the deployment chooses, and the tools the application declares. Nothing about the security chain is configurable.

## Testing

The library's MCP suites cover the registry, the boundary, the invocation and the adversarial cases; the example adds an inventory test, a capability test and a live chain.

## Common mistakes

Building a second authenticator for the tool surface; declaring a tool without a capability; accepting an identity argument; skipping the context scope so the handler sees no tenant; letting a tool reach a driver instead of a service.

## Production checklist

Serve the tool surface on the deployment's authenticated transport; keep the tool inventory small and reviewed; watch the denial rate; and make sure the process refuses to start when the chain's dependencies are missing.
