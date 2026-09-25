---
capability: mcp
namespace: jdlib.integrations.mcp
errors_module: jdlib.integrations.mcp.errors
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
  - McpArgumentsRefusedError
  - McpError
  - McpInvoker
  - McpResource
  - McpSecurityBoundary
  - McpServerUnavailableError
  - McpTool
  - McpToolDefinitionError
  - McpToolExecutionError
  - McpToolRegistry
  - build_mcp_server
  - graph_schema_resource
  - graph_tools
  - health_resource
  - request_from_http
  - tenant_resource
refusals:
  - McpArgumentsRefusedError
  - McpError
  - McpResourceDefinitionError
  - McpServerUnavailableError
  - McpTimeoutError
  - McpToolDefinitionError
  - McpToolExecutionError
test_files:
  - tests/unit/test_mcp_adversarial.py
  - tests/unit/test_mcp_boundary.py
  - tests/unit/test_mcp_graph_tools.py
  - tests/unit/test_mcp_invocation.py
  - tests/unit/test_mcp_observability.py
  - tests/unit/test_mcp_registry.py
  - tests/unit/test_mcp_reliability.py
  - tests/unit/test_mcp_resources.py
  - tests/unit/test_mcp_server.py
test_functions: 89
---

# The MCP surface: a second entry point into the same chain

## What it is

An MCP server that a client can call, built out of the library's existing security model rather
than beside it. Every step of the directive's chain is a collaborator the HTTP surface already
takes, handed to the same code:

```text
MCP client -> FastMCP -> jdlib.integrations.mcp -> Cerbos -> jdlib.graph -> Neo4j
```

The modules, in the order a call meets them:

| Module | What it owns |
|---|---|
| `tools.py` | the declarations: a tool names its capability, or says `public=True` in so many words |
| `boundary.py` | authentication, principal, tenant resolution, request ids — the HTTP edge's own steps |
| `invocation.py` | the chain: declared arguments → authorization → handler → audit, inside both scopes |
| `graph_tools.py` | seven tools over `GraphRepository`; no schema has an identity or a statement slot |
| `resources.py` | read-only tenant, schema and health payloads that carry no authority and no internals |
| `server.py` | the factory: one FastMCP tool per declaration, fastmcp imported only when one is built |
| `errors.py` | one refusal per outcome, all `JdlibError` |

## The security properties, and where each one is proven

| Property | Where it is proven |
|---|---|
| A tool with no declared capability cannot be constructed | `test_mcp_registry.py` — the gate is in the type, and the mutation check removes it |
| The boundary reuses the HTTP chain **by identity**, not resemblance | `test_mcp_boundary.py` — the chain sees the provider's own principal object |
| A denial raises before the handler is reached, and the handler's call count is the proof | `test_mcp_invocation.py`, `test_mcp_adversarial.py` (the non-execution table) |
| A refusal is recorded before it is raised, attributed to the caller | `test_mcp_invocation.py`, `test_mcp_observability.py` |
| No schema has anywhere to put an identity or a statement | `test_mcp_graph_tools.py`, swept again **through the wire** in `test_mcp_adversarial.py` |
| The advertised schema is enforced by the library, not merely stated | `test_mcp_server.py` — fastmcp 4.0.10 advertises `additionalProperties: false` and does not enforce it |
| A failure is recorded by the error's class, never its text | `test_mcp_observability.py`, `test_mcp_adversarial.py` |
| Drain, saturation and deadlines all refuse before the handler runs | `test_mcp_reliability.py`, `test_mcp_adversarial.py` |
| The surface is the inventory: no tool exists on the wire that is not declared | `test_mcp_server.py` |
| The extra stays optional and the core import never needs it | `test_mcp_server.py` — a subprocess with the module blocked, plus a control case |

## Limits, stated rather than implied

* **§26's metric names are not minted here.** The library's observability seam is spans plus the
  audit trail; metrics are the collector's derivation from those spans in the lab. Naming metrics
  with nothing to emit them would be a vocabulary with no producer — the thing the vocabulary pin
  exists to catch.
* **`mcp.dependency` is not a second span.** The dependency's own span is `graph.statement`, and
  one name per thing beats two names to keep in step.
* **`graph_search` is deliberately absent.** The repository has no property search, and a tool
  taking property *names* would re-open the identifier-position class the graph phase closed.
* **A deadline claims neither outcome.** `McpTimeoutError` says the operation may or may not have
  completed, because a deadline that fires has already started the work — the same distinction
  `TransactionOutcome.UNCERTAIN` preserves for a failed commit.
* **The request source is injectable.** Over HTTP it reads fastmcp's own request; a caller with no
  HTTP request (an in-process test, a stdio transport) must supply one rather than being handed an
  unauthenticated path.

## Running it

The extra is optional; the library imports without it and the factory names it if it is missing:

```bash
python -m pip install -e ".[mcp]"
```

```bash
.venv/Scripts/python.exe -m pytest tests/unit/test_mcp_*.py -q
```

Counts on this page are test **functions**, not parametrized cases: a function count is a
deterministic property of a file, whereas a case count depends on how the suite was invoked.
