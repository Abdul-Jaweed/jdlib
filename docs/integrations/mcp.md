# MCP

```bash
pip install "jdlib[mcp]"
```

`jdlib.integrations.mcp` exposes the same chain to a model-facing client: tools and resources instead
of routes, with the same authentication, the same tenant rule, the same policy decision and the same
audit vocabulary.

## The parts

| Module | What it does |
|---|---|
| `server` | builds the FastMCP server from the composed collaborators |
| `boundary` | the request boundary: credential, context, tenant, the audit events a call produces |
| `invocation` | binds a call to the context and runs the tool body behind the PEP |
| `tools` | the tool registry and the declared input models |
| `graph_tools` | the graph tools, over the closed query vocabulary |
| `resources` | resource URIs and their resolution |
| `errors` | the refusals, in the library's vocabulary |

## What it refuses

* **A tool call without an allowed decision.** The PEP runs first; the tool body is not entered, and
  the refusal is an MCP result rather than an exception the client cannot read.
* **Arguments that do not match the declared schema.** The schema a tool advertises is the schema the
  library enforces — the enterprise example asserts the two are the same, because an advertised
  schema that is not enforced is a promise the surface does not keep.
* **An unregistered resource URI.** A refusal, not a crash.
* **A free-text graph search.** `graph_search` is deliberately absent: the graph surface exposes the
  closed vocabulary, and a free-text search is a statement that vocabulary cannot express. The
  absence is recorded as a decision, not an omission.

## What a denial leaves behind

A refused tool call writes three audit events — the call, the decision and the outcome — where the
HTTP path writes one. The difference is real and the enterprise example asserts it, so an incident
can reconstruct an MCP denial from the audit plane alone.

## Where it is tested

`tests/unit/test_mcp_*.py` (the registry, the boundary, invocation, resources, reliability,
observability, the adversarial cases) and `examples/enterprise/tests/` for the composed surface
against a live tenant. The [feature guide](../jdlib/features/mcp.md) is the how-to.
