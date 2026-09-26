# The developer journey

The order to adopt things in, and what each step buys you.

## 1. Get one route right

Install the library (`install`), give it a `ContextFactory` and a `ResolverChain`, and put one
`require("...")` on one route. At this point you have: a verified principal, a resolved tenant, a
declared permission, and one error envelope — the four things that are painful to retrofit.
→ [`minimal-example.md`](minimal-example.md)

## 2. Make the tenant real

Provision a tenant through `TenantRegistry`, install RLS with the documented operator step, and run
your application as the role the policies constrain. Now a forgotten filter is a refused read rather
than a disclosure.
→ [`../features/tenancy.md`](../features/tenancy.md)

## 3. Put your data behind the repository

Move tenant-plane access into a repository whose sessions are bound, and services that own the
transaction boundary. Routes stop querying.
→ [`../features/resource-management.md`](../features/resource-management.md)

## 4. Answer with a real policy engine

Replace any in-process check with a `PolicyDecisionPoint` — Cerbos is the reference — and write the
policies as code, with the engine's own tests beside them. Now the answer is reviewable by someone
who does not read Python.
→ [`../features/authorization.md`](../features/authorization.md)

## 5. Record what happened

Point the security-event emitter at a sink and the platform audit writer at your trail. Now a
denial, a privileged read and an export are all answerable after the fact.
→ [`../features/audit.md`](../features/audit.md)

## 6. Add the second surface

Declare the tools you actually want an agent to have, and build the MCP server from the *same*
collaborators your HTTP app uses. Because the composition is shared, the second surface inherits
every decision you have already made.
→ [`../features/mcp.md`](../features/mcp.md)

## 7. Derive what is a graph

If (and only if) your questions are about relationships, project into a graph as a *derived* plane,
with the vocabulary closed and the tenant bound to the client.
→ [`../features/graph.md`](../features/graph.md)

## 8. Make degradation a state

Add the breaker, the retry budget, the concurrency gate and the shutdown coordinator; make
`/readyz` honest about your security dependencies. Now an outage of the engine is a refusal you can
explain, not an incident you discover.
→ [`../features/observability.md`](../features/observability.md)

## The rule behind the order

Each step makes the next one cheaper: a resolved tenant is what makes a bound repository possible, a
bound repository is what makes a policy answer meaningful, and a policy answer is what a second
surface can safely reuse. Doing them in the other order — a tool surface first, then discovering it
needs identity — is how a second entry point grows its own security model.
