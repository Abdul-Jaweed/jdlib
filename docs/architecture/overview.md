# Architecture

How JDLib is put together: the planes it separates, the boundaries it enforces, and the order a
request travels through them. These pages describe the *shape* of the library; the
[feature guides](../jdlib/features/README.md) describe how to use each mechanism, and the
[design authorities](../jdlib/architecture.md) are where each rule is stated in full.

## The planes

| Plane | What lives there | Where it is defined |
|---|---|---|
| **Control** | tenants, their lifecycle, placements, platform audit, migrations | `jdlib.control`, `jdlib.migrations` |
| **Request** | credentials, the security context, tenant resolution, authorization, the unit of work | `jdlib.authn`, `jdlib.security`, `jdlib.tenancy`, `jdlib.authz`, `jdlib.persistence` |
| **Data** | the tenant's own PostgreSQL schema and the derived graph | `jdlib.persistence.strategies`, `jdlib.graph` |
| **Operational** | reliability primitives, telemetry, tracing, audit | `jdlib.reliability`, `jdlib.security.audit`, `jdlib.security.telemetry` |

The separation is not decoration. A tenant's lifecycle is decided by an operator command and read by
a request; a request never writes control-plane state, and the control plane never holds request
state. That is what lets `jdlib.control` be public API for an operator without being reachable from a
request path.

## The dependency rule

One-way, and it is what makes the edges interchangeable:

```
jdlib.integrations   (FastAPI, MCP, CLI, the test kit)
        │
        ▼
jdlib.tenancy · jdlib.authz · jdlib.persistence · jdlib.graph · jdlib.reliability · …
        │
        ▼
jdlib.security · jdlib.context · jdlib.errors · jdlib.config   (the shared core)
```

`jdlib.integrations` may import anything; a mechanism package imports the shared types and not
another mechanism; nothing imports `jdlib.integrations`. That is why the HTTP surface and the MCP
surface build the *same* collaborators rather than each wiring their own — and why a denial behaves
identically on both, which the enterprise example measures rather than asserts.

## The pages

| Page | The question it answers |
|---|---|
| [High-level architecture](high-level-architecture.md) | what the system is, what it talks to, and where its boundaries are |
| [Component architecture](component-architecture.md) | which package holds which responsibility, and what each module is for |
| [Request lifecycle](request-lifecycle.md) | what happens, in order, from a credential to a tenant-bound row |
| [Data architecture](data-architecture.md) | the control plane, the placement plane, the tenant plane, and the derived graph |
| [Security architecture](security-architecture.md) | the trust boundaries and the enforcement points |
| [Reliability architecture](reliability-architecture.md) | the failure domains and the primitives that absorb them |
| [Observability architecture](observability-architecture.md) | the signals, what may leave the process, and what an incident reads |
| [The long-form reference](long-form-reference.md) | the complete technical reference, published with the revision it describes |

## How to read a claim on these pages

A statement about *structure* cites a module path. A statement about *behaviour* cites a test file.
Where a page describes something the library deliberately does not do, it says so in the page rather
than leaving the reader to infer it — the [documentation inventory](../development/documentation-inventory.md)
is the per-namespace audit behind that rule.
