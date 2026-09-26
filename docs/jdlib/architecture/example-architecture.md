# The example application's architecture

How the enterprise example is put together, and why each layer is where it is. The library's own
[`../architecture.md`](../architecture.md) describes the library; this page describes one
application that uses it.

## Two ASGI applications, deliberately

```
outer app  (examples/enterprise/app/main.py:create_app)
├── /healthz          liveness -- no credentials, no dependencies
├── /readyz           readiness -- control plane statement + a policy decision
└── /api  ──mount──▶  tenant app  (install(...): middleware, guard, envelope)
                     ├── /whoami                 require("tenant:read")
                     ├── /tenants/current        require("tenant:read")
                     └── /resources...           require("resource:read" | "resource:write")
```

The tenant plane is mounted under `/api`; nothing under it is reachable without a verified principal
and a resolved tenant. The probes are outside it, because a probe that needs a token fails during an
identity-provider outage and gets the process restarted for it.

## One composition, two surfaces

`build_collaborators()` builds every collaborator **once**; `create_app(collaborators)` serves HTTP
and `build_example_mcp_server(...)` serves MCP from the *same objects*. The unit tests assert that by
**identity**, not by shape — a second authenticator or a second enforcer would be a second place for
a decision to drift, and no test would notice.

```
Collaborators (frozen dataclass)
├── settings, config          configuration, validated at startup
├── control_engine, sessions  the control plane's connection
├── audit, security_sink      the platform trail + the security-event join
├── reader, registry          access reads, tenant lifecycle
├── plane, fence, resources   the tenant plane + the write fence + the service
├── pep, enforcer, container  policy engine, the bridge, the FastAPI container
├── principal_provider, chain, factory   authentication → tenant resolution → context
└── graph                     the derived plane, when configured
```

## The layers, and what each one may decide

| Layer | Decides | May not |
|---|---|---|
| `app/configuration/` | which settings exist, which are required | hold a secret |
| `app/security/` | which collaborator answers each question | decide policy |
| `app/api/` | which permission a route needs | query, or catch a typed error into a new shape |
| `app/services/` | the transaction boundary, the audit of a write | authorize, or resolve a tenant |
| `app/repositories/` | which statements run | commit, or open its own session |
| `app/models/` | the schema the application owns | know about HTTP |
| `app/mcp/` | the tool inventory, the schemas | build its own collaborators |
| `app/dataplane.py` | the plane, RLS, the operator grants | serve a request |
| `app/bootstrap.py` | the operator steps (tenant, schema) | run at request time |

## Where the seams are

Every security mechanism is the library's: `install` (middleware + guard + envelope),
`require(...)` (the declared permission), `build_authenticator`, the `ResolverChain`, the
`ContextFactory`, `AuthorizationPEP` through `CerbosEnforcer`, `SecurityEventEmitter`,
`GraphRepository` and `GraphRunner`, `build_mcp_server` and its boundary. The example supplies the
*choices* — which engine, which directory, which sink, which vocabulary — and the tests assert that
it supplies nothing else.

## What is deliberately absent

* **No driver imports outside `graph.py` and `dsn.py`** — a route that reached `asyncpg` or `neo4j`
  would be a path around the repository and the tenant binding.
* **No second error shape** — routes do not catch typed errors; the envelope answers them.
* **No tenant parameter anywhere** — the tenant comes from the credential, and the tests assert that
  a header claiming one changes nothing.
* **No caching on the request path** — the seam is documented, and the example does not use it: a
  cache is a second copy of the truth, and this example's point is the first one.
