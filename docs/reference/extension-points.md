# Extension points

What a deployment implements, and what it only configures. The distinction is deliberate: a *port* is
a protocol the library talks to, so replacing it changes nothing else.

## The ports

| Port | Module | Implement it to… |
|---|---|---|
| `DecisionPoint` | `jdlib.security.authz.interfaces` | answer the authorization question with your own engine (the shipped adapter is `jdlib.security.authz.cerbos.CerbosPDP`) |
| `TracerLike` | `jdlib.security.tracing` | emit spans into your tracer |
| an audit sink | `jdlib.security.audit.emitters` / `adapters` | write the audit vocabulary into a store you already run |
| a credential provider | `jdlib.credentials.composite` | source secrets from your own store, composed in a chain |
| a cache provider | `jdlib.caching.protocol` | cache in a store the library does not ship |
| a storage provider | `jdlib.storage.provider` | store objects where you already store them |
| a connector | `jdlib.data.contract` | reach a data source the library does not ship a connector for |
| `GraphRunner` / `GraphClient` | `jdlib.graph.client` | replace the graph client (the shipped one is `Neo4jClient`) |
| an authenticator | `jdlib.authn.base` | add an identity method; compose it in `jdlib.authn.wiring` |
| a tenant resolver | `jdlib.tenancy.resolution` | find the tenant somewhere the shipped resolvers do not look |
| an isolation strategy | `jdlib.persistence.strategies.base` | place a tenant's data somewhere new |

## What you configure instead

| Instead of implementing | Configure |
|---|---|
| where the tenant comes from | `JDLIB_RESOLVERS__ORDER` and its companions |
| which algorithms a token may use | `JDLIB_OIDC__ALGORITHMS` |
| the role the policy applies to | `JDLIB_RLS__APP_ROLE` |
| the permission names | the catalog, in code, at startup |

## The rule for a port

A port is defined by the question, not by the implementation: the PEP asks a `DecisionPoint` and does
not know Cerbos exists; the audit emitter writes to a sink and does not know whether it is a database.
That is why replacing one changes nothing else — and why the tests can substitute a recording double
without weakening what they assert.

## What is *not* an extension point

The chain itself. Authentication, tenant resolution, authorization, the data boundary and the audit
vocabulary are the library's; a deployment that replaces one of them has replaced the thing it
installed. Where a deployment needs different behaviour, the port is the seam — never a re-implemented
guard.
