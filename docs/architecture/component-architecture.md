# Component architecture

One row per package, one line per module. The module list is the tree at this revision; the
[documentation inventory](../development/documentation-inventory.md) records which of them are
documented and which test files hold them.

## The shared core

| Package | Modules | What it is |
|---|---|---|
| `jdlib` | `config`, `context`, `errors`, `models`, `lint` | the public surface: `TenancyConfig`, the context types, the error model, `current_tenant()` |
| `jdlib.security` | `context`, `config`, `errors`, `interfaces`, `identity`, `redaction`, `responses`, `telemetry`, `tracing` | the security core: the request context, the error envelope, the ports, the span allow-list |
| `jdlib.security.audit` | `emitter`, `emitters`, `events`, `access`, `adapters`, `export` | the audit vocabulary, the sinks, and the export surface |
| `jdlib.security.authn` | `provider`, `jwt`, `algorithms`, `transports`, `zitadel` | authentication *primitives*: token verification, algorithms, transports |
| `jdlib.security.authz` | `pep`, `decision`, `cerbos`, `interfaces`, `transports` | the policy enforcement point and the decision-point ports |
| `jdlib.security.compliance` | `controls`, `evidence`, `posture`, `session` | the control catalog and the evidence it can produce |
| `jdlib.security.gateway` | `adapters`, `config` | what a gateway asserts (Kong, Tyk) and how the library reads it |

## The request plane

| Package | Modules | What it is |
|---|---|---|
| `jdlib.authn` | `apikey`, `oidc`, `composite`, `base`, `wiring` | the authenticators and the composition that builds them from configuration |
| `jdlib.authz` | `permissions`, `guards`, `pdp`, `scopes`, `resource_types`, `access`, `reader`, `cache` | the permission catalog, `require()`, the default PDP, scope and resource-type resolution |
| `jdlib.tenancy` | `resolution`, `middleware`, `jobs`, `job_envelope`, `dead_letter` | resolver chain, the middleware, and the authority a background job carries |
| `jdlib.persistence` | `repository`, `uow`, `session`, `router`, `models`, `rawsql`, `secrets` | tenant-bound data access, the unit of work, the session and RLS, the read/write router |
| `jdlib.persistence.strategies` | `shared`, `schema`, `…` | the isolation strategies: shared schema, schema per tenant |
| `jdlib.control` | `registry`, `base`, `models`, `enums`, `session`, `audit`, `purge` | the tenant registry, the lifecycle, platform audit, purge |
| `jdlib.migrations` | `runner` | control-plane migrations, run by an operator command |
| `jdlib.resources` | `handle`, `connection`, `resolver`, `errors` | resource handles and how a connection configuration is resolved |

## The data plane

| Package | Modules | What it is |
|---|---|---|
| `jdlib.query` | `specification`, `ast`, `compiler`, `dialect`, `safety`, `errors` | the query compiler: a specification becomes an AST becomes SQL, with an identifier policy |
| `jdlib.data` | `connector`, `contract`, `registry`, `policy`, `capabilities`, `postgres`, `errors` | the connector framework: contracts, capability declarations, the policy that gates a call |
| `jdlib.storage` | `provider`, `keys`, `metadata`, `s3`, `errors` | object storage: key construction, metadata, the S3 backend |
| `jdlib.caching` | `protocol`, `policy`, `keys`, `local`, `redis`, `errors` | the cache protocol, the policy, and the credential guard |
| `jdlib.credentials` | `composite`, `refs`, `rotation`, `redaction`, `errors` | the secret-provider chain, references, and rotation |
| `jdlib.graph` | `client`, `repository`, `query`, `policy`, `tenant`, `transaction`, `mapping`, `models`, `config`, `errors` | the Neo4j plane: a tenant-bound client, a closed query vocabulary, a derived graph |

## The operational plane

| Package | Modules | What it is |
|---|---|---|
| `jdlib.reliability` | `breaker`, `budget`, `concurrency`, `lifecycle`, `policy` | circuit breaker, retry budget, concurrency gate, shutdown coordinator |
| `jdlib.integrations.fastapi` | `install`, `require`, `context`, `uow`, `container`, `errors` | the HTTP edge: middleware, the guard, the error envelope, the composition root |
| `jdlib.integrations.mcp` | `server`, `boundary`, `invocation`, `tools`, `graph_tools`, `resources`, `errors` | the MCP edge: the same chain behind a tool call |
| `jdlib.integrations.cli` | the Typer application | the operator commands: migrations, tenant creation, provisioning |
| `jdlib.integrations.pytest_plugin` / `jdlib.testing` | fixtures and helpers | the test kit the examples' suites are built on |

## Where a change goes

| A change to… | Belongs in… | Because |
|---|---|---|
| how a credential is verified | `jdlib.authn` | one implementation per method, composed in `wiring` |
| what a permission means | `jdlib.authz.permissions` + your policies | the catalog names, the engine decides |
| how a tenant is found | `jdlib.tenancy.resolution` | the order is configuration; the rule is not |
| how rows are constrained | `jdlib.persistence.strategies` | isolation is a strategy, chosen per tenant |
| what a failure looks like | `jdlib.security.responses` + `errors` | one envelope for every surface |
| what is recorded | `jdlib.security.audit` | one vocabulary, two sinks |
| how an edge behaves | `jdlib.integrations.*` | edges compose, they do not implement |
