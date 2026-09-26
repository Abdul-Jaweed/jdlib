# Integrations

The packages under `jdlib.integrations` are **edges**: each one translates a transport into the same
collaborators and the same chain. None of them implements a security mechanism of its own — an edge
that implemented one would be a second answer to a question the library has already answered.

| Integration | Package | Extra | What it is for |
|---|---|---|---|
| [FastAPI](fastapi.md) | `jdlib.integrations.fastapi` | `fastapi` | the HTTP surface: middleware, the guard, the error envelope, the composition root |
| [MCP](mcp.md) | `jdlib.integrations.mcp` | `mcp` | the model-facing surface: tools and resources over the same chain |
| [CLI](cli.md) | `jdlib.integrations.cli` | `cli` | the operator commands: migrations, tenants, isolation policies, schema lint |
| [pytest](pytest.md) | `jdlib.integrations.pytest_plugin`, `jdlib.testing` | `dev` | the fixtures and helpers the example suites are built on |

The stores are integrated the same way — a provider implements a protocol the library defines:

| Store | Module | Extra | What it is for |
|---|---|---|---|
| [PostgreSQL](postgresql.md) | `jdlib.data.postgres`, `jdlib.persistence` | — | the control plane and the tenant plane |
| [Neo4j](neo4j.md) | `jdlib.graph` | `graph` | the derived graph plane |
| [Redis](redis.md) | `jdlib.caching.redis` | `redis` | a shared cache provider |
| [S3](s3.md) | `jdlib.storage.s3` | `s3` | object storage |
| [Cerbos](cerbos.md) | `jdlib.security.authz.cerbos` | — | the reference decision point |

## The rule an integration follows

1. **It composes, it does not decide.** The edge builds the authenticator, the resolver chain, the
   context factory, the PEP and the unit of work from configuration, and then gets out of the way.
2. **Its optional dependency is optional.** Importing `jdlib` never imports `fastapi`, `mcp`, `redis`,
   `boto3` or `neo4j`; a missing extra is a refusal that names the extra, not an `ImportError` at
   process start.
3. **It answers with the library's envelope.** A failure on any edge is the same
   `ErrorResponse` shape, with the same stable codes, so a client does not need per-surface handling.
4. **It is measured like a surface.** The enterprise example runs its HTTP and MCP surfaces through
   the same security assertions, and the differences between them are documented rather than smoothed
   over.
