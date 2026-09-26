# The feature matrix

Every feature the library offers, with the seam that implements it, where the example uses
it, and the test that asserts the claim — each cell a real `file:line`, **generated from the
working tree** rather than written by hand.

Two cells need reading carefully, and both say exactly what was measured:

* ***library-only*** — the guide declares no example path, so the example application does not
  use this feature at all (background jobs, for instance); the evidence is the library's own
  suite, which the guide names;
* ***not named directly*** — the example uses the feature but reaches it through another seam
  (the builder, the middleware, the `install`), so this particular symbol never appears in
  `examples/`. Calling that library-only would be false.

Line numbers are the definition (library), the first use (example) and the test function that
names the symbol. Regenerate with `python scripts/feature-matrix.py`;
`tests/unit/test_example_docs.py` checks that every path these pages cite exists.

## authentication — [`features/authentication.md`](../features/authentication.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `Authenticator` | `src/jdlib/authn/base.py:10` | *not named directly* | — |
| `build_authenticator` | `src/jdlib/authn/wiring.py:30` | `examples/enterprise/app/security/authentication.py:3` | `tests/unit/test_authn_wiring.py:17` |
| `ApiKeyAuthenticator` | `src/jdlib/authn/apikey.py:47` | *not named directly* | `tests/unit/test_authn_wiring.py:17` |
| `OidcAuthenticator` | `src/jdlib/authn/oidc.py:298` | *not named directly* | `tests/unit/test_authn_wiring.py:17` |
| `CompositeAuthenticator` | `src/jdlib/authn/composite.py:10` | *not named directly* | `tests/unit/test_authn_wiring.py:17` |

## authorization — [`features/authorization.md`](../features/authorization.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `AuthorizationPEP` | `src/jdlib/security/authz/pep.py:36` | `examples/enterprise/app/main.py:53` | `tests/unit/security/test_authz_pep.py:113` |
| `AuthorizationQuery` | `src/jdlib/security/authz/decision.py:36` | `examples/enterprise/app/main.py:54` | `tests/unit/security/test_authz_pep.py:187` |
| `AuthorizationDecision` | `src/jdlib/security/authz/decision.py:86` | `examples/enterprise/app/security/authorization.py:6` | `tests/unit/security/test_authz_pep.py:187` |
| `CerbosPDP` | `src/jdlib/security/authz/cerbos.py:119` | `examples/enterprise/app/security/authorization.py:26` | — |
| `CerbosConfig` | `src/jdlib/security/authz/cerbos.py:88` | `examples/enterprise/app/configuration/settings.py:12` | — |

## tenancy — [`features/tenancy.md`](../features/tenancy.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `RequestInfo` | `src/jdlib/tenancy/resolution.py:14` | `examples/enterprise/tests/integration/test_mcp_live.py:69` | — |
| `TenantResolver` | `src/jdlib/tenancy/resolution.py:24` | *not named directly* | — |
| `ResolverChain` | `src/jdlib/tenancy/resolution.py:101` | `examples/enterprise/app/main.py:56` | — |
| `build_chain` | `src/jdlib/tenancy/resolution.py:113` | `examples/enterprise/app/main.py:56` | — |
| `TenantMiddleware` | `src/jdlib/tenancy/middleware.py:129` | `examples/enterprise/tests/unit/test_app.py:71` | — |

## resource-management — [`features/resource-management.md`](../features/resource-management.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `TenantRepository` | `src/jdlib/persistence/repository.py:13` | `examples/enterprise/app/repositories/resources.py:3` | — |
| `ResourceResolver` | `src/jdlib/resources/resolver.py:30` | *not named directly* | `tests/unit/test_resource_hydration.py:106` |
| `ResourceHandle` | `src/jdlib/resources/handle.py:7` | *not named directly* | `tests/unit/test_resource_hydration.py:96` |
| `ConnectionConfig` | `src/jdlib/resources/connection.py:8` | *not named directly* | — |
| `ResourceHydrationError` | `src/jdlib/resources/errors.py:6` | *not named directly* | `tests/unit/test_resource_hydration.py:136` |

## query-system — [`features/query-system.md`](../features/query-system.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `QueryCompiler` | `src/jdlib/query/compiler.py:57` | *not named directly* | `tests/unit/test_query_compiler.py:87` |
| `CompiledQuery` | `src/jdlib/query/compiler.py:36` | *not named directly* | — |
| `Filter` | `src/jdlib/query/specification.py:20` | *not named directly* | `tests/unit/test_query_compiler.py:87` |
| `Predicate` | `src/jdlib/query/ast.py:15` | *not named directly* | — |

## credentials — [`features/credentials.md`](../features/credentials.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `CompositeSecretProvider` | `src/jdlib/credentials/composite.py:11` | *not named directly* | `tests/unit/test_credentials_providers.py:164` |
| `SecretRef` | `src/jdlib/credentials/refs.py:25` | `examples/enterprise/app/graph.py:31` | `tests/unit/test_credentials_providers.py:46` |
| `SecretVersion` | `src/jdlib/credentials/refs.py:7` | *not named directly* | `tests/unit/test_credentials_providers.py:55` |
| `VersionedSecretProvider` | `src/jdlib/credentials/rotation.py:23` | `examples/enterprise/app/graph.py:32` | `tests/unit/test_credentials_providers.py:82` |
| `ResolvedSecret` | `src/jdlib/credentials/refs.py:46` | `examples/enterprise/app/graph.py:74` | — |

## caching — [`features/caching.md`](../features/caching.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `CachePolicy` | `src/jdlib/caching/policy.py:9` | *not named directly* | `tests/unit/test_scoped_cache.py:192` |
| `CacheProvider` | `src/jdlib/caching/protocol.py:7` | *not named directly* | — |
| `LocalCache` | `src/jdlib/caching/local.py:44` | *not named directly* | — |
| `RedisCache` | `src/jdlib/caching/redis.py:17` | *not named directly* | `tests/integration/test_redis_cache.py:159` |
| `ScopedKeyFactory` | `src/jdlib/caching/keys.py:12` | *not named directly* | `tests/unit/test_scoped_cache.py:50` |

## storage — [`features/storage.md`](../features/storage.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `ObjectStorageProvider` | `src/jdlib/storage/provider.py:25` | *not named directly* | — |
| `S3ObjectStorage` | `src/jdlib/storage/s3.py:23` | *not named directly* | `tests/integration/test_object_storage.py:123` |
| `StoredObject` | `src/jdlib/storage/metadata.py:8` | *not named directly* | — |
| `ObjectMetadata` | `src/jdlib/storage/metadata.py:17` | *not named directly* | — |
| `object_key` | `src/jdlib/storage/keys.py:12` | *not named directly* | — |

## connectors — [`features/connectors.md`](../features/connectors.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `DataConnector` | `src/jdlib/data/connector.py:14` | *not named directly* | `tests/unit/test_connector_framework.py:145` |
| `ConnectorRegistry` | `src/jdlib/data/registry.py:17` | *not named directly* | `tests/unit/test_connector_framework.py:255` |
| `PostgresConnector` | `src/jdlib/data/postgres.py:22` | *not named directly* | `tests/integration/test_postgres_connector.py:69` |
| `ConnectionPolicy` | `src/jdlib/data/policy.py:27` | *not named directly* | `tests/unit/test_connector_framework.py:183` |
| `ConnectorCapabilities` | `src/jdlib/data/capabilities.py:7` | *not named directly* | `tests/unit/test_connector_framework.py:152` |

## graph — [`features/graph.md`](../features/graph.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `GraphClient` | `src/jdlib/graph/client.py:65` | *not named directly* | `tests/unit/test_graph_client.py:93` |
| `GraphConfig` | `src/jdlib/graph/config.py:48` | `examples/enterprise/app/graph.py:34` | `tests/unit/test_graph_adversarial.py:214` |
| `GraphQuery` | `src/jdlib/graph/query.py:38` | *not named directly* | `tests/unit/test_graph_adversarial.py:174` |
| `GraphRepository` | `src/jdlib/graph/repository.py:62` | `examples/enterprise/app/graph.py:36` | — |
| `GraphRunner` | `src/jdlib/graph/client.py:56` | *not named directly* | — |

## mcp — [`features/mcp.md`](../features/mcp.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `build_mcp_server` | `src/jdlib/integrations/mcp/server.py:68` | `examples/enterprise/app/mcp/server.py:6` | — |
| `McpTool` | `src/jdlib/integrations/mcp/tools.py:30` | `examples/enterprise/app/mcp/tools.py:26` | — |
| `McpToolRegistry` | `src/jdlib/integrations/mcp/tools.py:85` | `examples/enterprise/app/mcp/server.py:35` | `tests/unit/test_mcp_registry.py:109` |
| `McpSecurityBoundary` | `src/jdlib/integrations/mcp/boundary.py:43` | `examples/enterprise/app/mcp/server.py:5` | `tests/unit/test_mcp_boundary.py:130` |
| `McpInvoker` | `src/jdlib/integrations/mcp/invocation.py:65` | *not named directly* | — |

## jobs — [`features/jobs.md`](../features/jobs.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `JobEnvelope` | `src/jdlib/tenancy/job_envelope.py:87` | *library-only* | `tests/unit/test_job_envelope.py:148` |
| `JobDispatcher` | `src/jdlib/tenancy/job_envelope.py:174` | *library-only* | `tests/unit/test_job_retry_dead_letter.py:209` |
| `EnvelopeForgeryError` | `src/jdlib/tenancy/job_envelope.py:39` | *library-only* | `tests/unit/test_job_envelope.py:148` |
| `EnvelopeExpiredError` | `src/jdlib/tenancy/job_envelope.py:43` | *library-only* | `tests/unit/test_job_envelope.py:204` |
| `EnvelopeReplayError` | `src/jdlib/tenancy/job_envelope.py:47` | *library-only* | `tests/unit/test_job_envelope.py:217` |

## audit — [`features/audit.md`](../features/audit.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `SecurityAuditEvent` | `src/jdlib/security/audit/events.py:209` | `examples/enterprise/app/security/audit.py:15` | `tests/unit/security/test_audit_events.py:184` |
| `AuditOutcome` | `src/jdlib/security/audit/events.py:125` | *not named directly* | `tests/unit/security/test_audit_events.py:151` |
| `AuditSource` | `src/jdlib/security/audit/events.py:134` | `examples/enterprise/app/security/authorization.py:25` | `tests/unit/security/test_audit_events.py:151` |
| `AuditCapability` | `src/jdlib/security/audit/access.py:35` | *not named directly* | — |
| `AuditQuery` | `src/jdlib/security/audit/export.py:71` | *not named directly* | `tests/integration/test_audit_isolation_export.py:137` |

## observability — [`features/observability.md`](../features/observability.md)

| Seam | Implements | The example uses it at | Asserted by |
|---|---|---|---|
| `security_span` | `src/jdlib/security/tracing.py:235` | *not named directly* | — |
| `SecuritySpan` | `src/jdlib/security/tracing.py:177` | *not named directly* | — |
| `TraceContext` | `src/jdlib/security/tracing.py:48` | *not named directly* | — |
| `parse_traceparent` | `src/jdlib/security/tracing.py:60` | *not named directly* | — |
| `format_traceparent` | `src/jdlib/security/tracing.py:85` | *not named directly* | — |
