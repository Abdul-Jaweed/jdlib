# Public API reference

**Generated** by `scripts/api-reference.py` from the source at this commit: the names
each namespace exports, their signatures, and the first line of their own docstring.
The gate runs `--check`, so a page that no longer matches the tree fails the build
rather than mislead a reader.

The library's public surface is declared, not implied. `jdlib.__all__` and the
subpackages' `__all__` are the declaration; the packages listed as *per-module* have
no package-level `__all__` and their surface is the submodules' exports. The
[documentation inventory](../development/documentation-inventory.md) audits the same
surface per namespace, with the test files that hold it.

## `jdlib`

`__all__` (13 names)

| Name | Signature | Summary |
|---|---|---|
| `AccessControl` | `AccessControl(*, session_factory: 'Callable[[], AsyncSession]', catalog: 'PermissionCatalog', reader: 'AccessReader', cache: 'AuthzCache', audit: 'PlatformAudit', registry: 'ResourceTypeRegistry | None' = None, scope_lookup: 'ScopeLookup | None' = None, resource_lookup: 'ResourceLookup | None' = None) -> 'None'` | — |
| `ContextFactory` | `ContextFactory(*, config: 'ContextConfig', principals: 'PrincipalDirectory', tenants: 'TenantDirectory', servability: 'ServabilityChecker', entitlements: 'EntitlementChecker', operators: 'OperatorAuthorizer', audit: 'PrivilegeAudit', clock: 'Clock | None' = None) -> 'None'` | — |
| `JdlibError` | `JdlibError(/, *args, **kwargs)` | — |
| `TenancyConfig` | `TenancyConfig(__pydantic_self__, _case_sensitive: 'bool | None' = None, _nested_model_default_partial_update: 'bool | None' = None, _env_prefix: 'str | None' = None, _env_prefix_target: 'EnvPrefixTarget | None' = None, _env_file: 'DotenvType | None' = WindowsPath('.'), _env_file_encoding: 'str | None' = None, _env_ignore_empty: 'bool | None' = None, _env_nested_delimiter: 'str | None' = None, _env_nested_max_split: 'int | None' = None, _env_parse_none_str: 'str | None' = None, _env_parse_enums: 'bool | None' = None, _cli_prog_name: 'str | None' = None, _cli_parse_args: 'bool | list[str] | tuple[str, ...] | None' = None, _cli_settings_source: 'CliSettingsSource[Any] | None' = None, _cli_parse_none_str: 'str | None' = None, _cli_hide_none_type: 'bool | None' = None, _cli_avoid_json: 'bool | None' = None, _cli_enforce_required: 'bool | None' = None, _cli_use_class_docs_for_groups: 'bool | None' = None, _cli_show_env_vars: 'bool | None' = None, _cli_exit_on_error: 'bool | None' = None, _cli_prefix: 'str | None' = None, _cli_flag_prefix_char: 'str | None' = None, _cli_implicit_flags: "bool | Literal['dual', 'toggle'] | None" = None, _cli_ignore_unknown_args: 'bool | None' = None, _cli_kebab_case: "bool | Literal['all', 'no_enums'] | None" = None, _cli_shortcuts: 'Mapping[str, str | list[str]] | None' = None, _secrets_dir: 'PathType | None' = None, _build_sources: 'tuple[tuple[PydanticBaseSettingsSource, ...], dict[str, Any]] | None' = None, **values: 'Any') -> 'None'` | — |
| `TenantContext` | `TenantContext(tenant_id: 'uuid.UUID', tenant_slug: 'str', strategy: 'PlacementStrategy', principal: 'Principal', request_id: 'str', correlation_id: 'str', trace_id: 'str | None' = None, privilege: 'PrivilegeContext | None' = None) -> None` | TenantContext(tenant_id: 'uuid.UUID', tenant_slug: 'str', strategy: 'PlacementStrategy', principal: 'Principal', request_id: 'str', correlation_id: 'str', trace_id: 'str \| None' = None, privilege: 'PrivilegeContext \| None' = None) |
| `TenantRegistry` | `TenantRegistry(*, session_factory: 'Callable[[], AsyncSession]', strategies: 'Mapping[PlacementStrategy, IsolationStrategy]', runner: 'MigrationRunner', audit: 'PlatformAudit', seeder: 'SeedHook | None' = None, desired_version: 'str' = '0002_security_audit_columns', purger: 'TenantPlanePurger | None' = None) -> 'None'` | — |
| `TenantRepository` | `TenantRepository(session: 'TenantSession', model: 'type[ModelT]') -> 'None'` | — |
| `UnitOfWork` | `UnitOfWork(session_factory: 'Callable[[], Any]', context: 'TenantContext', *, fence: 'WriteFence', auditor: 'RawSqlAuditor | None' = None) -> 'None'` | — |
| `authorize` | `authorize(permission: 'str', target: 'Target', *, enforcer: 'Enforcer', session: 'object') -> 'Decision'` | — |
| `current_principal` | `current_principal() -> 'Principal'` | — |
| `current_tenant` | `current_tenant() -> 'TenantContext'` | — |
| `errors` | | — |
| `requires` | `requires(permission: 'str', *, enforcer: 'Enforcer', target_factory: 'Callable[..., Target] | None' = None) -> 'Callable[[F], F]'` | — |

## `jdlib.caching`

`__all__` (11 names) · documented in [caching](../jdlib/capabilities/caching.md), [caching](../jdlib/features/caching.md)

| Name | Signature | Summary |
|---|---|---|
| `SCHEMA_VERSION` | | str(object='') -> str |
| `CacheKeyError` | `CacheKeyError(/, *args, **kwargs)` | A cache key could not be built safely: missing scope, empty part, or a delimiter clash. |
| `CachePolicy` | `CachePolicy(default_ttl: 'int' = 300, maximum_ttl: 'int' = 3600) -> None` | How long an entry may live, and the ceiling no caller may exceed. |
| `CachePolicyError` | `CachePolicyError(/, *args, **kwargs)` | A requested lifetime is outside what the policy for that namespace permits. |
| `CacheSerializationError` | `CacheSerializationError(/, *args, **kwargs)` | A value cannot survive the cache's serialisation, or a stored entry cannot be read back. |
| `CacheProvider` | `CacheProvider(*args, **kwargs)` | What a cache implementation must do. Local and shared providers share this shape. |
| `CredentialCacheRefusedError` | `CredentialCacheRefusedError(/, *args, **kwargs)` | A credential object was offered to a shared cache, and was refused. |
| `LocalCache` | `LocalCache(keys: 'ScopedKeyFactory', clock: 'Callable[[], datetime]', policy: 'CachePolicy' = <factory>, _entries: 'dict[str, _Entry]' = <factory>) -> None` | In-process cache. One instance per process; never a credential store (ADR-2). |
| `RedisCache` | `RedisCache(*, url: 'str', keys: 'ScopedKeyFactory', prefix: 'str' = 'jdlib', policy: 'CachePolicy | None' = None) -> 'None'` | Shared cache over real Redis. |
| `ScopedKeyFactory` | `ScopedKeyFactory(/, *args, **kwargs)` | The only place a cache key is built, so tenant scope cannot be forgotten. |
| `contains_credential` | `contains_credential(value: 'object', *, _depth: 'int' = 0) -> 'bool'` | Whether a value is, or contains, a credential object. |

## `jdlib.credentials`

`__all__` (10 names) · documented in [credentials](../jdlib/capabilities/credentials.md), [credentials](../jdlib/features/credentials.md)

| Name | Signature | Summary |
|---|---|---|
| `INITIAL_VERSION` | | An opaque token identifying one generation of a secret. |
| `REDACTED` | | str(object='') -> str |
| `CompositeSecretProvider` | `CompositeSecretProvider(providers: 'Iterable[SecretProvider]') -> 'None'` | Try providers in declared order. |
| `CredentialUnavailableError` | `CredentialUnavailableError(/, *args, **kwargs)` | A credential could not be resolved, or the requested version is no longer served. |
| `CredentialVersionRetiredError` | `CredentialVersionRetiredError(/, *args, **kwargs)` | A pinned version has been rotated away; the caller must re-resolve and rebuild. |
| `ResolvedSecret` | `ResolvedSecret(ref: 'SecretRef', version: 'SecretVersion', value: 'str') -> None` | A resolved value plus the version it came from. |
| `SecretRef` | `SecretRef(handle: 'str', version: 'SecretVersion | None' = None) -> None` | A reference to a secret. It carries no value, and it cannot render one. |
| `SecretVersion` | `SecretVersion(value: 'str') -> None` | An opaque token identifying one generation of a secret. |
| `VersionedSecretProvider` | `VersionedSecretProvider(inner: 'SecretProvider', *, tracer: 'TracerLike | None' = None, emitter: 'SecurityEventEmitter | None' = None) -> 'None'` | Wrap any secret provider to give its secrets observable, refusable versions. |
| `redact` | `redact(value: 'object') -> 'str'` | Render the presence of a secret without its content. |

## `jdlib.data`

`__all__` (10 names)

| Name | Signature | Summary |
|---|---|---|
| `AuthorizationRefusedError` | `AuthorizationRefusedError(*args: 'object', transient: 'bool' = False) -> 'None'` | A connector could not verify it was given an authorized context, and refused to open. |
| `CircuitOpenError` | `CircuitOpenError(*args: 'object', transient: 'bool' = False) -> 'None'` | The circuit is open: repeated failures, so calls are refused without being attempted. |
| `ConnectionPolicy` | `ConnectionPolicy(connect_timeout: 'float' = 10.0, statement_timeout: 'float' = 30.0, max_attempts: 'int' = 3, retry_backoff: 'timedelta' = datetime.timedelta(microseconds=200000), failure_threshold: 'int' = 5, reset_after: 'timedelta' = datetime.timedelta(seconds=60), retry_budget: 'RetryBudget | None' = None) -> None` | Timeouts, retries and a circuit breaker for connector calls. |
| `ConnectorCapabilities` | `ConnectorCapabilities(name: 'str', reads: 'bool', writes: 'bool', transactions: 'bool', dialect: 'str' = '') -> None` | What an engine can actually do, declared rather than discovered at first use. |
| `ConnectorError` | `ConnectorError(*args: 'object', transient: 'bool' = False) -> 'None'` | A connector operation failed. |
| `ConnectorRegistry` | `ConnectorRegistry(*, tracer: 'TracerLike | None' = None, emitter: 'SecurityEventEmitter | None' = None) -> 'None'` | The known connector types, validated when they are registered rather than when used. |
| `ConnectorTimeoutError` | `ConnectorTimeoutError(*args: 'object', transient: 'bool' = False) -> 'None'` | An operation exceeded the policy's timeout. |
| `DataConnector` | `DataConnector(*args, **kwargs)` | What an engine adapter must implement. Asynchronous throughout (ADR-14). |
| `PostgresConnector` | `PostgresConnector(*, policy: 'ConnectionPolicy | None' = None) -> 'None'` | A read-only PostgreSQL connector over the library's own async engine layer. |
| `assert_connector_contract` | `assert_connector_contract(candidate: 'Any') -> 'list[str]'` | Check a connector against the contract, returning every problem rather than the first. |

## `jdlib.graph`

`__all__` (32 names) · documented in [graph](../jdlib/capabilities/graph.md), [graph](../jdlib/features/graph.md)

| Name | Signature | Summary |
|---|---|---|
| `GraphAuthorizationError` | `GraphAuthorizationError(*args: 'object', transient: 'bool' = False) -> 'None'` | The caller's context does not authorize this operation, or cannot be verified. |
| `GraphCircuitBreaker` | `GraphCircuitBreaker(*, policy: 'GraphPolicy', clock: 'Callable[[], datetime]') -> 'None'` | The graph's view of the shared breaker: it decides *what* a refused call means. |
| `GraphCircuitOpenError` | `GraphCircuitOpenError(*args: 'object', transient: 'bool' = False) -> 'None'` | The circuit is open after repeated failures: the call was refused without attempting. |
| `GraphClient` | `GraphClient(*args, **kwargs)` | A runner that can also be opened, closed, asked about its health, and begin a transaction. |
| `GraphConfig` | `GraphConfig(uri: 'str', auth: 'SecretRef | None' = None, database: 'str | None' = None, max_connection_pool_size: 'int' = 100, connection_acquisition_timeout: 'float' = 60.0, max_connection_lifetime: 'float' = 3600.0, connection_timeout: 'float' = 30.0, max_transaction_retry_time: 'float' = 30.0, allow_unverified_certificates: 'bool' = False, username: 'str | None' = None) -> None` | A validated description of the graph the caller is allowed to reach. |
| `GraphConflictError` | `GraphConflictError(*args: 'object', transient: 'bool' = False) -> 'None'` | A constraint refused the write: a duplicate, or a relationship with a missing endpoint. |
| `GraphError` | `GraphError(*args: 'object', transient: 'bool' = False) -> 'None'` | Base for graph failures. |
| `GraphNotFoundError` | `GraphNotFoundError(*args: 'object', transient: 'bool' = False) -> 'None'` | The node or relationship is not there. |
| `GraphPolicy` | `GraphPolicy(statement_timeout: 'float' = 30.0, max_attempts: 'int' = 3, retry_backoff: 'timedelta' = datetime.timedelta(microseconds=200000), failure_threshold: 'int' = 5, reset_after: 'timedelta' = datetime.timedelta(seconds=60), retry_budget: 'RetryBudget | None' = None) -> None` | Timeouts, retries and a circuit breaker for graph calls. |
| `GraphQuery` | `GraphQuery(text: 'str', parameters: 'dict[str, object]' = <factory>) -> None` | Text and its bound parameters as one value. |
| `GraphQueryError` | `GraphQueryError(*args: 'object', transient: 'bool' = False) -> 'None'` | The database rejected the statement: syntax, types, an unknown procedure. |
| `GraphRepository` | `GraphRepository(*, client: 'GraphRunner', vocabulary: 'GraphVocabulary') -> 'None'` | Tenant-scoped node and relationship operations over a :class:`GraphRunner`. |
| `GraphRunner` | `GraphRunner(*args, **kwargs)` | What running a statement needs — a client, or a transaction inside one. |
| `GraphTenantViolationError` | `GraphTenantViolationError(*args: 'object', transient: 'bool' = False) -> 'None'` | An operation tried to cross a tenant boundary, and was refused. |
| `GraphTimeoutError` | `GraphTimeoutError(*args: 'object', transient: 'bool' = False) -> 'None'` | An operation exceeded its deadline. |
| `GraphUnavailableError` | `GraphUnavailableError(*args: 'object', transient: 'bool' = True) -> 'None'` | The database is unreachable, its pool is exhausted, or it refused the connection. |
| `GraphTransaction` | `GraphTransaction(*, session: 'Any', context: 'SecurityContext', policy: 'GraphPolicy', tracer: 'TracerLike | None' = None, emitter: 'SecurityEventEmitter | None' = None) -> 'None'` | An explicit transaction over an injected session. |
| `GraphValidationError` | `GraphValidationError(*args: 'object', transient: 'bool' = False) -> 'None'` | A value was refused before it reached the database. |
| `GraphVocabulary` | `GraphVocabulary(labels: 'frozenset[str]', relationship_types: 'frozenset[str]', property_keys: 'frozenset[str]') -> None` | Which labels, relationship types and property keys exist in this deployment. |
| `Label` | `Label(value: 'str') -> None` | A node label, validated at construction. |
| `Neo4jClient` | `Neo4jClient(config: 'GraphConfig', *, provider: 'SecretResolver', policy: 'GraphPolicy | None' = None, driver_factory: 'Callable[..., Any] | None' = None, tracer: 'TracerLike | None' = None, emitter: 'SecurityEventEmitter | None' = None) -> 'None'` | The verified Neo4j adapter over the library's own credential and reliability seams. |
| `PropertyKey` | `PropertyKey(value: 'str') -> None` | A property key, validated at construction. |
| `RelationshipType` | `RelationshipType(value: 'str') -> None` | A relationship type, validated at construction. |
| `SecretResolver` | `SecretResolver(*args, **kwargs)` | What the client needs from the credential chain: a reference, resolved to a value. |
| `TransactionOutcome` | `TransactionOutcome(*args, **kwds)` | How a transaction ended. |
| `node_create` | `node_create(label: 'Label', *, tenant: 'str', node_id: 'str', properties: 'Mapping[PropertyKey, object] | None' = None) -> 'GraphQuery'` | Create one node. The tenant and the identity are assigned last, and cannot be supplied. |
| `node_delete` | `node_delete(label: 'Label', *, tenant: 'str', node_id: 'str', detach: 'bool' = False) -> 'GraphQuery'` | Delete one node inside the caller's tenant. |
| `node_match` | `node_match(label: 'Label', *, tenant: 'str', node_id: 'str') -> 'GraphQuery'` | Select one node, by label and identity, inside the caller's tenant. |
| `node_update` | `node_update(label: 'Label', *, tenant: 'str', node_id: 'str', properties: 'Mapping[PropertyKey, object] | None' = None) -> 'GraphQuery'` | Merge properties into one node inside the caller's tenant. Identity is not touched. |
| `relationship_create` | `relationship_create(relationship: 'RelationshipType', *, tenant: 'str', from_label: 'Label', from_id: 'str', to_label: 'Label', to_id: 'str', properties: 'Mapping[PropertyKey, object] | None' = None) -> 'GraphQuery'` | Create one relationship between two nodes of the caller's tenant. |
| `relationship_delete` | `relationship_delete(relationship: 'RelationshipType', *, tenant: 'str', from_label: 'Label', from_id: 'str', to_label: 'Label', to_id: 'str') -> 'GraphQuery'` | Delete one relationship, with both endpoints scoped to the caller's tenant. |
| `relationship_match` | `relationship_match(relationship: 'RelationshipType', *, tenant: 'str', from_label: 'Label', from_id: 'str', to_label: 'Label', to_id: 'str') -> 'GraphQuery'` | Select one relationship, with *both* endpoints scoped to the caller's tenant. |

## `jdlib.integrations.mcp`

`__all__` (16 names) · documented in [mcp](../jdlib/capabilities/mcp.md), [mcp](../jdlib/features/mcp.md)

| Name | Signature | Summary |
|---|---|---|
| `McpArgumentsRefusedError` | `McpArgumentsRefusedError(/, *args, **kwargs)` | A call the tool's own declaration does not describe. |
| `McpError` | `McpError(/, *args, **kwargs)` | Base for every MCP failure. |
| `McpServerUnavailableError` | `McpServerUnavailableError(/, *args, **kwargs)` | The server factory needs the optional `mcp` extra; importing the library does not. |
| `McpInvoker` | `McpInvoker(*, boundary: 'McpSecurityBoundary', registry: 'McpToolRegistry', enforcer: 'Any', uow_factory: 'Callable[[], Any] | None' = None, emitter: 'SecurityEventEmitter | None' = None, tracer: 'TracerLike | None' = None, gate: 'ConcurrencyGate | None' = None, timeout: 'float | None' = None, shutdown: 'ShutdownCoordinator | None' = None, resources: 'Any' = None) -> 'None'` | Runs one tool call through the library's own chain. |
| `McpSecurityBoundary` | `McpSecurityBoundary(*, principal_provider: 'PrincipalProvider', chain: 'ResolverChain', factory: 'ContextFactory', tracer: 'TracerLike | None' = None, emitter: 'SecurityEventEmitter | None' = None, auth_method: 'Callable[[], AuthMethod] | None' = None) -> 'None'` | Establishes the authoritative context for one MCP request. |
| `McpTool` | `McpTool(name: 'str', description: 'str', handler: 'Callable[..., Awaitable[Any]]', capability: 'str | None' = None, public: 'bool' = False, resource_kind: 'str' = '', action: 'str' = '', privileged: 'bool' = False, sensitive: 'bool' = False, input_schema: 'Mapping[str, object]' = <factory>) -> None` | One tool: its name, what it needs, and what it does. |
| `McpToolDefinitionError` | `McpToolDefinitionError(/, *args, **kwargs)` | A tool, or a registration, that cannot be described safely. |
| `McpToolExecutionError` | `McpToolExecutionError(/, *args, **kwargs)` | A tool ran and did not complete. |
| `McpResource` | `McpResource(uri: 'str', name: 'str', description: 'str', handler: 'Callable[[], Awaitable[Any]]', capability: 'str', sensitive: 'bool' = False, mime_type: 'str' = 'application/json') -> None` | A read-only resource: a URI, what it requires, and what it answers. |
| `McpToolRegistry` | `McpToolRegistry() -> 'None'` | What the surface exposes, as a value an operator can read and a test can check. |
| `build_mcp_server` | `build_mcp_server(*, boundary: 'Any', registry: 'McpToolRegistry', enforcer: 'Any', uow_factory: 'Callable[[], Any] | None' = None, emitter: 'Any' = None, tracer: 'Any' = None, resources: 'Sequence[McpResource]' = (), gate: 'Any' = None, timeout: 'float | None' = None, shutdown: 'Any' = None, name: 'str' = 'jdlib', request_source: 'Callable[[], RequestInfo] | None' = None) -> 'Any'` | Compose a FastMCP server whose tools and resources are the given declarations. |
| `graph_schema_resource` | `graph_schema_resource(vocabulary: 'GraphVocabulary') -> 'McpResource'` | The graph's declared vocabulary — a contract, not a configuration. |
| `graph_tools` | `graph_tools(repository: 'GraphRepository') -> 'tuple[McpTool, ...]'` | The graph's tools over ``repository``, in the order the registry will sort them. |
| `health_resource` | `health_resource() -> 'McpResource'` | Liveness, and nothing else. |
| `request_from_http` | `request_from_http() -> 'RequestInfo'` | The request the chain authenticates, read from the HTTP request fastmcp is serving. |
| `tenant_resource` | `tenant_resource() -> 'McpResource'` | The caller's own tenancy, described from the ambient context and nowhere else. |

## `jdlib.query`

`__all__` (21 names) · documented in [query](../jdlib/capabilities/query.md)

| Name | Signature | Summary |
|---|---|---|
| `OPERATORS` | | Built-in immutable sequence. |
| `TENANT_PARAMETER` | | str(object='') -> str |
| `CompiledQuery` | `CompiledQuery(text: 'str', parameters: 'dict[str, object]', names_in_order: 'tuple[str, ...]' = (), dialect: 'str' = 'postgres') -> None` | Text and its bound parameters as one value. |
| `CrossTenantQueryError` | `CrossTenantQueryError(/, *args, **kwargs)` | A specification does not agree with the security context that would run it. |
| `Filter` | `Filter(/, **data: 'Any') -> 'None'` | One predicate. ``operator`` is a name from the policy's allowlist, never a fragment. |
| `IdentifierPolicy` | `IdentifierPolicy(tables: 'Mapping[str, Sequence[str]]', tenant_scoped: 'Sequence[str]' = (), tenant_plane: 'Sequence[str]' = (), max_columns: 'int' = 16, max_filters: 'int' = 16, max_in_values: 'int' = 1000, max_limit: 'int' = 10000, max_sort_keys: 'int' = 4) -> None` | Which tables may be queried, which columns they have, and what may not be queried. |
| `MysqlDialect` | `MysqlDialect(name: 'str' = 'mysql', quote_char: 'str' = '`', parameter_prefix: 'str' = ':') -> None` | MysqlDialect(name: 'str' = 'mysql', quote_char: 'str' = '`', parameter_prefix: 'str' = ':') |
| `PostgresDialect` | `PostgresDialect(name: 'str' = 'postgres', quote_char: 'str' = '"', parameter_prefix: 'str' = ':') -> None` | PostgresDialect(name: 'str' = 'postgres', quote_char: 'str' = '"', parameter_prefix: 'str' = ':') |
| `Predicate` | `Predicate(column: 'str', operator: 'str', value: 'object') -> None` | Predicate(column: 'str', operator: 'str', value: 'object') |
| `QueryCompiler` | `QueryCompiler(policy: 'IdentifierPolicy', dialect: 'QueryDialect' = <factory>, tracer: 'TracerLike | None' = None, emitter: 'SecurityEventEmitter | None' = None) -> None` | Renders a parsed specification to SQL for one dialect, binding every value. |
| `QueryComplexityError` | `QueryComplexityError(/, *args, **kwargs)` | A specification was within the schema but outside the bounds on cost. |
| `QueryDialect` | `QueryDialect(name: 'str' = 'generic', quote_char: 'str' = '"', parameter_prefix: 'str' = ':') -> None` | How one engine spells identifiers and bind parameters. |
| `QueryError` | `QueryError(/, *args, **kwargs)` | Base for every query failure. |
| `QueryNode` | `QueryNode(table: 'str', columns: 'tuple[str, ...]', predicates: 'tuple[Predicate, ...]', order_by: 'tuple[SortColumn, ...]', limit: 'int', offset: 'int', tenant_scoped: 'bool') -> None` | A parsed specification: identifiers already checked against the policy. |
| `QueryParseError` | `QueryParseError(/, *args, **kwargs)` | A specification was refused while being parsed, before any compiler saw it. |
| `QuerySpecification` | `QuerySpecification(/, **data: 'Any') -> 'None'` | — |
| `SortColumn` | `SortColumn(column: 'str', direction: 'SortDirection') -> None` | SortColumn(column: 'str', direction: 'SortDirection') |
| `SortDirection` | `SortDirection(*args, **kwds)` | — |
| `SortKey` | `SortKey(/, **data: 'Any') -> 'None'` | — |
| `TenantPlaneQueryError` | `TenantPlaneQueryError(/, *args, **kwargs)` | A specification named a table that only TenantRepository may read (ADR-1). |
| `parse_specification` | `parse_specification(spec: 'QuerySpecification', policy: 'IdentifierPolicy') -> 'QueryNode'` | Validate a specification against the policy, and return the parsed form. |

## `jdlib.reliability`

`__all__` (11 names)

| Name | Signature | Summary |
|---|---|---|
| `backoff_seconds` | `backoff_seconds(backoff: 'timedelta', attempt: 'int', jitter: 'Callable[[float, float], float]') -> 'float'` | Exponential backoff with full jitter: the ceiling doubles, the wait is drawn under it. |
| `BreakerPolicy` | `BreakerPolicy(failure_threshold: 'int' = 5, reset_after: 'timedelta' = datetime.timedelta(seconds=30)) -> None` | When to open, and how long to wait before probing. |
| `BreakerState` | `BreakerState(*args, **kwds)` | Closed admits, open refuses, half-open admits exactly one trial. |
| `CircuitBreaker` | `CircuitBreaker(*, policy: 'BreakerPolicy | None' = None, clock: 'Callable[[], datetime]') -> 'None'` | Closed -> Open after ``failure_threshold`` consecutive failures. |
| `DrainHook` | `Callable(*args, **kwargs)` | — |
| `is_retryable_failure` | `is_retryable_failure(exc: 'BaseException') -> 'bool'` | The taxonomy first, the error's own flag second: one classification, not two. |
| `RetryBudget` | `RetryBudget(capacity: 'int' = 20, refill_per_second: 'float' = 1.0) -> None` | Tokens shared by every call that consults the same budget. |
| `RetryBudgetExhaustedError` | `RetryBudgetExhaustedError(/, *args, **kwargs)` | A retry was refused because the shared budget had no tokens left. |
| `ShutdownCoordinator` | `ShutdownCoordinator(*, timeout: 'float' = 5.0) -> 'None'` | The one place that knows whether work is admitted and what is still draining. |
| `ShutdownInProgressError` | `ShutdownInProgressError(/, *args, **kwargs)` | Work was offered after the shutdown began, and was refused. |
| `ShutdownReport` | `ShutdownReport(drained: 'Mapping[str, int]', failed: 'Mapping[str, str]', abandoned: 'Mapping[str, str]') -> None` | What a shutdown left behind, by name. |

## `jdlib.resources`

`__all__` (4 names) · documented in [resources](../jdlib/capabilities/resources.md)

| Name | Signature | Summary |
|---|---|---|
| `ConnectionConfig` | `ConnectionConfig(handle: 'str', target: 'str', credential_version: 'str', tenant_id: 'str', server_settings: 'Mapping[str, str]' = <factory>) -> None` | A hydrated target: what to connect to, and which credential version produced it. |
| `ResourceHandle` | `ResourceHandle(value: 'str') -> None` | An opaque name for a resource, such as ``db-tenant-acme``. |
| `ResourceHydrationError` | `ResourceHydrationError(/, *args, **kwargs)` | A resource could not be hydrated, and nothing was substituted for it. |
| `ResourceResolver` | `ResourceResolver(*, secrets: 'Any', cache: 'CacheProvider', check_tenant: 'TenantCheck | None' = None, check_resource: 'ResourceCheck | None' = None, check_privilege: 'PrivilegeCheck | None' = None, tracer: 'TracerLike | None' = None, emitter: 'SecurityEventEmitter | None' = None) -> 'None'` | Turns a handle into a connection target, lazily and deterministically. |

## `jdlib.security`

`__all__` (38 names)

| Name | Signature | Summary |
|---|---|---|
| `AuthMethod` | `AuthMethod(*args, **kwds)` | How the current request was authenticated. |
| `RequestIds` | `RequestIds(request_id: 'str', correlation_id: 'str | None' = None, trace_id: 'str | None' = None) -> None` | Trusted request, correlation and trace identifiers for one request. |
| `SecurityContext` | `SecurityContext(principal: 'Principal', request_ids: 'RequestIds', auth_method: 'AuthMethod', tenant: 'TenantContext | None' = None, token_metadata: 'TokenMetadata | None' = None) -> None` | Immutable, request-scoped authentication and tenancy context. |
| `TokenMetadata` | `TokenMetadata(issuer: 'str | None' = None, audience: 'str | None' = None, subject: 'str | None' = None, token_type: 'str | None' = None, jti: 'str | None' = None, expires_at: 'datetime | None' = None, scopes: 'frozenset[str] | None' = None, client_id: 'str | None' = None) -> None` | Non-secret metadata about the credential used for authentication. |
| `current_security_context` | `current_security_context() -> 'SecurityContext'` | Return the bound security context, failing closed when absent. |
| `current_security_context_or_none` | `current_security_context_or_none() -> 'SecurityContext | None'` | Return the bound security context, or ``None`` when absent. |
| `new_request_ids` | `new_request_ids() -> 'RequestIds'` | Generate identifiers for a request that arrives without them. |
| `security_context_scope` | `security_context_scope(context: 'SecurityContext') -> 'Iterator[SecurityContext]'` | Bind ``context`` for the duration of the block. |
| `AuditConfig` | `AuditConfig(/, **data: 'Any') -> 'None'` | Audit posture. |
| `AuthenticationConfig` | `AuthenticationConfig(/, **data: 'Any') -> 'None'` | Inbound authentication posture. |
| `AuthorizationConfig` | `AuthorizationConfig(/, **data: 'Any') -> 'None'` | Authorization (PEP/PDP) posture. |
| `ComplianceConfig` | `ComplianceConfig(/, **data: 'Any') -> 'None'` | Deployment profile used for posture validation. |
| `Environment` | `Environment(*args, **kwds)` | Deployment environment governing the required security posture. |
| `GatewayConfig` | `GatewayConfig(/, **data: 'Any') -> 'None'` | Trust model for identity information arriving from an API gateway. |
| `ObservabilityConfig` | `ObservabilityConfig(/, **data: 'Any') -> 'None'` | Observability posture. |
| `SecurityConfig` | `SecurityConfig(/, **data: 'Any') -> 'None'` | Complete security configuration; validated on construction. |
| `TenantSecurityConfig` | `TenantSecurityConfig(/, **data: 'Any') -> 'None'` | Tenancy and data-boundary posture. |
| `assert_strong_signing_key` | `assert_strong_signing_key(key: 'SecretStr | str', *, minimum_bytes: 'int' = 32) -> 'None'` | Fail closed when an HMAC signing key is blank or too short. |
| `validate_security_config` | `validate_security_config(config: 'SecurityConfig') -> 'None'` | Validate a security configuration, raising on any unsafe combination. |
| `AuthorizationUnavailable` | `AuthorizationUnavailable(/, *args, **kwargs)` | A policy decision could not be taken because the engine was unavailable. |
| `SecurityClassification` | `SecurityClassification(*args, **kwds)` | Security domain a failure belongs to (for audit, metrics, policy). |
| `SecurityCode` | `SecurityCode(*args, **kwds)` | Stable, machine-readable security error codes. |
| `SecurityConfigurationError` | `SecurityConfigurationError(/, *args, **kwargs)` | Unsafe or incoherent security configuration (spec #21, #31, #75). |
| `SecurityDescriptor` | `SecurityDescriptor(code: 'SecurityCode', http_status: 'int', retryable: 'bool', classification: 'SecurityClassification') -> None` | Immutable description of how a failure is reported. |
| `describe_error` | `describe_error(target: 'BaseException | type[BaseException]') -> 'SecurityDescriptor'` | Return the descriptor for an error class or instance. |
| `is_retryable` | `is_retryable(target: 'BaseException | type[BaseException]') -> 'bool'` | Return whether the failure is transient and safe to retry. |
| `security_code` | `security_code(target: 'BaseException | type[BaseException]') -> 'SecurityCode'` | Return the stable code for an error class or instance. |
| `www_authenticate` | `www_authenticate(target: 'BaseException | type[BaseException]') -> 'str | None'` | Return the ``WWW-Authenticate`` challenge for 401 failures. |
| `ErrorResponse` | `ErrorResponse(status: 'int', payload: 'Mapping[str, str]', headers: 'Mapping[str, str]') -> None` | A status, a safe payload and response headers. |
| `error_response` | `error_response(exc: 'BaseException', *, request_ids: 'RequestIds', descriptor: 'SecurityDescriptor | None' = None, status: 'int | None' = None, message: 'str | None' = None) -> 'ErrorResponse'` | Build the client-visible response for a failure. |
| `GatewayAdapter` | `GatewayAdapter(*args, **kwargs)` | Edge/gateway integration: identity propagation and edge metadata. |
| `GatewayIdentity` | `GatewayIdentity(subject: 'str', tenant_slug: 'str | None', scopes: 'frozenset[str]', issued_at: 'datetime', expires_at: 'datetime') -> None` | Identity asserted by a trusted API gateway, bound to a validity window. |
| `OutboundToken` | `OutboundToken(value: 'SecretStr', expires_at: 'datetime', token_type: 'str' = 'Bearer') -> None` | A service credential for calling another system. |
| `RateLimitDecision` | `RateLimitDecision(allowed: 'bool' = False, limit: 'int | None' = None, remaining: 'int | None' = None, retry_after: 'timedelta | None' = None) -> None` | Outcome of a rate-limit check; defaults to denied (fail closed). |
| `RateLimiter` | `RateLimiter(*args, **kwargs)` | Rate limiting is delegated to an adapter (gateway, Redis, custom). |
| `TokenProvider` | `TokenProvider(*args, **kwargs)` | Outbound service authentication (client credentials, private_key_jwt). |
| `TokenValidator` | `TokenValidator(*args, **kwargs)` | Inbound token validation (JWT/JWKS/OIDC, introspection, ...). |
| `ValidatedToken` | `ValidatedToken(subject: 'str', metadata: 'TokenMetadata', scopes: 'frozenset[str]' = frozenset()) -> None` | Result of validating an inbound credential. |

## `jdlib.security.audit`

`__all__` (26 names) · documented in [audit](../jdlib/features/audit.md)

| Name | Signature | Summary |
|---|---|---|
| `DEFAULT_EXPORT_LIMIT` | | int([x]) -> integer |
| `MAX_EXPORT_LIMIT` | | int([x]) -> integer |
| `AuditAccess` | `AuditAccess(scopes: 'frozenset[str] | None' = None, platform_operator: 'bool' = False) -> None` | What a principal may do with the audit trail. |
| `AuditControlPlaneAudit` | `AuditControlPlaneAudit(sink: 'SecurityEventSink') -> 'None'` | Serve the control plane's audit seats from one object. |
| `AuditPrivilegeAudit` | `AuditPrivilegeAudit(sink: 'SecurityEventSink', extra_metadata: 'Mapping[str, object] | None' = None) -> 'None'` | Emit ``PRIVILEGE_ISSUED`` whenever a privilege is minted. |
| `AuditRawSqlAuditor` | `AuditRawSqlAuditor(sink: 'SecurityEventSink') -> 'None'` | Emit the privileged raw-SQL trail, including refused attempts. |
| `AuditCapability` | `AuditCapability(*args, **kwds)` | Capabilities over the audit trail. |
| `AuditOutcome` | `AuditOutcome(*args, **kwds)` | What happened. |
| `AuditPage` | `AuditPage(events: 'tuple[SecurityAuditEvent, ...]', next_offset: 'int | None' = None) -> None` | A bounded slice of the trail, plus how to ask for the next one. |
| `AuditQuery` | `AuditQuery(event_types: 'tuple[SecurityEventType, ...]' = (), outcomes: 'tuple[AuditOutcome, ...]' = (), principal_id: 'uuid.UUID | None' = None, resource_type: 'str | None' = None, resource_id: 'str | None' = None, request_id: 'str | None' = None, correlation_id: 'str | None' = None, since: 'datetime | None' = None, until: 'datetime | None' = None, tenant_id: 'uuid.UUID | None' = None, limit: 'int' = 100, offset: 'int' = 0) -> None` | Narrowing filters for a read. Never widens beyond the bound tenant. |
| `AuditSource` | `AuditSource(*args, **kwds)` | Where the event was produced. |
| `DecisionObserver` | `Callable(*args, **kwargs)` | — |
| `NullSecurityEventSink` | `NullSecurityEventSink(/, *args, **kwargs)` | Drop every event. |
| `SecurityAuditEvent` | `SecurityAuditEvent(event_type: 'SecurityEventType', outcome: 'AuditOutcome', action: 'str', source: 'AuditSource', event_id: 'uuid.UUID' = <factory>, occurred_at: 'datetime' = <factory>, tenant_id: 'uuid.UUID | None' = None, principal_id: 'uuid.UUID | None' = None, principal_kind: 'str | None' = None, resource_type: 'str | None' = None, resource_id: 'str | None' = None, request_id: 'str | None' = None, correlation_id: 'str | None' = None, trace_id: 'str | None' = None, metadata: 'Mapping[str, object]' = <factory>) -> None` | One security-relevant event, ready to be persisted or exported. |
| `SecurityEventSink` | `SecurityEventSink(*args, **kwargs)` | Where security events go. |
| `SecurityEventType` | `SecurityEventType(*args, **kwds)` | Stable security event names (directive §4). |
| `TransactionAuditSink` | `TransactionAuditSink(session: 'object') -> 'None'` | Persist events in the caller's transaction. |
| `audit_metadata` | `audit_metadata(mapping: 'Mapping[str, object] | None') -> 'dict[str, object]'` | Validate, sanitize and copy audit metadata. |
| `authorization_audit_event` | `authorization_audit_event(query: 'AuthorizationQuery', decision: 'AuthorizationDecision', *, source: 'AuditSource' = <AuditSource.API: 'API'>) -> 'SecurityAuditEvent'` | Describe an authorization decision as an audit event. |
| `authorization_audit_observer` | `authorization_audit_observer(sink: 'SecurityEventSink', *, source: 'AuditSource' = <AuditSource.API: 'API'>) -> 'DecisionObserver'` | Build the observer that feeds an authorization sink. |
| `export_events` | `export_events(session: 'object', *, access: 'AuditAccess', tenant_id: 'uuid.UUID', query: 'AuditQuery | None' = None, fmt: 'str' = 'json', on_export: 'SecurityEventSink | None' = None) -> 'str'` | Render a bounded, authorized slice of the trail. |
| `iter_records` | `iter_records(page: 'AuditPage') -> 'Iterable[Mapping[str, object]]'` | Machine-readable records without rendering (for a custom writer). |
| `read_events` | `read_events(session: 'object', *, access: 'AuditAccess', tenant_id: 'uuid.UUID', query: 'AuditQuery | None' = None) -> 'AuditPage'` | Read the trail for ``tenant_id`` — that tenant only, by construction. |
| `render_csv` | `render_csv(page: 'AuditPage') -> 'str'` | CSV with a stable header; metadata is JSON in a single column. |
| `render_json` | `render_json(page: 'AuditPage') -> 'str'` | Deterministic JSON array (fixed field order, one trailing newline). |
| `render_jsonl` | `render_jsonl(page: 'AuditPage') -> 'str'` | One JSON object per line — the format to stream or append. |

## `jdlib.security.authn`

`__all__` (16 names)

| Name | Signature | Summary |
|---|---|---|
| `ASYMMETRIC_ALGORITHMS` | | frozenset() -> empty frozenset object |
| `ClientAuthMethod` | `ClientAuthMethod(*args, **kwds)` | How the client authenticates at the token endpoint. |
| `ClientCredentialsConfig` | `ClientCredentialsConfig(/, **data: 'Any') -> 'None'` | Configuration for outbound client-credentials authentication. |
| `ClientCredentialsTokenProvider` | `ClientCredentialsTokenProvider(*, config: 'ClientCredentialsConfig', fetch: 'TokenFetch', clock: 'Clock | None' = None, sleeper: 'Callable[[float], Awaitable[None]] | None' = None, jitter: 'Callable[[float, float], float] | None' = None) -> 'None'` | Acquires and caches outbound service tokens (spec #7, #76). |
| `JwksFetch` | `Callable(*args, **kwargs)` | — |
| `JwtClaimMapping` | `JwtClaimMapping(issuer: 'str', audience: 'str', algorithms: 'tuple[str, ...]' = ('RS256',), subject_claim: 'str' = 'sub', scope_claims: 'tuple[str, ...]' = ('scope', 'scp'), client_id_claims: 'tuple[str, ...]' = ('client_id', 'azp')) -> None` | Explicit, validated mapping of token claims onto the security model. |
| `JwtTokenValidator` | `JwtTokenValidator(*, mapping: 'JwtClaimMapping', keys: 'SigningKeySource', clock: 'Clock | None' = None, leeway: 'timedelta' = datetime.timedelta(seconds=60)) -> 'None'` | Validates inbound JWT bearer tokens and returns metadata-only results. |
| `SigningKeySource` | `SigningKeySource(*args, **kwargs)` | Supplies public signing keys by ``kid`` (e.g. a JWKS cache). |
| `TokenAcquisitionError` | `TokenAcquisitionError(/, *args, **kwargs)` | Token acquisition failed permanently (credentials, malformed response). |
| `TokenEndpointUnavailable` | `TokenEndpointUnavailable(/, *args, **kwargs)` | Token endpoint is temporarily unreachable or failing. |
| `TokenFetch` | `Callable(*args, **kwargs)` | — |
| `ZitadelConfig` | `ZitadelConfig(/, **data: 'Any') -> 'None'` | ZITADEL integration settings (spec #8). |
| `assert_safe_algorithms` | `assert_safe_algorithms(algorithms: 'Sequence[str]') -> 'None'` | Fail closed unless every configured algorithm is an asymmetric allow-listed one. |
| `build_zitadel_token_provider` | `build_zitadel_token_provider(config: 'ZitadelConfig', *, fetch: 'TokenFetch', clock: 'Clock | None' = None) -> 'ClientCredentialsTokenProvider'` | Wire the generic token provider to the ZITADEL token endpoint. |
| `build_zitadel_token_validator` | `build_zitadel_token_validator(config: 'ZitadelConfig', *, fetch: 'JwksFetch', clock: 'Clock | None' = None) -> 'JwtTokenValidator'` | Wire a hardened JWT validator to the ZITADEL JWKS endpoint. |
| `zitadel_provider_config` | `zitadel_provider_config(config: 'ZitadelConfig') -> 'ClientCredentialsConfig'` | Translate ZITADEL settings into the generic outbound-auth configuration. |

## `jdlib.security.authz`

`__all__` (8 names)

| Name | Signature | Summary |
|---|---|---|
| `AuthorizationDecision` | `AuthorizationDecision(allowed: 'bool', effect: 'Effect', decided_at: 'datetime', policy_id: 'str | None' = None, policy_version: 'str | None' = None, reason: 'str' = 'no_allow', degraded: 'bool' = False, denied_actions: 'tuple[str, ...]' = ()) -> None` | The answer, with safe metadata (directive §17). |
| `AuthorizationPEP` | `AuthorizationPEP(*, pdp: 'PolicyDecisionPoint', on_decision: 'DecisionObserver | None' = None) -> 'None'` | Turn authorization decisions into outcomes application code can rely on. |
| `AuthorizationQuery` | `AuthorizationQuery(principal_id: 'str', tenant_id: 'uuid.UUID', resource_kind: 'str', resource_id: 'str', actions: 'tuple[str, ...]', roles: 'frozenset[str]' = frozenset(), attributes: 'Mapping[str, object]' = <factory>, principal_attributes: 'Mapping[str, object]' = <factory>, request_id: 'str | None' = None) -> None` | What is being asked of the policy engine, in neutral terms. |
| `CerbosConfig` | `CerbosConfig(/, **data: 'Any') -> 'None'` | Cerbos coordinates. |
| `CerbosPDP` | `CerbosPDP(*, config: 'CerbosConfig', transport: 'CerbosTransport', clock: 'Clock | None' = None) -> 'None'` | Ask Cerbos for a decision, and never for permission to skip asking. |
| `CerbosTransport` | `Callable(*args, **kwargs)` | — |
| `Effect` | `Effect(*args, **kwds)` | The outcome a policy engine can return. |
| `PolicyDecisionPoint` | `PolicyDecisionPoint(*args, **kwargs)` | An external policy engine that answers authorization queries. |

## `jdlib.security.compliance`

`__all__` (22 names)

| Name | Signature | Summary |
|---|---|---|
| `CONFIGURATION_EVIDENCE_KEYS` | | frozenset() -> empty frozenset object |
| `CONTROL_REGISTRY` | | — |
| `MIGRATION_BRANCHES` | | Built-in immutable sequence. |
| `POSTURE_RULES` | | dict() -> new empty dictionary |
| `Control` | `Control(control_id: 'str', title: 'str', description: 'str', category: 'ControlCategory', implementation_status: 'ImplementationStatus', mappings: 'tuple[ControlMapping, ...]', evidence_requirements: 'tuple[str, ...]', evidence_sources: 'tuple[str, ...]', technical_owner: 'str', verification_method: 'VerificationMethod', status_note: 'str | None' = None) -> None` | One control, with everything an evidence collector or an assessor needs. |
| `ControlCategory` | `ControlCategory(*args, **kwds)` | What a control protects, so posture can be grouped by concern. |
| `ControlFramework` | `ControlFramework(*args, **kwds)` | The framework families a control can be mapped onto (directive §9.1). |
| `ControlMapping` | `ControlMapping(framework: 'ControlFramework', reference: 'str') -> None` | Where a control is described in one framework. |
| `ImplementationStatus` | `ImplementationStatus(*args, **kwds)` | How far the control is implemented *in this library*. |
| `PostureFinding` | `PostureFinding(control_id: 'str', outcome: 'PostureOutcome', severity: 'Severity', title: 'str', reason: 'str', evidence: 'tuple[SecurityEvidence, ...]' = ()) -> None` | One control, one outcome, and the explanation behind it. |
| `PostureOutcome` | `PostureOutcome(*args, **kwds)` | What today's check said about a control. |
| `PostureReport` | `PostureReport(findings: 'tuple[PostureFinding, ...]', generated_at: 'datetime', environment: 'str') -> None` | Every control in the registry, exactly once, in a deterministic order. |
| `SecurityEvidence` | `SecurityEvidence(control_id: 'str', subject: 'str', collected_by: 'str', collected_at: 'datetime', observations: 'Mapping[str, object]', reproducible: 'str', evidence_id: 'uuid.UUID' = <factory>, environment: 'str | None' = None) -> None` | One observation about the system, ready to be reported or stored. |
| `Severity` | `Severity(*args, **kwds)` | How much attention an outcome deserves. |
| `VerificationMethod` | `VerificationMethod(*args, **kwds)` | How the claim is shown to be true (directive §9.2). |
| `collect_configuration_evidence` | `collect_configuration_evidence(config: 'SecurityConfig', *, clock: 'Clock | None' = None, environment: 'str | None' = None) -> 'SecurityEvidence'` | Observe the security configuration's posture-relevant facts. |
| `collect_migration_evidence` | `collect_migration_evidence(*, root: 'pathlib.Path | None' = None, clock: 'Clock | None' = None, environment: 'str | None' = None) -> 'SecurityEvidence'` | Observe the revision history this checkout carries, per branch. |
| `collect_policy_evidence` | `collect_policy_evidence(directory: 'pathlib.Path | str', *, pdp_kind: 'str', clock: 'Clock | None' = None, environment: 'str | None' = None) -> 'SecurityEvidence'` | Observe the policy files a deployment declares for its decision point. |
| `control_by_id` | `control_by_id(control_id: 'str') -> 'Control | None'` | Look a control up by id, returning ``None`` when it is not registered. |
| `controls_for_framework` | `controls_for_framework(framework: 'ControlFramework') -> 'tuple[Control, ...]'` | Every control mapped into ``framework``, in registry order. |
| `evaluate_posture` | `evaluate_posture(config: 'SecurityConfig', *, evidence: 'Iterable[SecurityEvidence]' = (), rules: 'Mapping[str, PostureRule] | None' = None, clock: 'Clock | None' = None, environment: 'str | None' = None) -> 'PostureReport'` | Evaluate every control in the registry against this configuration. |
| `frameworks_in_use` | `frameworks_in_use() -> 'tuple[ControlFramework, ...]'` | The frameworks the registry maps onto, in declaration order. |

## `jdlib.security.gateway`

`__all__` (5 names)

| Name | Signature | Summary |
|---|---|---|
| `GatewayConfig` | `GatewayConfig(/, **data: 'Any') -> 'None'` | Trusted-gateway configuration. |
| `GatewayMode` | `GatewayMode(*args, **kwds)` | How (and whether) gateway identity assertions are verified. |
| `KongGatewayAdapter` | `KongGatewayAdapter(*, config: 'GatewayConfig', clock: 'Clock | None' = None) -> 'None'` | Kong (``kong:3.x``) by default injects ``x-jdlib-*`` headers. |
| `NoGatewayAdapter` | `NoGatewayAdapter() -> 'None'` | No gateway: identity may never come from request headers. |
| `TykGatewayAdapter` | `TykGatewayAdapter(*, config: 'GatewayConfig', clock: 'Clock | None' = None) -> 'None'` | Tyk uses its own namespaced headers by default. |

## `jdlib.storage`

`__all__` (11 names) · documented in [storage](../jdlib/capabilities/storage.md), [storage](../jdlib/features/storage.md)

| Name | Signature | Summary |
|---|---|---|
| `AuthorizationRefusedError` | `AuthorizationRefusedError(/, *args, **kwargs)` | The provider could not verify it was given an authorized context, and refused to open. |
| `InvalidObjectKeyError` | `InvalidObjectKeyError(/, *args, **kwargs)` | A key was refused before it reached the store. |
| `ObjectMetadata` | `ObjectMetadata(key: 'str', size: 'int', etag: 'str', content_type: 'str | None' = None, last_modified: 'datetime | None' = None) -> None` | What the store knows about an object without transferring its body. |
| `ObjectNotFoundError` | `ObjectNotFoundError(/, *args, **kwargs)` | The object is not there. Distinct from 'the store is unreachable', which is not a 404. |
| `ObjectStorageError` | `ObjectStorageError(/, *args, **kwargs)` | Base for object storage failures. |
| `ObjectStorageProvider` | `ObjectStorageProvider(*args, **kwargs)` | What a storage backend must implement. Asynchronous throughout (ADR-14). |
| `S3ObjectStorage` | `S3ObjectStorage(*, chunk_size: 'int' = 8192) -> 'None'` | S3-compatible object storage: the one verified backend (ADR-5). |
| `StoredObject` | `StoredObject(key: 'str', size: 'int', etag: 'str') -> None` | A confirmed write: the key as stored, its size, and the store's entity tag. |
| `assert_object_storage_contract` | `assert_object_storage_contract(candidate: 'Any') -> 'list[str]'` | Every problem with a candidate backend, so one can be refused at startup. |
| `object_key` | `object_key(tenant_id: 'str', key: 'str') -> 'str'` | The only place a stored key is built, so no caller can place an object elsewhere. |
| `tenant_prefix` | `tenant_prefix(tenant_id: 'str') -> 'str'` | — |

## `jdlib.testing`

`__all__` (3 names)

| Name | Signature | Summary |
|---|---|---|
| `assert_cross_tenant_write_rejected` | `assert_cross_tenant_write_rejected(session_factory: 'Callable[[], AsyncSession]', context_a: 'TenantContext', model: 'type[Any]', **values: 'Any') -> 'None'` | Assert a row owned by another tenant cannot be flushed under ``context_a``. |
| `assert_scoped_count` | `assert_scoped_count(session_factory: 'Callable[[], AsyncSession]', context: 'TenantContext', model: 'type[Any]', expected: 'int') -> 'None'` | Assert that ``model`` has exactly ``expected`` rows visible to ``context``. |
| `assert_tenant_isolated` | `assert_tenant_isolated(session_factory: 'Callable[[], AsyncSession]', context_a: 'TenantContext', context_b: 'TenantContext', model: 'type[Any]', **values: 'Any') -> 'uuid.UUID'` | Create a ``model`` row for ``context_b`` and assert ``context_a`` cannot see it. |

## Regenerating

```bash
python scripts/api-reference.py            # write the page
python scripts/api-reference.py --check    # fail when it is stale
```
