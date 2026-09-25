"""The Neo4j client: what it holds, what it refuses, and what it maps (directive §10–§11, §15).

Three properties are this adapter's own, and each is here because it can regress silently:

* the driver is imported when a client opens, never when the library is imported, so the
  optional dependency stays optional — proven in a subprocess, because an in-process check
  would pass or fail on collection order;
* the tenant a statement runs under is checked against the authenticated tenant at the last
  point where both halves are visible, so a repository bug cannot become a cross-tenant read,
  and the refusal is proven by *nothing reaching the driver*;
* the driver's failures arrive as the graph taxonomy, and no driver message is interpolated
  into a graph error — a driver message can quote the statement it rejected.
"""

from __future__ import annotations

import inspect
import subprocess
import sys
import types
import uuid
from typing import Any

import pytest

from jdlib.credentials import SecretRef
from jdlib.errors import MissingTenantContext
from jdlib.graph import (
    GraphConfig,
    GraphConflictError,
    GraphError,
    GraphQueryError,
    GraphTenantViolationError,
    GraphTimeoutError,
    GraphUnavailableError,
    GraphVocabulary,
    node_match,
)
from jdlib.graph.client import GraphClient, Neo4jClient
from jdlib.graph.policy import GraphPolicy
from jdlib.graph.query import GraphQuery
from jdlib.security.context import SecurityContext
from tests.support.graph_fakes import (
    OTHER_TENANT_ID,
    RESOLVED,
    TENANT_ID,
    DriverFactory,
    FakeDriver,
    RecordingProvider,
    graph_context,
)

URI = "neo4j+s://graph.internal:7687"
VOCABULARY = GraphVocabulary(
    labels=frozenset({"User"}),
    relationship_types=frozenset({"OWNS"}),
    property_keys=frozenset({"id", "name"}),
)


def _config(**overrides: Any) -> GraphConfig:
    base: dict[str, Any] = {"uri": URI, "auth": SecretRef(handle="neo4j-app"), "database": "acme"}
    base.update(overrides)
    return GraphConfig(**base)


def _scoped(tenant: uuid.UUID = TENANT_ID) -> GraphQuery:
    return node_match(VOCABULARY.label("User"), tenant=str(tenant), node_id="u1")


def _client(
    config: GraphConfig | None = None,
    *,
    driver: FakeDriver | None = None,
    policy: GraphPolicy | None = None,
) -> tuple[Neo4jClient, RecordingProvider, DriverFactory]:
    provider = RecordingProvider()
    factory = DriverFactory(driver or FakeDriver())
    client = Neo4jClient(
        config or _config(), provider=provider, policy=policy, driver_factory=factory
    )
    return client, provider, factory


def test_the_driver_is_not_imported_when_the_library_is() -> None:
    code = "import jdlib.graph, sys; print('neo4j' in sys.modules)"
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "False"


def test_the_adapter_satisfies_the_protocol_and_is_asynchronous() -> None:
    client, _, _ = _client()
    assert isinstance(client, GraphClient)
    for name in ("open", "close", "health", "run"):
        assert inspect.iscoroutinefunction(getattr(Neo4jClient, name)), name


async def test_open_resolves_the_secret_and_hands_it_to_the_driver() -> None:
    client, provider, factory = _client()
    await client.open(context=graph_context())
    assert provider.refs == [SecretRef(handle="neo4j-app")]
    assert factory.uri == URI
    assert factory.kwargs["auth"] == ("bearer", RESOLVED)
    await client.close()


async def test_open_uses_basic_auth_when_the_config_names_a_user() -> None:
    client, _, factory = _client(_config(username="graph-app"))
    await client.open(context=graph_context())
    assert factory.kwargs["auth"] == ("graph-app", RESOLVED)
    await client.close()


async def test_the_config_maps_to_the_drivers_own_bounds() -> None:
    config = _config(
        max_connection_pool_size=7,
        connection_acquisition_timeout=1.5,
        max_connection_lifetime=60.0,
        connection_timeout=2.5,
        max_transaction_retry_time=3.0,
    )
    client, _, factory = _client(config)
    await client.open(context=graph_context())
    assert factory.kwargs["max_connection_pool_size"] == 7
    assert factory.kwargs["connection_acquisition_timeout"] == 1.5
    assert factory.kwargs["max_connection_lifetime"] == 60.0
    assert factory.kwargs["connection_timeout"] == 2.5
    assert factory.kwargs["max_transaction_retry_time"] == 3.0
    await client.close()


async def test_open_refuses_without_an_authenticated_tenant() -> None:
    client, _, factory = _client()
    with pytest.raises(MissingTenantContext):
        await client.open(context=SecurityContext.anonymous())
    assert factory.uri is None


async def test_run_sends_the_statement_with_its_parameters_and_the_database() -> None:
    driver = FakeDriver(rows=[{"id": "u1", "name": "A"}])
    client, _, _ = _client(driver=driver)
    await client.open(context=graph_context())
    rows = await client.run(query=_scoped(), context=graph_context())
    assert rows == [{"id": "u1", "name": "A"}]
    text, parameters, kwargs = driver.calls[0]
    assert parameters["jdlib_scope_tenant"] == str(TENANT_ID)
    assert "jdlib_scope_tenant" in text
    assert kwargs["timeout"] == GraphPolicy().statement_timeout
    assert driver.database == "acme"
    await client.close()


async def test_run_refuses_a_statement_scoped_to_another_tenant() -> None:
    driver = FakeDriver()
    client, _, _ = _client(driver=driver)
    await client.open(context=graph_context())
    with pytest.raises(GraphTenantViolationError):
        await client.run(query=_scoped(OTHER_TENANT_ID), context=graph_context())
    assert driver.calls == []


async def test_run_refuses_a_context_for_another_tenant_than_the_open() -> None:
    driver = FakeDriver()
    client, _, _ = _client(driver=driver)
    await client.open(context=graph_context(TENANT_ID))
    with pytest.raises(GraphTenantViolationError):
        await client.run(query=_scoped(OTHER_TENANT_ID), context=graph_context(OTHER_TENANT_ID))
    assert driver.calls == []


async def test_run_before_open_is_refused() -> None:
    client, _, _ = _client()
    with pytest.raises(GraphError):
        await client.run(query=_scoped(), context=graph_context())


async def test_a_statement_that_exceeds_the_policy_timeout_is_a_graph_timeout() -> None:
    client, _, _ = _client(driver=FakeDriver(delay=0.5), policy=GraphPolicy(statement_timeout=0.05))
    await client.open(context=graph_context())
    with pytest.raises(GraphTimeoutError):
        await client.run(query=_scoped(), context=graph_context())


async def test_health_is_false_before_open_and_follows_the_driver() -> None:
    driver = FakeDriver(reachable=False)
    client, _, _ = _client(driver=driver)
    assert await client.health() is False
    await client.open(context=graph_context())
    assert await client.health() is False
    driver.reachable = True
    assert await client.health() is True


async def test_close_closes_the_driver_and_is_safe_twice() -> None:
    driver = FakeDriver()
    client, _, _ = _client(driver=driver)
    await client.open(context=graph_context())
    await client.close()
    assert driver.closed is True
    await client.close()
    with pytest.raises(GraphError):
        await client.run(query=_scoped(), context=graph_context())


async def test_the_client_never_renders_the_resolved_secret() -> None:
    client, _, _ = _client()
    await client.open(context=graph_context())
    assert RESOLVED not in repr(client)
    await client.close()


@pytest.fixture
def driver_errors(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """A stub of the driver's exception module, hierarchy included.

    The real package is not installed for the unit layer, and the mapping must be exercised
    against the hierarchy the driver actually has — a constraint error is also a client error,
    so the order of the checks is part of the behaviour.
    """
    exceptions = types.ModuleType("neo4j.exceptions")

    class DriverError(Exception): ...

    class ServiceUnavailable(DriverError): ...

    class SessionExpired(DriverError): ...

    class Neo4jError(Exception): ...

    class ClientError(Neo4jError): ...

    class DatabaseError(Neo4jError): ...

    class TransientError(Neo4jError): ...

    class AuthError(ClientError): ...

    class Unauthorized(ClientError): ...

    class Forbidden(ClientError): ...

    class ConstraintError(ClientError): ...

    for cls in (
        DriverError,
        ServiceUnavailable,
        SessionExpired,
        Neo4jError,
        ClientError,
        DatabaseError,
        TransientError,
        AuthError,
        Unauthorized,
        Forbidden,
        ConstraintError,
    ):
        setattr(exceptions, cls.__name__, cls)
    module = types.ModuleType("neo4j")
    module.exceptions = exceptions  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "neo4j", module)
    monkeypatch.setitem(sys.modules, "neo4j.exceptions", exceptions)
    return exceptions


async def _run_with(driver_errors: types.ModuleType, error: BaseException) -> GraphError:
    client, _, _ = _client(driver=FakeDriver(error=error))
    await client.open(context=graph_context())
    with pytest.raises(GraphError) as caught:
        await client.run(query=_scoped(), context=graph_context())
    return caught.value


async def test_a_transient_driver_failure_is_a_transient_unavailable_error(
    driver_errors: types.ModuleType,
) -> None:
    error = await _run_with(driver_errors, driver_errors.ServiceUnavailable("server gone"))
    assert type(error) is GraphUnavailableError
    assert error.transient is True


async def test_a_constraint_violation_is_a_conflict(driver_errors: types.ModuleType) -> None:
    error = await _run_with(driver_errors, driver_errors.ConstraintError("already exists"))
    assert type(error) is GraphConflictError


async def test_a_refused_connection_is_not_retryable(driver_errors: types.ModuleType) -> None:
    error = await _run_with(driver_errors, driver_errors.AuthError("bad credentials"))
    assert type(error) is GraphUnavailableError
    assert error.transient is False


async def test_an_unexpected_client_error_is_a_query_error(driver_errors: types.ModuleType) -> None:
    error = await _run_with(driver_errors, driver_errors.ClientError("bad syntax"))
    assert type(error) is GraphQueryError


async def test_no_driver_message_is_interpolated_into_a_graph_error(
    driver_errors: types.ModuleType,
) -> None:
    hostile = "MATCH (n:User) WHERE n.tenant_id = 'acme' failed"
    error = await _run_with(driver_errors, driver_errors.ServiceUnavailable(hostile))
    assert "MATCH" not in str(error)
    assert "acme" not in str(error)
