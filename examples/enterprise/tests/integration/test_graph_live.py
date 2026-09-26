"""The graph plane against a real Neo4j: the binding, the vocabulary and the projection.

Skipped unless ``JDLIB_EXAMPLE_GRAPH_URI`` points at a running server:

    export JDLIB_ENTERPRISE_GRAPH_PASSWORD=<any local value>   # one name, for the lab and the app
    docker compose -f examples/enterprise/docker/docker-compose.yml up -d neo4j
    export JDLIB_EXAMPLE_GRAPH_URI=bolt://127.0.0.1:7688
    pytest examples/enterprise/tests/test_graph_live.py -q -W error


The unit layer can prove the wiring; only the server can prove the protocol and the mapping. What is
asserted here and nowhere else:

* a projected node comes back over a **fresh client**, with the properties that were written — the
  positive path, because a suite of refusals cannot see a write that stored nothing;
* a client opened for one tenant **refuses** another tenant's statement — the binding, not a filter
  the caller could forget;
* the node is invisible to the other tenant's client, which is the property the whole plane exists
  for;
* an undeclared label never reaches a statement: the vocabulary refuses it first.

Every tenant id here is generated per run, so nothing in this file can pass on state a previous
session left in the container.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager

import pytest
from neo4j import Driver, GraphDatabase

from examples.enterprise.app.graph import (
    GRAPH_PASSWORD_HANDLE,
    VOCABULARY,
    GraphPlane,
    ensure_graph_constraints,
    graph_config,
    graph_secret_provider,
)
from examples.enterprise.app.models.resources import Resource
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.credentials.refs import SecretRef
from jdlib.graph import (
    GraphConfig,
    GraphConflictError,
    GraphTenantViolationError,
    GraphValidationError,
    node_match,
)
from jdlib.security.context import AuthMethod, SecurityContext

GRAPH_URI = os.environ.get("JDLIB_EXAMPLE_GRAPH_URI", "")
GRAPH_DATABASE = os.environ.get("JDLIB_EXAMPLE_GRAPH_DATABASE", "neo4j")
GRAPH_USERNAME = os.environ.get("JDLIB_EXAMPLE_GRAPH_USERNAME", "neo4j")

pytestmark = pytest.mark.skipif(
    not GRAPH_URI,
    reason=(
        "the graph lab is not running: docker compose -f "
        "examples/enterprise/docker/docker-compose.yml up -d neo4j, then export "
        "JDLIB_EXAMPLE_GRAPH_URI=bolt://127.0.0.1:7688 (and JDLIB_ENTERPRISE_GRAPH_PASSWORD)"
    ),
)


def _tenant_context(tenant_id: uuid.UUID) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug=f"graph-{str(tenant_id)[:8]}",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), tenant_id=tenant_id),
        request_id=f"req-{uuid.uuid4().hex[:8]}",
        correlation_id=f"corr-{uuid.uuid4().hex[:8]}",
    )


def _security(tenant_id: uuid.UUID) -> SecurityContext:
    """The context the graph plane takes: a promoted tenant context, not a hand-built one."""
    return SecurityContext.from_tenant_context(
        _tenant_context(tenant_id), auth_method=AuthMethod.API_KEY
    )


def _config() -> GraphConfig:
    return graph_config(uri=GRAPH_URI, database=GRAPH_DATABASE, username=GRAPH_USERNAME)


@pytest.fixture(scope="module")
def tenants() -> Iterator[tuple[uuid.UUID, uuid.UUID]]:
    """Two tenants, generated per run: nothing here reads another run's state."""
    yield uuid.uuid4(), uuid.uuid4()


@contextmanager
def _operator_driver() -> Iterator[Driver]:
    """The operator's connection: the driver directly, with the resolved credential.

    The application never does this — the library's client refuses any statement that is not scoped
    to a tenant, and schema has no tenant to be scoped to. Schema is the operator's job, which is
    why the application's schema step lives in `bootstrap` and this file mirrors it rather than
    reusing the client.
    """
    resolved = graph_secret_provider().resolve(SecretRef(handle=GRAPH_PASSWORD_HANDLE))
    driver = GraphDatabase.driver(
        GRAPH_URI, auth=(GRAPH_USERNAME, resolved.value), connection_timeout=30.0
    )
    try:
        yield driver
    finally:
        driver.close()


@pytest.fixture(scope="module")
def graph_schema() -> None:
    """The operator step, run the way `bootstrap` runs it — on a lab that can accept it.

    A uniqueness constraint cannot be declared over data that violates it, and Neo4j refuses and
    *names the nodes* (this lab had exactly that, left by a mutation run that turned the
    projection's upsert into a create). A deployment fixes the data at that point; a lab gets the
    same treatment,
    because the alternative is a suite that is red for a reason that is not the code under test.
    """
    repair = (
        "MATCH (n:{label}) WITH n.tenant_id AS tenant_id, n.id AS id, collect(n) AS nodes "
        "WHERE size(nodes) > 1 "
        "FOREACH (duplicate IN tail(nodes) | DETACH DELETE duplicate)"
    )
    with _operator_driver() as driver, driver.session(database=GRAPH_DATABASE) as session:
        for label in sorted(VOCABULARY.labels):
            session.run(repair.format(label=label)).consume()
    ensure_graph_constraints(_config())


@asynccontextmanager
async def _plane() -> AsyncIterator[GraphPlane]:
    plane = GraphPlane(_config())
    try:
        yield plane
    finally:
        await plane.aclose()


def test_a_projected_resource_comes_back_over_a_fresh_client(
    tenants: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """The positive path: a write that stored nothing cannot hide behind refusals."""

    async def _body() -> None:
        tenant, _other = tenants
        context = _security(tenant)
        resource_id = uuid.uuid4()
        properties = {"name": f"node-{resource_id.hex[:8]}", "kind": "dataset", "status": "active"}

        async with _plane() as plane:
            await plane.project_resource(
                context=context, resource_id=resource_id, properties=properties
            )

        # A second plane: a second client, a second connection, nothing from the first one's state.
        async with _plane() as fresh:
            node = await fresh.read_resource(context=context, resource_id=resource_id)

        assert node is not None
        assert node["name"] == properties["name"]
        assert node["kind"] == "dataset"
        assert node["status"] == "active"
        assert node["id"] == str(resource_id)

    asyncio.run(_body())


def test_the_projection_updates_a_node_that_is_already_there(
    tenants: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Projecting twice is one node with the newer properties, not a conflict."""

    async def _body() -> None:
        tenant, _other = tenants
        context = _security(tenant)
        resource_id = uuid.uuid4()

        async with _plane() as plane:
            await plane.project_resource(
                context=context,
                resource_id=resource_id,
                properties={"name": "first", "kind": "dataset", "status": "active"},
            )
            await plane.project_resource(
                context=context,
                resource_id=resource_id,
                properties={"name": "second", "kind": "dataset", "status": "archived"},
            )
            node = await plane.read_resource(context=context, resource_id=resource_id)

        assert node is not None
        assert node["name"] == "second"
        assert node["status"] == "archived"

    asyncio.run(_body())


def test_another_tenants_client_cannot_see_the_node(
    tenants: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """The property the plane exists for, measured on the engine rather than on the builder."""

    async def _body() -> None:
        tenant, other = tenants
        owner, intruder = _security(tenant), _security(other)
        resource_id = uuid.uuid4()

        async with _plane() as plane:
            await plane.project_resource(
                context=owner,
                resource_id=resource_id,
                properties={"name": "isolated", "kind": "dataset", "status": "active"},
            )
            assert await plane.read_resource(context=intruder, resource_id=resource_id) is None
            # And it is still there for its owner, in the same session.
            assert await plane.read_resource(context=owner, resource_id=resource_id) is not None

    asyncio.run(_body())


def test_a_statement_for_another_tenant_is_refused_by_the_client(
    tenants: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Not a filter the caller can forget: the client is bound, and it refuses.

    The statement below is well-formed and correctly scoped for the *intruder*; what refuses it is
    the client, which was opened for the owner. That distinction is the whole difference between a
    scope that is a parameter and one that is enforced.
    """

    async def _body() -> None:
        tenant, other = tenants
        owner, intruder = _security(tenant), _security(other)

        async with _plane() as plane:
            client = await plane.client_for(owner)
            with pytest.raises(GraphTenantViolationError):
                await client.run(
                    query=node_match(
                        VOCABULARY.label("Resource"),
                        tenant=str(other),
                        node_id=str(uuid.uuid4()),
                    ),
                    context=intruder,
                )

    asyncio.run(_body())


def test_an_undeclared_label_never_reaches_a_statement(
    tenants: tuple[uuid.UUID, uuid.UUID],
) -> None:
    async def _body() -> None:
        tenant, _other = tenants
        context = _security(tenant)

        async with _plane() as plane:
            repository = await plane.repository_for(context)
            with pytest.raises(GraphValidationError):
                await repository.get_node(
                    context=context, label="Invoice", node_id=str(uuid.uuid4())
                )
            with pytest.raises(GraphValidationError):
                await repository.create_node(
                    context=context,
                    label="Resource",
                    node_id=str(uuid.uuid4()),
                    properties={"secret": "not in this vocabulary"},
                )

    asyncio.run(_body())


def test_the_projection_carries_the_rows_own_identity(
    tenants: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """The projection is derived from the row: its id is the row's, so the two can be joined."""

    async def _body() -> None:
        tenant, _other = tenants
        context = _security(tenant)
        resource = Resource(
            tenant_id=tenant, id=uuid.uuid4(), name=f"row-{uuid.uuid4().hex[:8]}", kind="document"
        )

        async with _plane() as plane:
            await plane.project_resource(
                context=context,
                resource_id=resource.id,
                properties={
                    "name": resource.name,
                    "kind": resource.kind,
                    "status": resource.status,
                },
            )
            node = await plane.read_resource(context=context, resource_id=resource.id)

        assert node is not None
        assert node["id"] == str(resource.id)
        assert node["name"] == resource.name

    asyncio.run(_body())


def test_the_operator_step_declares_the_identity_constraint(
    tenants: tuple[uuid.UUID, uuid.UUID], graph_schema: None
) -> None:
    """The constraint is what makes "project twice" an update rather than a second node.

    Two assertions, and the second is the tenancy of the first: the same node id in *another*
    tenant is not a conflict, because the constraint is on the pair.
    """

    async def _body() -> None:
        tenant, other = tenants
        owner, neighbour = _security(tenant), _security(other)
        resource_id = uuid.uuid4()
        properties = {"name": "constrained", "kind": "dataset", "status": "active"}

        async with _plane() as plane:
            repository = await plane.repository_for(owner)
            await repository.create_node(
                context=owner,
                label="Resource",
                node_id=str(resource_id),
                properties=properties,
            )
            with pytest.raises(GraphConflictError):
                await repository.create_node(
                    context=owner,
                    label="Resource",
                    node_id=str(resource_id),
                    properties=properties,
                )

            # The same id, a different tenant: no conflict, because the constraint is the pair.
            neighbour_repository = await plane.repository_for(neighbour)
            await neighbour_repository.create_node(
                context=neighbour,
                label="Resource",
                node_id=str(resource_id),
                properties=properties,
            )

    asyncio.run(_body())
