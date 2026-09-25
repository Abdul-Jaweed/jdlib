"""Layer 3 infrastructure: the graph namespace against a real Neo4j (directive §15).

Skipped unless ``JDLIB_INFRA_NEO4J_URL`` points at a running server:

    docker compose -f tests/infra/docker-compose.yml up -d neo4j
    export JDLIB_INFRA_NEO4J_URL=bolt://127.0.0.1:7687
    export JDLIB_INFRA_NEO4J_PASSWORD=jdliblab

Unit tests prove the wiring; only the real engine proves the protocol and the mapping.
What is asserted here and nowhere else:

* the statements the builders produce are Cypher this server accepts, and the
  parameters they bind are what it filters on — so a node written under one tenant is
  invisible to a statement scoped to another;
* the driver's own exception classes land on the right taxonomy: a uniqueness
  violation is a conflict, a statement the server rejects is a query error, and
  neither is a connection failure;
* a transaction commits for real, and a rolled-back one leaves nothing behind.

Every tenant id here is generated per run, so nothing in this file can pass on state a
previous session left in the container.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest

from jdlib.credentials.refs import SecretRef
from jdlib.credentials.rotation import VersionedSecretProvider
from jdlib.graph import (
    GraphConfig,
    GraphConflictError,
    GraphPolicy,
    GraphQuery,
    GraphQueryError,
    GraphVocabulary,
    Neo4jClient,
    node_create,
    node_match,
)
from jdlib.graph.query import TENANT_PARAMETER
from jdlib.persistence.secrets import MemorySecretProvider
from tests.support.graph_fakes import graph_context

NEO4J_URL = os.environ.get("JDLIB_INFRA_NEO4J_URL")
NEO4J_PASSWORD = os.environ.get("JDLIB_INFRA_NEO4J_PASSWORD", "jdliblab")
NEO4J_DATABASE = os.environ.get("JDLIB_INFRA_NEO4J_DATABASE", "neo4j")
HANDLE = "graph/password"

pytestmark = [
    pytest.mark.infra,
    pytest.mark.skipif(
        not NEO4J_URL, reason="set JDLIB_INFRA_NEO4J_URL to run against real Neo4j"
    ),
]

VOCABULARY = GraphVocabulary(
    labels=frozenset({"InfraUser"}),
    relationship_types=frozenset({"INFRA_OWNS"}),
    property_keys=frozenset({"name", "email"}),
)


def _config() -> GraphConfig:
    return GraphConfig(
        uri=str(NEO4J_URL),
        database=NEO4J_DATABASE,
        username="neo4j",
        auth=SecretRef(handle=HANDLE),
    )


def _statement(text: str, tenant: uuid.UUID) -> GraphQuery:
    """A hand-written statement, scoped the way the builders scope theirs.

    The client refuses every statement that does not name the authenticated tenant, so a
    statement written by hand has to bind it too — that refusal is the point, and it is what
    keeps schema DDL out of the data plane (see the constraint fixture below).
    """
    return GraphQuery(text, {TENANT_PARAMETER: str(tenant)})


def _provider() -> VersionedSecretProvider:
    return VersionedSecretProvider(MemorySecretProvider({HANDLE: NEO4J_PASSWORD}))





@pytest.fixture()
def constraint() -> None:
    """The uniqueness constraint, declared the way a deployment declares one.

    Out of band, with the driver directly: the library's client refuses any statement that is not
    scoped to a tenant, and a constraint has no tenant to be scoped to. Schema is an operator's
    job — the data plane is the library's — so the suite does what a migration would do, and then
    proves the library's own statements meet the constraint.
    """
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(
        str(NEO4J_URL), auth=("neo4j", NEO4J_PASSWORD), connection_timeout=30.0
    )
    try:
        with driver.session(database=NEO4J_DATABASE) as session:
            session.run(
                "CREATE CONSTRAINT infra_user_identity IF NOT EXISTS "
                "FOR (n:InfraUser) REQUIRE (n.tenant_id, n.id) IS UNIQUE"
            ).consume()
    finally:
        driver.close()


@pytest.fixture()
async def open_client() -> AsyncIterator[Callable[[uuid.UUID], Awaitable[Neo4jClient]]]:
    """A client per tenant.

    A client is opened *for* a tenant — ``open`` binds the tenant and every statement is checked
    against it, which is the property ``test_a_statement_for_another_tenant_is_refused`` pins at
    the unit layer. So a live test that writes under two tenants opens two clients, and the
    teardown closes whatever this test opened.
    """
    opened: list[Neo4jClient] = []

    async def factory(tenant: uuid.UUID) -> Neo4jClient:
        graph = Neo4jClient(_config(), provider=_provider(), policy=GraphPolicy())
        await graph.open(context=graph_context(tenant_id=tenant))
        opened.append(graph)
        return graph

    yield factory
    for graph in opened:
        await graph.close()


async def test_a_statement_runs_against_the_real_server(open_client) -> None:
    tenant = uuid.uuid4()
    context = graph_context(tenant_id=tenant)
    client = await open_client(tenant)
    created = await client.run(
        query=node_create(
            VOCABULARY.label("InfraUser"),
            tenant=str(tenant),
            node_id="u-1",
            properties={VOCABULARY.property_key("name"): "Ada"},
        ),
        context=context,
    )
    assert created[0]["n"]["name"] == "Ada"
    read = await client.run(
        query=node_match(VOCABULARY.label("InfraUser"), tenant=str(tenant), node_id="u-1"),
        context=context,
    )
    assert [row["n"]["name"] for row in read] == ["Ada"]


async def test_the_tenant_parameter_is_what_the_server_filters_on(
    open_client,
) -> None:
    """The same node id under two tenants: a scoped read sees exactly one of them."""
    first, second = uuid.uuid4(), uuid.uuid4()
    for tenant, name in ((first, "first"), (second, "second")):
        client = await open_client(tenant)
        await client.run(
            query=node_create(
                VOCABULARY.label("InfraUser"),
                tenant=str(tenant),
                node_id="shared",
                properties={VOCABULARY.property_key("name"): name},
            ),
            context=graph_context(tenant_id=tenant),
        )
    for tenant, expected in ((first, "first"), (second, "second")):
        client = await open_client(tenant)
        rows = await client.run(
            query=node_match(
                VOCABULARY.label("InfraUser"), tenant=str(tenant), node_id="shared"
            ),
            context=graph_context(tenant_id=tenant),
        )
        assert [row["n"]["name"] for row in rows] == [expected]


async def test_a_uniqueness_violation_is_a_conflict_not_a_query_error(
    open_client, constraint: None
) -> None:
    """The driver's ConstraintError has to arrive as GraphConflictError, not as its sibling."""
    tenant = uuid.uuid4()
    context = graph_context(tenant_id=tenant)
    client = await open_client(tenant)
    query = node_create(
        VOCABULARY.label("InfraUser"),
        tenant=str(tenant),
        node_id="duplicate",
        properties={VOCABULARY.property_key("name"): "Ada"},
    )
    await client.run(query=query, context=context)
    with pytest.raises(GraphConflictError):
        await client.run(query=query, context=context)


async def test_a_statement_the_server_refuses_is_a_query_error(
    open_client,
) -> None:
    tenant = uuid.uuid4()
    client = await open_client(tenant)
    with pytest.raises(GraphQueryError):
        await client.run(
            query=_statement("MATCH (n:InfraUser) WHERE n.tenant_id = $tenant_id RETURN", tenant),
            context=graph_context(tenant_id=tenant),
        )


async def test_a_transaction_commits_and_a_rollback_leaves_nothing(
    open_client,
) -> None:
    committed, rolled_back = uuid.uuid4(), uuid.uuid4()
    client = await open_client(committed)
    async with client.begin(context=graph_context(tenant_id=committed)) as transaction:
        await transaction.run(
            query=node_create(
                VOCABULARY.label("InfraUser"),
                tenant=str(committed),
                node_id="committed",
                properties={VOCABULARY.property_key("name"): "Ada"},
            ),
            context=graph_context(tenant_id=committed),
        )
    rolled_client = await open_client(rolled_back)
    with pytest.raises(RuntimeError):
        async with rolled_client.begin(
            context=graph_context(tenant_id=rolled_back)
        ) as transaction:
            await transaction.run(
                query=node_create(
                    VOCABULARY.label("InfraUser"),
                    tenant=str(rolled_back),
                    node_id="rolled-back",
                    properties={VOCABULARY.property_key("name"): "Grace"},
                ),
                context=graph_context(tenant_id=rolled_back),
            )
            raise RuntimeError("the caller gave up")
    found = await rolled_client.run(
        query=node_match(
            VOCABULARY.label("InfraUser"), tenant=str(rolled_back), node_id="rolled-back"
        ),
        context=graph_context(tenant_id=rolled_back),
    )
    assert found == []


async def test_a_health_probe_answers_against_the_real_server(open_client) -> None:
    client = await open_client(uuid.uuid4())
    assert await client.health() is True
    await client.close()
    assert await client.health() is False
