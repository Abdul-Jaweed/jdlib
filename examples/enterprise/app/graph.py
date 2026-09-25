"""The graph plane: what the relational plane cannot say.

A resource is a row; the *shape* of the data — which entity belongs to which resource, and how
resources relate — is what a graph answers. It is a second data plane with the same security model
rather than a second kind of access, and three things follow from that:

* **The tenant comes from the authenticated context, never from an argument.** A client is opened
  *for* a tenant — `Neo4jClient.open` binds it and every statement is checked against that binding —
  so this module keeps one client per tenant and passes each call's context to the statement. A
  client opened for one tenant refuses another tenant's statement, which is why the cache is keyed
  by tenant rather than shared.
* **The vocabulary is declared, not inferred.** A label or relationship type that is not in
  `VOCABULARY` cannot reach a statement, however the caller spells it: the repository resolves
  names *through* the vocabulary, and an undeclared one is refused before any text is built.
* **The library owns the statements, the scope and the reliability; this module owns the URI, the
  credential handle, the vocabulary and the projection's shape.** The projection is derived from the
  relational plane — the record is the row, the graph follows it — so nothing here writes a
  resource.

The projection is an upsert inside one transaction: reading and then writing in two statements is a
race that a second writer wins, and the library's transaction seam is exactly the place to close it.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping

from neo4j import GraphDatabase

from jdlib.credentials.refs import SecretRef
from jdlib.credentials.rotation import VersionedSecretProvider
from jdlib.graph import (
    GraphConfig,
    GraphPolicy,
    GraphRepository,
    GraphValidationError,
    GraphVocabulary,
    Neo4jClient,
)
from jdlib.persistence.secrets import EnvSecretProvider
from jdlib.security.context import SecurityContext

__all__ = [
    "GRAPH_CONSTRAINTS",
    "GRAPH_PASSWORD_HANDLE",
    "VOCABULARY",
    "GraphPlane",
    "ensure_graph_constraints",
    "graph_config",
    "graph_secret_provider",
]

#: The credential handle the graph password is resolved through. `EnvSecretProvider` reads the
#: prefix plus the handle, upper-cased and with `-` as `_`, so this handle resolves
#: `JDLIB_ENTERPRISE_GRAPH_PASSWORD` — deliberately the *same* variable the lab's compose file uses
#: to initialise the server. One secret, one name: two names for one password is how a rotation
#: updates one of them.
GRAPH_PASSWORD_HANDLE = "graph-password"

#: What this deployment's graph may contain. Closed by construction: the repository resolves a
#: caller's name through this, so an undeclared label never reaches a statement.
VOCABULARY = GraphVocabulary(
    labels=frozenset({"Resource", "Entity"}),
    relationship_types=frozenset({"CONTAINS"}),
    property_keys=frozenset({"name", "kind", "status", "label"}),
)


def graph_secret_provider() -> VersionedSecretProvider:
    """The graph password, from the environment, through the library's versioned resolver.

    `EnvSecretProvider` reads a *handle*; the graph client asks a `SecretResolver` for a `SecretRef`
    and gets a versioned `ResolvedSecret`. `VersionedSecretProvider` is the adapter between the two,
    and using it rather than writing one is the point: rotation, retirement and redaction come with
    it.
    """
    return VersionedSecretProvider(EnvSecretProvider("JDLIB_ENTERPRISE_"))


#: The schema the projection relies on, declared out of band like a migration's tables. Without the
#: first, a second projection of the same row is a *second node* rather than a conflict -- and "the
#: projection is an upsert" would hold only because nothing else wrote at the same moment.
GRAPH_CONSTRAINTS: tuple[str, ...] = (
    "CREATE CONSTRAINT resource_identity IF NOT EXISTS "
    "FOR (n:Resource) REQUIRE (n.tenant_id, n.id) IS UNIQUE",
    "CREATE CONSTRAINT entity_identity IF NOT EXISTS "
    "FOR (n:Entity) REQUIRE (n.tenant_id, n.id) IS UNIQUE",
)


def ensure_graph_constraints(config: GraphConfig) -> tuple[str, ...]:
    """Declare the graph's schema, as the operator, before the application serves.

    Schema is not tenant-scoped, and the library's client refuses every statement that is not: a
    constraint has no tenant to be scoped to, so it cannot go through the client at all. This is the
    driver directly with the operator's credentials -- the graph's counterpart to a migration -- and
    it is why the step lives in `bootstrap` rather than in the request path.
    """
    if config.auth is None:  # pragma: no cover - `graph_config` always names a handle
        raise GraphValidationError(
            "the graph config carries no credential reference, so there is nothing to resolve"
        )
    resolved = graph_secret_provider().resolve(config.auth)
    username = config.username or "neo4j"
    driver = GraphDatabase.driver(
        config.uri,
        auth=(username, resolved.value),
        connection_timeout=config.connection_timeout,
    )
    try:
        with driver.session(database=config.database) as session:
            for statement in GRAPH_CONSTRAINTS:
                session.run(statement).consume()
    finally:
        driver.close()
    return GRAPH_CONSTRAINTS


def graph_config(*, uri: str, database: str, username: str) -> GraphConfig:
    """The graph this deployment may reach. The password is a reference, never a value."""
    return GraphConfig(
        uri=uri,
        database=database,
        username=username,
        auth=SecretRef(handle=GRAPH_PASSWORD_HANDLE),
    )


class GraphPlane:
    """A client per tenant, and the projection the resource plane drives.

    The client cache is keyed by tenant because a client *is* a tenant binding: sharing one across
    tenants would either serve the first tenant's scope to the second or refuse every call, and both
    are wrong in ways that only a live database shows.
    """

    def __init__(self, config: GraphConfig) -> None:
        self._config = config
        self._provider = graph_secret_provider()
        self._clients: dict[uuid.UUID, Neo4jClient] = {}

    async def client_for(self, context: SecurityContext) -> Neo4jClient:
        """The tenant's client, opened on first use and reused afterwards.

        The tenant is read *from the context* and is the cache key: taking it as a second parameter
        would allow a context and an id that disagree, which is the one mistake this plane exists to
        make impossible.
        """
        tenant_id = context.require_tenant().tenant_id
        client = self._clients.get(tenant_id)
        if client is None:
            client = Neo4jClient(self._config, provider=self._provider, policy=GraphPolicy())
            await client.open(context=context)
            self._clients[tenant_id] = client
        return client

    async def repository_for(self, context: SecurityContext) -> GraphRepository:
        client = await self.client_for(context)
        return GraphRepository(client=client, vocabulary=VOCABULARY)

    async def project_resource(
        self,
        *,
        context: SecurityContext,
        resource_id: uuid.UUID,
        properties: Mapping[str, object],
    ) -> None:
        """Write the resource's node, creating it or updating it — in one transaction.

        The read and the write are inside the same transaction: doing them in two is a race a second
        writer wins, and the losing writer's `create` is a conflict rather than an update.
        """
        client = await self.client_for(context)
        repository = GraphRepository(client=client, vocabulary=VOCABULARY)
        node_id = str(resource_id)
        async with client.begin(context=context) as transaction:
            within = repository.within(transaction)
            existing = await repository.get_node(
                context=context, label="Resource", node_id=node_id
            )
            if existing is None:
                await within.create_node(
                    context=context,
                    label="Resource",
                    node_id=node_id,
                    properties=properties,
                )
            else:
                await within.update_node(
                    context=context,
                    label="Resource",
                    node_id=node_id,
                    properties=properties,
                )

    async def read_resource(
        self, *, context: SecurityContext, resource_id: uuid.UUID
    ) -> dict[str, object] | None:
        """The resource's node, as this tenant's client sees it."""
        repository = await self.repository_for(context)
        return await repository.get_node(
            context=context, label="Resource", node_id=str(resource_id)
        )

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.close()
        self._clients.clear()
