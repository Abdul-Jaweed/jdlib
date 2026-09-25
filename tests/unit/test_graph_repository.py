"""The repository: tenant scope has no parameter to arrive in (directive §11–§12).

Every method here takes the authenticated context and nothing else about identity. There is no
``tenant=`` argument to pass and no default to forget, the tenant is read from the context, and
the client re-checks the statement against that same context before it runs. The tests assert
the property from both sides: the recorded statements all carry the context's tenant, and a
caller who tries to supply one gets a ``TypeError`` rather than a silently different scope.

Identifiers come from the vocabulary, so an undeclared label or property key is refused before
anything reaches the client — asserted together with the client having recorded nothing, because
a refusal that still ran the statement is not a refusal.
"""

from __future__ import annotations

import inspect
import uuid
from typing import Any

import pytest

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import MissingTenantContext
from jdlib.graph import (
    GraphClient,
    GraphQuery,
    GraphValidationError,
    GraphVocabulary,
)
from jdlib.graph.repository import GraphRepository
from jdlib.security.context import AuthMethod, SecurityContext

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
VOCABULARY = GraphVocabulary(
    labels=frozenset({"User", "Resource"}),
    relationship_types=frozenset({"OWNS"}),
    property_keys=frozenset({"name", "email"}),
)
RESERVED = ("tenant_id", "id")


def _context(tenant_id: uuid.UUID = TENANT_ID) -> SecurityContext:
    principal = Principal(kind=PrincipalKind.USER, id=uuid.uuid4())
    tenant = TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req-1",
        correlation_id="corr-1",
        trace_id=None,
    )
    return SecurityContext.from_tenant_context(tenant=tenant, auth_method=AuthMethod.SERVICE)


class _RecordingClient:
    """A client double that keeps what it was asked to run."""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.queries: list[GraphQuery] = []
        self.rows = rows if rows is not None else []

    async def open(self, *, context: SecurityContext) -> None: ...

    async def close(self) -> None: ...

    async def health(self) -> bool:
        return True

    async def run(
        self, *, query: GraphQuery, context: SecurityContext
    ) -> list[dict[str, Any]]:
        self.queries.append(query)
        return list(self.rows)


def _repository(client: _RecordingClient | None = None) -> tuple[GraphRepository, _RecordingClient]:
    recorded = client or _RecordingClient()
    return GraphRepository(client=recorded, vocabulary=VOCABULARY), recorded


def test_no_method_accepts_a_tenant() -> None:
    """The scope has no parameter to arrive in — the property the rest of the file relies on."""
    for name, member in inspect.getmembers(GraphRepository, inspect.isfunction):
        if name.startswith("_"):
            continue
        assert "tenant" not in inspect.signature(member).parameters, name


async def test_every_statement_carries_the_contexts_tenant() -> None:
    repository, recorded = _repository()
    context = _context()
    await repository.create_node(
        context=context, label="User", node_id="u1", properties={"name": "A"}
    )
    await repository.get_node(context=context, label="User", node_id="u1")
    await repository.update_node(
        context=context, label="User", node_id="u1", properties={"name": "B"}
    )
    await repository.delete_node(context=context, label="User", node_id="u1")
    await repository.relate(
        context=context,
        relationship="OWNS",
        from_label="User",
        from_id="u1",
        to_label="Resource",
        to_id="r1",
    )
    await repository.related(
        context=context,
        relationship="OWNS",
        from_label="User",
        from_id="u1",
        to_label="Resource",
        to_id="r1",
    )
    await repository.unrelate(
        context=context,
        relationship="OWNS",
        from_label="User",
        from_id="u1",
        to_label="Resource",
        to_id="r1",
    )
    assert len(recorded.queries) == 7
    for query in recorded.queries:
        assert query.parameters["jdlib_scope_tenant"] == str(TENANT_ID)


async def test_a_caller_cannot_supply_a_tenant() -> None:
    repository, recorded = _repository()
    with pytest.raises(TypeError):
        await repository.get_node(  # type: ignore[call-arg]
            context=_context(), label="User", node_id="u1", tenant=str(OTHER_TENANT_ID)
        )
    assert recorded.queries == []


async def test_the_repository_requires_an_authenticated_tenant() -> None:
    repository, recorded = _repository()
    with pytest.raises(MissingTenantContext):
        await repository.get_node(
            context=SecurityContext.anonymous(), label="User", node_id="u1"
        )
    assert recorded.queries == []


async def test_an_undeclared_label_is_refused_before_anything_runs() -> None:
    repository, recorded = _repository()
    with pytest.raises(GraphValidationError):
        await repository.get_node(context=_context(), label="Admin", node_id="u1")
    assert recorded.queries == []


async def test_an_undeclared_property_key_is_refused_before_anything_runs() -> None:
    repository, recorded = _repository()
    with pytest.raises(GraphValidationError):
        await repository.create_node(
            context=_context(), label="User", node_id="u1", properties={"salary": 1}
        )
    assert recorded.queries == []


@pytest.mark.parametrize("reserved", RESERVED)
async def test_a_reserved_property_key_is_refused(reserved: str) -> None:
    """``tenant_id`` and ``id`` are set by the operation, not by the caller."""
    vocabulary = GraphVocabulary(
        labels=frozenset({"User"}),
        relationship_types=frozenset({"OWNS"}),
        property_keys=frozenset({reserved}),
    )
    recorded = _RecordingClient()
    repository = GraphRepository(client=recorded, vocabulary=vocabulary)
    with pytest.raises(GraphValidationError):
        await repository.create_node(
            context=_context(), label="User", node_id="u1", properties={reserved: "x"}
        )
    assert recorded.queries == []


@pytest.mark.parametrize("node_id", ["", "with space", "with\nnewline", "x" * 300])
async def test_a_node_id_is_validated(node_id: str) -> None:
    repository, recorded = _repository()
    with pytest.raises(GraphValidationError):
        await repository.get_node(context=_context(), label="User", node_id=node_id)
    assert recorded.queries == []


async def test_create_node_binds_the_identity_and_the_properties() -> None:
    repository, recorded = _repository()
    await repository.create_node(
        context=_context(), label="User", node_id="u1", properties={"name": "A"}
    )
    query = recorded.queries[0]
    assert "CREATE (n:User)" in query.text
    assert query.parameters["jdlib_node_id"] == "u1"
    assert query.parameters["jdlib_properties"] == {"name": "A"}
    assert query.parameters["jdlib_scope_tenant"] == str(TENANT_ID)


async def test_get_node_returns_the_properties_or_none() -> None:
    found = _RecordingClient(rows=[{"n": {"id": "u1", "name": "A"}}])
    repository, _ = _repository(found)
    assert await repository.get_node(context=_context(), label="User", node_id="u1") == {
        "id": "u1",
        "name": "A",
    }
    empty = _RecordingClient(rows=[])
    repository, _ = _repository(empty)
    assert await repository.get_node(context=_context(), label="User", node_id="u1") is None


async def test_update_node_reports_whether_anything_matched() -> None:
    matched = _RecordingClient(rows=[{"n": {"id": "u1"}}])
    repository, _ = _repository(matched)
    assert (
        await repository.update_node(
            context=_context(), label="User", node_id="u1", properties={"name": "B"}
        )
        is True
    )
    empty = _RecordingClient(rows=[])
    repository, _ = _repository(empty)
    assert (
        await repository.update_node(
            context=_context(), label="User", node_id="u1", properties={"name": "B"}
        )
        is False
    )


async def test_a_relationship_scopes_both_endpoints_with_one_tenant() -> None:
    repository, recorded = _repository()
    await repository.relate(
        context=_context(),
        relationship="OWNS",
        from_label="User",
        from_id="u1",
        to_label="Resource",
        to_id="r1",
    )
    query = recorded.queries[0]
    assert query.text.count("$jdlib_scope_tenant") == 2
    assert list(query.parameters.values()).count(str(TENANT_ID)) == 1
    assert query.parameters["jdlib_from_id"] == "u1"
    assert query.parameters["jdlib_to_id"] == "r1"


async def test_related_answers_whether_the_edge_is_there() -> None:
    present = _RecordingClient(rows=[{"r": {"since": "2026"}}])
    repository, _ = _repository(present)
    assert (
        await repository.related(
            context=_context(),
            relationship="OWNS",
            from_label="User",
            from_id="u1",
            to_label="Resource",
            to_id="r1",
        )
        is True
    )
    absent = _RecordingClient(rows=[])
    repository, _ = _repository(absent)
    assert (
        await repository.related(
            context=_context(),
            relationship="OWNS",
            from_label="User",
            from_id="u1",
            to_label="Resource",
            to_id="r1",
        )
        is False
    )


def test_the_repository_depends_on_the_protocol_not_the_driver() -> None:
    """A recording client satisfies the seam, which is what makes the unit layer possible."""
    _, recorded = _repository()
    assert isinstance(recorded, GraphClient)
