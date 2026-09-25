"""What the graph says about itself, and what it must never say (directive §15).

The graph adds no telemetry system: it uses the span seam and the audit seam the rest of the
library already has, and the properties this file pins are the ones those seams cannot enforce
for it —

* a refusal is recorded *before* it is raised, with the actor the call was made for (the event
  fills its actor from the ambient context, so the statement has to run under that context);
* nothing that leaves the process carries a tenant id or a statement: a span attribute that is
  forbidden raises rather than being scrubbed, and the audit metadata carries the error's kind,
  never its text;
* an audit outage is not the caller's failure: an emitter that raises does not change what the
  caller sees.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from jdlib.graph import (
    GraphConfig,
    GraphError,
    GraphQuery,
    GraphTenantViolationError,
    GraphVocabulary,
    Neo4jClient,
    node_match,
)
from jdlib.graph.transaction import TransactionOutcome
from jdlib.security.audit.events import AuditOutcome, SecurityEventType
from jdlib.security.context import current_security_context_or_none
from tests.support.graph_fakes import (
    TENANT_ID,
    DriverFactory,
    FakeDriver,
    RecordingProvider,
    graph_context,
)

VOCABULARY = GraphVocabulary(
    labels=frozenset({"User"}),
    relationship_types=frozenset({"OWNS"}),
    property_keys=frozenset({"name"}),
)
URI = "neo4j+s://graph.internal:7687"
OTHER_TENANT = "22222222-2222-2222-2222-222222222222"


def _query(tenant: str = str(TENANT_ID)) -> GraphQuery:
    return node_match(VOCABULARY.label("User"), tenant=tenant, node_id="u1")


class _Span:
    def __init__(self, name: str, attributes: dict[str, Any]) -> None:
        self.name = name
        self.attributes = dict(attributes)
        self.ended = False

    def set_attribute(self, key: str, value: object) -> None:
        self.attributes[key] = value

    def end(self, *, status: str | None = None) -> None:
        self.ended = True


class _Tracer:
    def __init__(self) -> None:
        self.spans: list[_Span] = []

    def start_span(self, name: str, attributes: dict[str, Any]) -> _Span:
        span = _Span(name, attributes)
        self.spans.append(span)
        return span


class _Emitter:
    def __init__(self, *, raises: bool = False) -> None:
        self.events: list[Any] = []
        self.ambient: list[Any] = []
        self._raises = raises

    def __call__(self, event: Any) -> None:
        self.ambient.append(current_security_context_or_none())
        if self._raises:
            raise RuntimeError("the audit sink is down")
        self.events.append(event)


def _client(
    driver: FakeDriver | None = None, *, tracer: Any = None, emitter: Any = None
) -> tuple[Neo4jClient, FakeDriver]:
    the_driver = driver or FakeDriver()
    client = Neo4jClient(
        GraphConfig(uri=URI, database="acme"),
        provider=RecordingProvider(),
        driver_factory=DriverFactory(the_driver),
        tracer=tracer,
        emitter=emitter,
    )
    return client, the_driver


@pytest.fixture
def driver_client_error(monkeypatch: pytest.MonkeyPatch) -> type[BaseException]:
    """The driver's client-error class, stubbed: the unit layer has no driver installed."""
    exceptions = types.ModuleType("neo4j.exceptions")

    class Neo4jError(Exception): ...

    class ClientError(Neo4jError): ...

    exceptions.ClientError = ClientError
    exceptions.Neo4jError = Neo4jError
    module = types.ModuleType("neo4j")
    module.exceptions = exceptions  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "neo4j", module)
    monkeypatch.setitem(sys.modules, "neo4j.exceptions", exceptions)
    return ClientError


async def test_a_statement_opens_a_span_and_reports_its_result() -> None:
    tracer = _Tracer()
    client, _ = _client(tracer=tracer)
    await client.open(context=graph_context())
    await client.run(query=_query(), context=graph_context())
    span = tracer.spans[0]
    assert span.name == "graph.run"
    assert span.attributes["security.operation"] == "graph.run"
    assert span.attributes["security.result"] == "ok"
    assert span.ended is True


async def test_a_refused_statement_is_recorded_before_it_is_raised() -> None:
    tracer = _Tracer()
    emitter = _Emitter()
    client, driver = _client(tracer=tracer, emitter=emitter)
    context = graph_context()
    await client.open(context=context)
    with pytest.raises(GraphTenantViolationError):
        await client.run(query=_query(OTHER_TENANT), context=context)
    assert tracer.spans[0].attributes["security.result"] == "refused"
    assert driver.calls == []
    assert len(emitter.events) == 1
    event = emitter.events[0]
    assert event.event_type is SecurityEventType.CROSS_TENANT_ACCESS_REJECTED
    assert event.outcome is AuditOutcome.DENIED
    assert event.principal_id == context.principal.id
    assert event.tenant_id == TENANT_ID


async def test_a_statement_the_database_rejects_is_recorded_as_an_error(
    driver_client_error: type[BaseException],
) -> None:
    tracer = _Tracer()
    emitter = _Emitter()
    driver = FakeDriver(error=driver_client_error("bad syntax"))
    client, _ = _client(driver, tracer=tracer, emitter=emitter)
    await client.open(context=graph_context())
    with pytest.raises(GraphError):
        await client.run(query=_query(), context=graph_context())
    assert tracer.spans[0].attributes["security.result"] == "failed"
    assert len(emitter.events) == 1
    event = emitter.events[0]
    assert event.event_type is SecurityEventType.QUERY_REJECTED
    assert event.outcome is AuditOutcome.ERROR
    assert event.metadata["error"] == "GraphQueryError"


async def test_a_failure_that_is_not_a_refused_statement_is_not_an_audit_event() -> None:
    """Only a statement the database refused is security-relevant; the rest are noise."""
    emitter = _Emitter()
    driver = FakeDriver(error=RuntimeError("the connection dropped"))
    client, _ = _client(driver, emitter=emitter)
    await client.open(context=graph_context())
    with pytest.raises(GraphError):
        await client.run(query=_query(), context=graph_context())
    assert emitter.events == []


async def test_nothing_exported_carries_a_tenant_or_a_statement() -> None:
    tracer = _Tracer()
    client, _ = _client(tracer=tracer)
    await client.open(context=graph_context())
    await client.run(query=_query(), context=graph_context())
    rendered = repr(tracer.spans[0].attributes)
    assert str(TENANT_ID) not in rendered
    assert "MATCH" not in rendered


async def test_an_audit_outage_does_not_change_the_callers_outcome() -> None:
    client, _ = _client(emitter=_Emitter(raises=True))
    context = graph_context()
    await client.open(context=context)
    with pytest.raises(GraphTenantViolationError):
        await client.run(query=_query(OTHER_TENANT), context=context)


async def test_the_default_wiring_is_unchanged() -> None:
    client, _ = _client()
    await client.open(context=graph_context())
    rows = await client.run(query=_query(), context=graph_context())
    assert rows == [{"id": "u1"}]


async def test_a_transaction_reports_how_it_ended() -> None:
    tracer = _Tracer()
    client, _ = _client(tracer=tracer)
    await client.open(context=graph_context())
    async with client.begin(context=graph_context()) as transaction:
        await transaction.run(query=_query(), context=graph_context())
    span = tracer.spans[-1]
    assert span.name == "graph.transaction"
    assert span.attributes["security.outcome"] == TransactionOutcome.COMMITTED.value


async def test_a_transaction_that_rolls_back_says_so() -> None:
    tracer = _Tracer()
    client, _ = _client(tracer=tracer)
    await client.open(context=graph_context())
    with pytest.raises(RuntimeError):
        async with client.begin(context=graph_context()) as transaction:
            await transaction.run(query=_query(), context=graph_context())
            raise RuntimeError("the caller gave up")
    assert tracer.spans[-1].attributes["security.outcome"] == TransactionOutcome.ROLLED_BACK.value


async def test_a_driver_failure_inside_a_transaction_is_mapped() -> None:
    """The transaction maps driver failures the same way the client does, through one mapper."""
    driver = FakeDriver(error=RuntimeError("the connection dropped"))
    client, _ = _client(driver)
    await client.open(context=graph_context())
    async with client.begin(context=graph_context()) as transaction:
        with pytest.raises(GraphError):
            await transaction.run(query=_query(), context=graph_context())


async def test_the_event_is_built_under_the_calls_own_context() -> None:
    """The ambient context is what attributes the event; the statement must run under it."""
    emitter = _Emitter()
    client, _ = _client(emitter=emitter)
    context = graph_context()
    await client.open(context=context)
    with pytest.raises(GraphTenantViolationError):
        await client.run(query=_query(OTHER_TENANT), context=context)
    assert emitter.ambient[0] is not None
    assert emitter.events[0].principal_id == context.principal.id
