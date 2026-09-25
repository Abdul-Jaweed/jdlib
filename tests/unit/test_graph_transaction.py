"""Transactions: one statement at a time, one ending, and no retry after a commit (directive §14).

The property this file exists for is the one a retry can destroy. A transaction that committed
must never be repeated, so the transaction records how it ended and answers whether it may be
retried; the tests assert both directions, because a rule that only ever says "no" would pass a
one-sided test and stall the recovery the rule exists to allow.

The tenant check is the same one the client applies, applied again here — a transaction is
exactly where a scope check gets forgotten, and the refusal is asserted by *nothing reaching the
transaction*.
"""

from __future__ import annotations

import uuid

import pytest

from jdlib.errors import MissingTenantContext
from jdlib.graph import (
    GraphError,
    GraphPolicy,
    GraphQuery,
    GraphRepository,
    GraphTenantViolationError,
    GraphValidationError,
    GraphVocabulary,
    Neo4jClient,
    node_match,
)
from jdlib.graph.transaction import GraphTransaction, TransactionOutcome
from jdlib.security.context import SecurityContext
from tests.support.graph_fakes import (
    OTHER_TENANT_ID,
    TENANT_ID,
    DriverFactory,
    FakeDriver,
    RecordingProvider,
    graph_context,
)

VOCABULARY = GraphVocabulary(
    labels=frozenset({"User", "Resource"}),
    relationship_types=frozenset({"OWNS"}),
    property_keys=frozenset({"name"}),
)
URI = "neo4j+s://graph.internal:7687"


def _scoped(tenant: uuid.UUID = TENANT_ID) -> GraphQuery:
    return node_match(VOCABULARY.label("User"), tenant=str(tenant), node_id="u1")


def _client(
    driver: FakeDriver | None = None, *, policy: GraphPolicy | None = None
) -> tuple[Neo4jClient, FakeDriver, DriverFactory]:
    the_driver = driver or FakeDriver()
    factory = DriverFactory(the_driver)
    from jdlib.graph import GraphConfig

    client = Neo4jClient(
        GraphConfig(uri=URI, database="acme"),
        provider=RecordingProvider(),
        policy=policy,
        driver_factory=factory,
    )
    return client, the_driver, factory


async def test_a_transaction_commits_on_a_clean_exit() -> None:
    client, driver, _ = _client()
    await client.open(context=graph_context())
    async with client.begin(context=graph_context()) as transaction:
        rows = await transaction.run(query=_scoped(), context=graph_context())
    assert rows == [{"id": "u1"}]
    assert driver.transaction is not None
    assert driver.transaction.committed is True
    assert driver.transaction.rolled_back is False
    assert driver.session_closed is True


async def test_a_transaction_rolls_back_when_the_block_raises() -> None:
    client, driver, _ = _client()
    await client.open(context=graph_context())
    with pytest.raises(RuntimeError):
        async with client.begin(context=graph_context()):
            raise RuntimeError("the caller gave up")
    assert driver.transaction is not None
    assert driver.transaction.committed is False
    assert driver.transaction.rolled_back is True
    assert driver.session_closed is True


async def test_the_statement_runs_inside_the_transaction_not_the_session() -> None:
    client, driver, _ = _client()
    await client.open(context=graph_context())
    async with client.begin(context=graph_context()) as transaction:
        await transaction.run(query=_scoped(), context=graph_context())
    assert driver.calls == []
    assert driver.transaction is not None
    assert len(driver.transaction.calls) == 1
    text, parameters = driver.transaction.calls[0]
    assert parameters["jdlib_scope_tenant"] == str(TENANT_ID)
    assert "jdlib_scope_tenant" in text


async def test_a_statement_for_another_tenant_is_refused_inside_the_transaction() -> None:
    client, driver, _ = _client()
    await client.open(context=graph_context())
    async with client.begin(context=graph_context()) as transaction:
        with pytest.raises(GraphTenantViolationError):
            await transaction.run(query=_scoped(OTHER_TENANT_ID), context=graph_context())
    assert driver.transaction is not None
    assert driver.transaction.calls == []


async def test_a_committed_transaction_is_not_retryable() -> None:
    client, _, _ = _client()
    await client.open(context=graph_context())
    async with client.begin(context=graph_context()) as transaction:
        await transaction.run(query=_scoped(), context=graph_context())
        assert transaction.retryable() is True
    assert transaction.outcome is TransactionOutcome.COMMITTED
    assert transaction.retryable() is False


async def test_a_rolled_back_transaction_is_retryable() -> None:
    client, _, _ = _client()
    await client.open(context=graph_context())
    with pytest.raises(RuntimeError):
        async with client.begin(context=graph_context()) as transaction:
            raise RuntimeError("transient")
    assert transaction.outcome is TransactionOutcome.ROLLED_BACK
    assert transaction.retryable() is True


async def test_a_statement_before_the_transaction_begins_is_refused() -> None:
    transaction = GraphTransaction(
        session=FakeDriver().session(), context=graph_context(), policy=GraphPolicy()
    )
    with pytest.raises(GraphError):
        await transaction.run(query=_scoped(), context=graph_context())
    assert transaction.outcome is TransactionOutcome.PENDING


async def test_a_transaction_that_ended_refuses_more_statements() -> None:
    client, _, _ = _client()
    await client.open(context=graph_context())
    async with client.begin(context=graph_context()) as transaction:
        await transaction.run(query=_scoped(), context=graph_context())
    with pytest.raises(GraphError):
        await transaction.run(query=_scoped(), context=graph_context())


async def test_the_transactions_timeout_is_the_policys() -> None:
    client, driver, _ = _client(policy=GraphPolicy(statement_timeout=1.25))
    await client.open(context=graph_context())
    async with client.begin(context=graph_context()):
        pass
    assert driver.begin_kwargs["timeout"] == 1.25


async def test_begin_before_open_is_refused() -> None:
    client, _, _ = _client()
    with pytest.raises(GraphError):
        client.begin(context=graph_context())


async def test_begin_refuses_a_context_for_another_tenant() -> None:
    client, driver, _ = _client()
    await client.open(context=graph_context(TENANT_ID))
    with pytest.raises(GraphTenantViolationError):
        client.begin(context=graph_context(OTHER_TENANT_ID))
    assert driver.transaction is None


async def test_begin_refuses_without_an_authenticated_tenant() -> None:
    client, driver, _ = _client()
    await client.open(context=graph_context())
    with pytest.raises(MissingTenantContext):
        client.begin(context=SecurityContext.anonymous())
    assert driver.transaction is None


async def test_a_repository_can_run_its_operations_inside_a_transaction() -> None:
    client, driver, _ = _client()
    await client.open(context=graph_context())
    repository = GraphRepository(client=client, vocabulary=VOCABULARY)
    context = graph_context()
    async with client.begin(context=context) as transaction:
        scoped = repository.within(transaction)
        await scoped.create_node(
            context=context, label="User", node_id="u1", properties={"name": "A"}
        )
        await scoped.relate(
            context=context,
            relationship="OWNS",
            from_label="User",
            from_id="u1",
            to_label="Resource",
            to_id="r1",
        )
    assert driver.calls == []
    assert driver.transaction is not None
    assert len(driver.transaction.calls) == 2
    for _, parameters in driver.transaction.calls:
        assert parameters["jdlib_scope_tenant"] == str(TENANT_ID)


async def test_a_repository_inside_a_transaction_keeps_the_vocabulary() -> None:
    client, _, _ = _client()
    await client.open(context=graph_context())
    repository = GraphRepository(client=client, vocabulary=VOCABULARY)
    context = graph_context()
    async with client.begin(context=context) as transaction:
        scoped = repository.within(transaction)
        with pytest.raises(GraphValidationError):
            await scoped.create_node(
                context=context, label="Admin", node_id="u1", properties={}
            )
