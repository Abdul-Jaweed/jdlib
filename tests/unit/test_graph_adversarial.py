"""Attacks on the graph's control claims (directive §15; successor §16).

Method, as the programme's adversarial discipline requires: attack a *claim*, at the
*position* the claim protects, and distrust a refusal you did not cause — every case
asserts the exact error type, and the cases that go through a client also assert the
driver was never touched, so a typo cannot pass for a refusal.

Claims under attack:

1. an identifier in a statement came from the vocabulary, and was validated when it was
   made — so a plain string in an identifier position must be refused, not interpolated;
2. a value is never statement text;
3. a statement is scoped to the authenticated tenant, and one that is not never reaches
   the driver;
4. a refused statement changed nothing;
5. a delete is scoped, and does not detach unless asked.

The spellings are chosen by position rather than by content: a backtick that could close
a quoted identifier, a second label, a label expression, a variable-length marker, a
property map, a trailing space, a newline, a NUL, a homoglyph, the right name in the
wrong case, and a whole statement.
"""

from __future__ import annotations

from typing import Any

import pytest

from jdlib.graph import (
    GraphConfig,
    GraphQuery,
    GraphTenantViolationError,
    GraphValidationError,
    GraphVocabulary,
    Neo4jClient,
    node_create,
    node_delete,
    node_match,
    node_update,
    relationship_create,
    relationship_delete,
    relationship_match,
)
from jdlib.graph.query import TENANT_PARAMETER
from tests.support.graph_fakes import (
    TENANT_ID,
    DriverFactory,
    FakeDriver,
    RecordingProvider,
    graph_context,
)

URI = "neo4j+s://graph.internal:7687"

HOSTILE_IDENTIFIERS = [
    "User) DETACH DELETE n //",
    "User`",
    "User:Admin",
    "User|Admin",
    "User*1..5",
    "User{",
    "User ",
    "User\n",
    "Us\u0435r",
    "user",
    "User\x00",
    "",
    "MATCH (n) RETURN n",
]

VOCABULARY = GraphVocabulary(
    labels=frozenset({"User"}),
    relationship_types=frozenset({"OWNS"}),
    property_keys=frozenset({"name", "email"}),
)


def _node_builders(name: str) -> Any:
    return {
        "node_match": lambda label: node_match(label, tenant=str(TENANT_ID), node_id="u1"),
        "node_create": lambda label: node_create(label, tenant=str(TENANT_ID), node_id="u1"),
        "node_update": lambda label: node_update(
            label, tenant=str(TENANT_ID), node_id="u1", properties={}
        ),
        "node_delete": lambda label: node_delete(label, tenant=str(TENANT_ID), node_id="u1"),
    }[name]


def _relationship_builders(name: str) -> Any:
    return {
        "relationship_match": lambda rel: relationship_match(
            rel,
            tenant=str(TENANT_ID),
            from_label=VOCABULARY.label("User"),
            from_id="u1",
            to_label=VOCABULARY.label("User"),
            to_id="u2",
        ),
        "relationship_create": lambda rel: relationship_create(
            rel,
            tenant=str(TENANT_ID),
            from_label=VOCABULARY.label("User"),
            from_id="u1",
            to_label=VOCABULARY.label("User"),
            to_id="u2",
        ),
        "relationship_delete": lambda rel: relationship_delete(
            rel,
            tenant=str(TENANT_ID),
            from_label=VOCABULARY.label("User"),
            from_id="u1",
            to_label=VOCABULARY.label("User"),
            to_id="u2",
        ),
    }[name]


@pytest.mark.parametrize("hostile", HOSTILE_IDENTIFIERS, ids=repr)
@pytest.mark.parametrize(
    "builder", ["node_match", "node_create", "node_update", "node_delete"]
)
def test_a_string_in_a_label_position_is_refused(builder: str, hostile: str) -> None:
    """Claim 1, at the position that matters: the label is interpolated into the pattern."""
    with pytest.raises(GraphValidationError):
        _node_builders(builder)(hostile)


@pytest.mark.parametrize("hostile", HOSTILE_IDENTIFIERS, ids=repr)
@pytest.mark.parametrize(
    "builder", ["relationship_match", "relationship_create", "relationship_delete"]
)
def test_a_string_in_a_relationship_type_position_is_refused(
    builder: str, hostile: str
) -> None:
    """The relationship type sits inside the arrow; a `>` there closes the pattern."""
    with pytest.raises(GraphValidationError):
        _relationship_builders(builder)(hostile)


@pytest.mark.parametrize("hostile", HOSTILE_IDENTIFIERS, ids=repr)
def test_a_string_in_an_endpoint_label_position_is_refused(hostile: str) -> None:
    """Both endpoints are identifiers too, and both are interpolated."""
    with pytest.raises(GraphValidationError):
        relationship_match(
            VOCABULARY.relationship_type("OWNS"),
            tenant=str(TENANT_ID),
            from_label=hostile,
            from_id="u1",
            to_label=VOCABULARY.label("User"),
            to_id="u2",
        )
    with pytest.raises(GraphValidationError):
        relationship_match(
            VOCABULARY.relationship_type("OWNS"),
            tenant=str(TENANT_ID),
            from_label=VOCABULARY.label("User"),
            from_id="u1",
            to_label=hostile,
            to_id="u2",
        )


def test_a_well_formed_but_undeclared_identifier_is_refused_by_the_vocabulary() -> None:
    """The vocabulary is closed: the right shape is not the same as a declared name."""
    with pytest.raises(GraphValidationError):
        VOCABULARY.label("Admin")
    with pytest.raises(GraphValidationError):
        VOCABULARY.relationship_type("OWNS_ADMIN")
    with pytest.raises(GraphValidationError):
        VOCABULARY.property_key("password")


def test_a_value_is_never_statement_text() -> None:
    """Claim 2: the statement is a function of identifiers alone, so two runs that differ only
    in a value produce byte-identical text, and the value travels in the parameters."""
    hostile = "x' OR 1=1 // \u2028\u0000"
    benign = "x"

    def build(node_id: str) -> list[GraphQuery]:
        return [
            node_match(VOCABULARY.label("User"), tenant=str(TENANT_ID), node_id=node_id),
            node_create(VOCABULARY.label("User"), tenant=str(TENANT_ID), node_id=node_id),
            node_update(
                VOCABULARY.label("User"),
                tenant=str(TENANT_ID),
                node_id="u1",
                properties={VOCABULARY.property_key("name"): node_id},
            ),
            node_delete(VOCABULARY.label("User"), tenant=str(TENANT_ID), node_id=node_id),
            relationship_create(
                VOCABULARY.relationship_type("OWNS"),
                tenant=str(TENANT_ID),
                from_label=VOCABULARY.label("User"),
                from_id=node_id,
                to_label=VOCABULARY.label("User"),
                to_id="u2",
                properties={VOCABULARY.property_key("name"): node_id},
            ),
        ]

    def scalars(value: Any) -> list[Any]:
        if isinstance(value, dict):
            return [item for nested in value.values() for item in scalars(nested)]
        return [value]

    for hostile_query, benign_query in zip(build(hostile), build(benign), strict=True):
        assert hostile_query.text == benign_query.text
        assert hostile not in hostile_query.text
        assert "OR 1=1" not in hostile_query.text
        assert hostile in scalars(hostile_query.parameters)


async def test_a_statement_for_another_tenant_never_reaches_the_driver() -> None:
    """Claim 3 and 4 together: the refusal happens before a connection, and it changed nothing."""
    driver = FakeDriver()
    client = Neo4jClient(
        GraphConfig(uri=URI, database="acme"),
        provider=RecordingProvider(),
        driver_factory=DriverFactory(driver),
    )
    context = graph_context()
    await client.open(context=context)
    with pytest.raises(GraphTenantViolationError):
        await client.run(
            query=node_match(
                VOCABULARY.label("User"),
                tenant="22222222-2222-2222-2222-222222222222",
                node_id="u1",
            ),
            context=context,
        )
    assert driver.calls == []


async def test_a_statement_with_no_tenant_parameter_never_reaches_the_driver() -> None:
    """Claim 3, against the low-level seam: a hand-built statement is still checked."""
    driver = FakeDriver()
    client = Neo4jClient(
        GraphConfig(uri=URI, database="acme"),
        provider=RecordingProvider(),
        driver_factory=DriverFactory(driver),
    )
    context = graph_context()
    await client.open(context=context)
    with pytest.raises(GraphTenantViolationError):
        await client.run(query=GraphQuery("MATCH (n) RETURN n"), context=context)
    assert driver.calls == []


async def test_the_low_level_seam_cannot_run_unscoped() -> None:
    """What the escape hatch may do: run its own text, scoped — never run unscoped."""
    driver = FakeDriver()
    client = Neo4jClient(
        GraphConfig(uri=URI, database="acme"),
        provider=RecordingProvider(),
        driver_factory=DriverFactory(driver),
    )
    context = graph_context()
    await client.open(context=context)
    scoped = GraphQuery("MATCH (n) RETURN n", {TENANT_PARAMETER: str(TENANT_ID)})
    await client.run(query=scoped, context=context)
    assert len(driver.calls) == 1
    text, parameters = driver.calls[0][0], driver.calls[0][1]
    assert text == scoped.text
    assert parameters[TENANT_PARAMETER] == str(TENANT_ID)


def test_a_delete_does_not_detach_unless_asked() -> None:
    """Claim 5, as the mechanism: the default keyword is DELETE, and DETACH is opt-in."""
    plain = node_delete(VOCABULARY.label("User"), tenant=str(TENANT_ID), node_id="u1")
    detached = node_delete(
        VOCABULARY.label("User"), tenant=str(TENANT_ID), node_id="u1", detach=True
    )
    assert "DETACH DELETE" not in plain.text
    assert plain.text.endswith("DELETE n")
    assert "DETACH DELETE n" in detached.text
    assert f"{TENANT_PARAMETER}" in plain.text


async def test_a_delete_for_another_tenant_never_reaches_the_driver() -> None:
    """Claim 5 through the enforcement path: a delete is checked like every other statement."""
    driver = FakeDriver()
    client = Neo4jClient(
        GraphConfig(uri=URI, database="acme"),
        provider=RecordingProvider(),
        driver_factory=DriverFactory(driver),
    )
    context = graph_context()
    await client.open(context=context)
    with pytest.raises(GraphTenantViolationError):
        await client.run(
            query=node_delete(
                VOCABULARY.label("User"),
                tenant="22222222-2222-2222-2222-222222222222",
                node_id="u1",
                detach=True,
            ),
            context=context,
        )
    assert driver.calls == []
