"""Graph identifiers are validated values, and the vocabulary is closed (directive §12–§13).

A label, a relationship type and a property key are the only things that reach a statement as
text — every *value* is bound as a parameter — so this is where injection has to be made
impossible rather than sanitised. Two rules do it: a name that needs backticks is refused by
pattern, and a name that was not declared is refused by the vocabulary.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from jdlib.graph import (
    GraphValidationError,
    GraphVocabulary,
    Label,
    PropertyKey,
    RelationshipType,
)


def vocabulary() -> GraphVocabulary:
    return GraphVocabulary(
        labels=frozenset({"Tenant", "User", "Resource"}),
        relationship_types=frozenset({"OWNS", "RELATES_TO"}),
        property_keys=frozenset({"id", "tenant_id", "name", "created_at"}),
    )


def test_a_declared_label_is_returned_as_a_typed_value() -> None:
    assert vocabulary().label("User") == Label("User")
    assert str(vocabulary().label("User")) == "User"


def test_an_undeclared_label_is_refused() -> None:
    with pytest.raises(GraphValidationError):
        vocabulary().label("Admin")


@pytest.mark.parametrize(
    "hostile",
    [
        "User) DETACH DELETE n //",
        "User`",
        "`User",
        "User; MATCH (n) RETURN n",
        "User:Admin",
        "User-Rel",
        "user",
        "",
        "User Admin",
    ],
)
def test_a_label_cannot_carry_cypher_syntax(hostile: str) -> None:
    with pytest.raises(GraphValidationError):
        Label(hostile)


@pytest.mark.parametrize(
    "hostile",
    [
        "OWNS]->() DETACH DELETE (n) //",
        "owns",
        "OWNS:OTHER",
        "OWNS`",
        "",
    ],
)
def test_a_relationship_type_cannot_carry_cypher_syntax(hostile: str) -> None:
    with pytest.raises(GraphValidationError):
        RelationshipType(hostile)


@pytest.mark.parametrize(
    "hostile",
    [
        "name}) DETACH DELETE (n) //",
        "Name",
        "na me",
        "name`",
        "",
    ],
)
def test_a_property_key_cannot_carry_cypher_syntax(hostile: str) -> None:
    with pytest.raises(GraphValidationError):
        PropertyKey(hostile)


def test_a_vocabulary_cannot_declare_a_hostile_name() -> None:
    """A declared name is validated too: the declaration is not a way around the pattern."""
    with pytest.raises(GraphValidationError):
        GraphVocabulary(
            labels=frozenset({"User) DETACH DELETE n //"}),
            relationship_types=frozenset({"OWNS"}),
            property_keys=frozenset({"name"}),
        )


def test_the_vocabulary_is_frozen() -> None:
    vocab = vocabulary()
    with pytest.raises(FrozenInstanceError):
        vocab.labels = frozenset()  # type: ignore[misc]
