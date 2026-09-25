"""The query builders: identifiers are interpolated, values never are (directive §13).

The property this file exists to pin is that the *text* of a statement is a function of the
validated identifiers alone. A hostile value therefore cannot change a statement — not because
it is filtered, but because there is no place for it to land: it goes into the parameters, and
the same query built with a benign value is byte-for-byte identical.
"""

from __future__ import annotations

import pytest

from jdlib.graph import (
    GraphValidationError,
    GraphVocabulary,
    node_create,
    node_delete,
    node_match,
    node_update,
    relationship_create,
    relationship_delete,
)
from jdlib.graph.query import ID_PROPERTY, TENANT_PARAMETER, TENANT_PROPERTY


def vocabulary() -> GraphVocabulary:
    return GraphVocabulary(
        labels=frozenset({"User", "Resource"}),
        relationship_types=frozenset({"OWNS"}),
        property_keys=frozenset({"id", "tenant_id", "name"}),
    )


def test_the_tenant_is_a_parameter_and_never_appears_as_text() -> None:
    vocab = vocabulary()
    query = node_match(vocab.label("User"), tenant="acme-corp", node_id="u1")
    assert f"${TENANT_PARAMETER}" in query.text
    assert query.parameters[TENANT_PARAMETER] == "acme-corp"
    assert "acme-corp" not in query.text


def test_a_hostile_value_changes_no_text() -> None:
    """The statement is a function of the identifiers; the values only ever reach parameters."""
    vocab = vocabulary()
    key = vocab.property_key("name")
    benign = node_create(vocab.label("User"), tenant="acme", node_id="u1", properties={key: "Ada"})
    hostile = node_create(
        vocab.label("User"),
        tenant="acme",
        node_id="u1",
        properties={key: "x'}) DETACH DELETE (n) MATCH (m) WHERE m.name = 'y"},
    )
    assert benign.text == hostile.text
    assert hostile.parameters != benign.parameters


def test_a_property_key_must_be_a_property_key() -> None:
    vocab = vocabulary()
    with pytest.raises(GraphValidationError):
        node_create(
            vocab.label("User"),
            tenant="acme",
            node_id="u1",
            properties={"name": "Ada"},  # type: ignore[dict-item]
        )


@pytest.mark.parametrize("reserved", ["tenant_id", "id"])
def test_the_reserved_properties_are_set_by_the_operation_not_the_caller(reserved: str) -> None:
    vocab = vocabulary()
    with pytest.raises(GraphValidationError):
        node_create(
            vocab.label("User"),
            tenant="acme",
            node_id="u1",
            properties={vocab.property_key(reserved): "someone-else"},
        )
    with pytest.raises(GraphValidationError):
        node_update(
            vocab.label("User"),
            tenant="acme",
            node_id="u1",
            properties={vocab.property_key(reserved): "someone-else"},
        )


def test_a_node_delete_is_not_detaching_unless_asked() -> None:
    """The safe default: a node with relationships refuses to vanish quietly with them."""
    vocab = vocabulary()
    assert "DETACH" not in node_delete(vocab.label("User"), tenant="acme", node_id="u1").text
    assert (
        "DETACH DELETE"
        in node_delete(vocab.label("User"), tenant="acme", node_id="u1", detach=True).text
    )


def test_relationship_creation_scopes_both_endpoints_with_one_tenant() -> None:
    """One tenant parameter for both ends, so a cross-tenant edge cannot be expressed."""
    vocab = vocabulary()
    query = relationship_create(
        vocab.relationship_type("OWNS"),
        tenant="acme",
        from_label=vocab.label("User"),
        from_id="u1",
        to_label=vocab.label("Resource"),
        to_id="r1",
    )
    assert query.text.count(f"${TENANT_PARAMETER}") == 2
    assert list(query.parameters.values()).count("acme") == 1
    assert "MERGE" in query.text


def test_relationship_delete_matches_both_endpoints_the_same_way() -> None:
    vocab = vocabulary()
    query = relationship_delete(
        vocab.relationship_type("OWNS"),
        tenant="acme",
        from_label=vocab.label("User"),
        from_id="u1",
        to_label=vocab.label("Resource"),
        to_id="r1",
    )
    assert query.text.count(f"${TENANT_PARAMETER}") == 2
    assert "DELETE r" in query.text


def test_an_empty_tenant_is_refused() -> None:
    vocab = vocabulary()
    for tenant in ("", None):
        with pytest.raises(GraphValidationError):
            node_match(vocab.label("User"), tenant=tenant, node_id="u1")  # type: ignore[arg-type]


def test_the_repr_redacts_the_values() -> None:
    vocab = vocabulary()
    query = node_create(
        vocab.label("User"),
        tenant="acme",
        node_id="u1",
        properties={vocab.property_key("name"): "x'}) DETACH DELETE (n)"},
    )
    rendered = repr(query)
    assert "REDACTED" in rendered
    assert "DETACH DELETE (n)" not in rendered


def test_every_builder_binds_the_tenant_and_the_identifiers_it_was_given() -> None:
    """A smoke test over the whole surface: nothing here interpolates a value."""
    vocab = vocabulary()
    label = vocab.label("User")
    queries = [
        node_match(label, tenant="acme", node_id="u1"),
        node_create(
            label, tenant="acme", node_id="u1", properties={vocab.property_key("name"): "A"}
        ),
        node_update(
            label, tenant="acme", node_id="u1", properties={vocab.property_key("name"): "A"}
        ),
        node_delete(label, tenant="acme", node_id="u1"),
    ]
    for query in queries:
        assert query.parameters[TENANT_PARAMETER] == "acme"
        assert f"n.{TENANT_PROPERTY} = ${TENANT_PARAMETER}" in query.text
        assert f"n.{ID_PROPERTY} = " in query.text
        assert "acme" not in query.text
        assert "u1" not in query.text
