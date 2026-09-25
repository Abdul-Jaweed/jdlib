"""GraphConfig: what a connection may express, and what it refuses to (directive §10).

The config is the one place a deployment describes how to reach the graph, so it is also the
one place that has to make two things unexpressible: a credential value (the config carries a
reference, never a secret) and an unverified transport (the self-signed schemes need an explicit
opt-in, and the default is verification).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from jdlib.credentials import SecretRef, SecretVersion
from jdlib.graph import GraphConfig, GraphValidationError


def test_a_uri_with_embedded_credentials_is_refused() -> None:
    """A connection string that carries a password is how one reaches a log or a trace."""
    with pytest.raises(GraphValidationError):
        GraphConfig("neo4j://neo4j:hunter2@graph.internal:7687")


@pytest.mark.parametrize(
    "uri",
    [
        "neo4j://graph.internal:7687",
        "neo4j+s://graph.internal:7687",
        "bolt://graph.internal:7687",
        "bolt+s://graph.internal:7687",
        "neo4j://graph.internal",
    ],
)
def test_known_schemes_are_accepted(uri: str) -> None:
    assert GraphConfig(uri).uri == uri


@pytest.mark.parametrize(
    "uri",
    [
        "http://graph.internal:7687",
        "file:///etc/passwd",
        "neo4j:/graph.internal",
        "graph.internal:7687",
        "",
    ],
)
def test_anything_that_is_not_a_graph_uri_is_refused(uri: str) -> None:
    with pytest.raises(GraphValidationError):
        GraphConfig(uri)


def test_a_self_signed_transport_needs_the_explicit_opt_in() -> None:
    with pytest.raises(GraphValidationError):
        GraphConfig("neo4j+ssc://graph.internal:7687")
    config = GraphConfig("neo4j+ssc://graph.internal:7687", allow_unverified_certificates=True)
    assert config.uri.startswith("neo4j+ssc://")


def test_the_auth_is_a_reference_and_a_value_is_refused() -> None:
    """The config cannot express a credential: a caller with a password has nowhere to put it."""
    config = GraphConfig(
        "neo4j+s://graph.internal:7687",
        auth=SecretRef(handle="neo4j-app", version=SecretVersion("v3")),
    )
    assert config.auth is not None
    assert config.auth.handle == "neo4j-app"
    with pytest.raises(GraphValidationError):
        GraphConfig("neo4j+s://graph.internal:7687", auth="hunter2")  # type: ignore[arg-type]


def test_the_repr_names_the_reference_and_the_host_but_no_value() -> None:
    config = GraphConfig(
        "neo4j+s://graph.internal:7687",
        auth=SecretRef(handle="neo4j-app"),
        database="tenantgraph",
    )
    rendered = repr(config)
    assert "neo4j-app" in rendered
    assert "graph.internal" in rendered
    assert "hunter2" not in rendered


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_connection_pool_size", 0),
        ("max_connection_pool_size", -1),
        ("connection_acquisition_timeout", 0),
        ("connection_timeout", -1.0),
        ("max_connection_lifetime", 0),
        ("max_transaction_retry_time", -0.5),
    ],
)
def test_bounds_are_enforced(field: str, value: float) -> None:
    with pytest.raises(GraphValidationError):
        GraphConfig("neo4j://graph.internal:7687", **{field: value})


@pytest.mark.parametrize("database", ["", "with space", "with`backtick", "with'quote", "with;sem"])
def test_a_database_name_is_validated(database: str) -> None:
    with pytest.raises(GraphValidationError):
        GraphConfig("neo4j://graph.internal:7687", database=database)


@pytest.mark.parametrize("database", ["neo4j", "tenant-graph_2", "Tenant.Graph"])
def test_a_valid_database_name_is_kept(database: str) -> None:
    assert GraphConfig("neo4j://graph.internal:7687", database=database).database == database


def test_the_config_is_frozen() -> None:
    config = GraphConfig("neo4j://graph.internal:7687")
    with pytest.raises(FrozenInstanceError):
        config.database = "other"  # type: ignore[misc]
