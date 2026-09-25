"""The graph error taxonomy, and what it means for retries (directive §15).

Two things are asserted here that a later slice depends on: that the failures which must never
be retried are not, and that a timeout's retryability belongs to the *operation* rather than to
the exception class - a read may be retried after a deadline, a write may not.
"""

from __future__ import annotations

import pytest

from jdlib.errors import JdlibError
from jdlib.graph import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphError,
    GraphNotFoundError,
    GraphQueryError,
    GraphTenantViolationError,
    GraphTimeoutError,
    GraphUnavailableError,
    GraphValidationError,
)
from jdlib.reliability import is_retryable_failure


def test_every_graph_error_is_a_jdlib_error() -> None:
    for exc_type in (
        GraphAuthorizationError,
        GraphConflictError,
        GraphNotFoundError,
        GraphQueryError,
        GraphTenantViolationError,
        GraphTimeoutError,
        GraphUnavailableError,
        GraphValidationError,
    ):
        assert issubclass(exc_type, GraphError)
        assert issubclass(exc_type, JdlibError)


def test_an_unreachable_dependency_is_retryable() -> None:
    assert is_retryable_failure(GraphUnavailableError("neo4j is unreachable")) is True


def test_the_failures_that_must_not_be_retried_are_not() -> None:
    """Authorization, validation, tenant and query failures are decisions, not weather."""
    for exc in (
        GraphValidationError("a label was refused"),
        GraphAuthorizationError("the policy denied this"),
        GraphTenantViolationError("cross-tenant traversal refused"),
        GraphNotFoundError("no such node"),
        GraphConflictError("constraint violated"),
        GraphQueryError("the statement was rejected"),
    ):
        assert is_retryable_failure(exc) is False, exc


def test_a_timeout_is_not_retryable_unless_the_operation_says_so() -> None:
    assert is_retryable_failure(GraphTimeoutError("deadline exceeded")) is False
    assert is_retryable_failure(GraphTimeoutError("deadline exceeded", transient=True)) is True


def test_a_validation_error_is_also_a_value_error() -> None:
    """Ordinary argument validation catches it either way, like the storage key refusal."""
    with pytest.raises(ValueError):
        raise GraphValidationError("a property key was refused")
