from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from jdlib.query.ast import Predicate, QueryNode, SortColumn
from jdlib.query.errors import (
    QueryComplexityError,
    QueryParseError,
    TenantPlaneQueryError,
)
from jdlib.query.specification import QuerySpecification

IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

OPERATORS = ("eq", "ne", "lt", "lte", "gt", "gte", "in", "not_in", "like", "not_like")


@dataclass(frozen=True, slots=True)
class IdentifierPolicy:
    """Which tables may be queried, which columns they have, and what may not be queried.

    ``tenant_plane`` is the ADR-1 boundary: those tables are reachable through
    ``TenantRepository`` alone, and a query specification naming one is refused rather than
    silently narrowed.
    """

    tables: Mapping[str, Sequence[str]]
    tenant_scoped: Sequence[str] = ()
    tenant_plane: Sequence[str] = ()
    max_columns: int = 16
    max_filters: int = 16
    max_in_values: int = 1000
    max_limit: int = 10_000
    max_sort_keys: int = 4

    def columns(self, table: str) -> Sequence[str]:
        return self.tables[table]


def _require_identifier(value: object, what: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.match(value):
        raise QueryParseError(
            f"{what} must be a plain lower-case identifier, and {value!r} is not: an "
            "identifier is never assembled from caller-supplied text"
        )
    return value


def parse_specification(spec: QuerySpecification, policy: IdentifierPolicy) -> QueryNode:
    """Validate a specification against the policy, and return the parsed form.

    Everything that can be refused is refused here: unknown or hostile identifiers, the
    tenant plane, unpaginated reads, and cost that is out of bounds.
    """
    table = _require_identifier(spec.table, "table")
    if table in policy.tenant_plane:
        raise TenantPlaneQueryError(
            f"table {table!r} is tenant-plane: TenantRepository is the only path to its rows, "
            "and the query compiler does not become a second one"
        )
    if table not in policy.tables:
        raise QueryParseError(
            f"table {table!r} is not declared in the identifier policy; known tables: "
            f"{sorted(policy.tables)}"
        )

    allowed_columns = policy.columns(table)
    if not spec.columns:
        raise QueryParseError("at least one column must be named")
    if len(spec.columns) > policy.max_columns:
        raise QueryComplexityError(
            f"{len(spec.columns)} columns exceeds the policy maximum of {policy.max_columns}"
        )
    columns = tuple(_require_identifier(column, "column") for column in spec.columns)
    for column in columns:
        if column not in allowed_columns:
            raise QueryParseError(f"table {table!r} has no column {column!r}")

    if spec.limit is None:
        raise QueryParseError(
            "a limit is required: an unpaginated read is refused rather than defaulted"
        )
    if spec.offset is not None and spec.limit is None:  # pragma: no cover - limit checked above
        raise QueryParseError("an offset without a limit is unbounded")
    if spec.limit < 1:
        raise QueryComplexityError("a limit must be at least 1")
    if spec.limit > policy.max_limit:
        raise QueryComplexityError(
            f"limit {spec.limit} exceeds the policy maximum of {policy.max_limit}"
        )
    if spec.offset is not None and spec.offset < 0:
        raise QueryComplexityError("an offset must not be negative")

    if len(spec.filters) > policy.max_filters:
        raise QueryComplexityError(
            f"{len(spec.filters)} filters exceeds the policy maximum of {policy.max_filters}"
        )

    predicates: list[Predicate] = []
    for filter_ in spec.filters:
        column = _require_identifier(filter_.column, "filter column")
        if column not in allowed_columns:
            raise QueryParseError(f"table {table!r} has no column {column!r}")
        if filter_.operator not in OPERATORS:
            raise QueryParseError(
                f"operator {filter_.operator!r} is not in the allowlist {OPERATORS}"
            )
        if filter_.operator in ("in", "not_in"):
            values = filter_.value
            if not isinstance(values, Iterable) or isinstance(values, (str, bytes)):
                raise QueryParseError("an 'in' filter takes a collection of values")
            if len(list(values)) > policy.max_in_values:
                raise QueryComplexityError(
                    f"an 'in' list of {len(list(values))} values exceeds the policy maximum of "
                    f"{policy.max_in_values}: one request must not become an unbounded scan"
                )
        predicates.append(Predicate(column=column, operator=filter_.operator, value=filter_.value))

    if len(spec.order_by) > policy.max_sort_keys:
        raise QueryComplexityError(
            f"{len(spec.order_by)} sort keys exceeds the policy maximum of {policy.max_sort_keys}"
        )
    order_by = tuple(
        SortColumn(column=_require_identifier(key.column, "sort column"), direction=key.direction)
        for key in spec.order_by
    )

    return QueryNode(
        table=table,
        columns=columns,
        predicates=tuple(predicates),
        order_by=order_by,
        limit=spec.limit,
        offset=spec.offset or 0,
        tenant_scoped=table in policy.tenant_scoped,
    )
