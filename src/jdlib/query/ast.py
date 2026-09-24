from __future__ import annotations

from dataclasses import dataclass

from jdlib.query.specification import SortDirection


@dataclass(frozen=True, slots=True)
class SortColumn:
    column: str
    direction: SortDirection


@dataclass(frozen=True, slots=True)
class Predicate:
    column: str
    operator: str
    value: object


@dataclass(frozen=True, slots=True)
class QueryNode:
    """A parsed specification: identifiers already checked against the policy.

    Nothing past this point re-derives what an identifier may be, so there is exactly one
    place where the allowlist is enforced and exactly one place to audit.
    """

    table: str
    columns: tuple[str, ...]
    predicates: tuple[Predicate, ...]
    order_by: tuple[SortColumn, ...]
    limit: int
    offset: int
    tenant_scoped: bool
