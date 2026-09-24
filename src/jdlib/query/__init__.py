"""Query specification and compiler (successor Phase 8).

Scoped by ADR-1: this is for engines that have no ORM of their own, and it never becomes a
second path to tenant-plane rows - ``TenantRepository`` remains the only one, and a
specification naming a tenant-plane table is refused.

The design decision that carries the phase is where the allowlist lives. Identifiers are
checked against the policy when a specification is PARSED, not when SQL is rendered, so a
hostile or unknown table, column, operator or sort key never reaches a compiler. Values are
never text: every one is bound, and the compiled query carries its text and its parameters as
a single value because neither is useful without the other.
"""

from jdlib.query.ast import Predicate, QueryNode, SortColumn
from jdlib.query.compiler import TENANT_PARAMETER, CompiledQuery, QueryCompiler
from jdlib.query.dialect import MysqlDialect, PostgresDialect, QueryDialect
from jdlib.query.errors import (
    CrossTenantQueryError,
    QueryComplexityError,
    QueryError,
    QueryParseError,
    TenantPlaneQueryError,
)
from jdlib.query.safety import OPERATORS, IdentifierPolicy, parse_specification
from jdlib.query.specification import Filter, QuerySpecification, SortDirection, SortKey

__all__ = [
    "OPERATORS",
    "TENANT_PARAMETER",
    "CompiledQuery",
    "CrossTenantQueryError",
    "Filter",
    "IdentifierPolicy",
    "MysqlDialect",
    "PostgresDialect",
    "Predicate",
    "QueryCompiler",
    "QueryComplexityError",
    "QueryDialect",
    "QueryError",
    "QueryNode",
    "QueryParseError",
    "QuerySpecification",
    "SortColumn",
    "SortDirection",
    "SortKey",
    "TenantPlaneQueryError",
    "parse_specification",
]
