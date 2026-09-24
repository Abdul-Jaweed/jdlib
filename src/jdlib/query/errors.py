from __future__ import annotations

from jdlib.errors import JdlibError


class QueryError(JdlibError):
    """Base for every query failure."""


class QueryParseError(QueryError):
    """A specification was refused while being parsed, before any compiler saw it.

    Identifier allowlisting lives here rather than at render time: a specification is either
    expressible against the declared schema or it is not, and finding that out after the SQL
    is built is finding out too late.
    """


class QueryComplexityError(QueryParseError):
    """A specification was within the schema but outside the bounds on cost."""


class TenantPlaneQueryError(QueryParseError):
    """A specification named a table that only TenantRepository may read (ADR-1)."""


class CrossTenantQueryError(QueryError):
    """A specification does not agree with the security context that would run it."""
