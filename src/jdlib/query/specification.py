"""What a caller may ask for - and, by omission, what they may not.

There is deliberately no field for raw SQL, a join, a subquery, a function call or a ``HAVING``
clause: an unexpressible construct cannot be smuggled in, which is worth more than a list of
forbidden ones. Values are always values, bound by the compiler.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class SortDirection(StrEnum):
    ASC = "asc"
    DESC = "desc"


class Filter(BaseModel):
    """One predicate. ``operator`` is a name from the policy's allowlist, never a fragment."""

    column: str
    operator: str
    value: object = None


class SortKey(BaseModel):
    column: str
    direction: SortDirection = SortDirection.ASC


class QuerySpecification(BaseModel):
    table: str
    columns: list[str]
    filters: list[Filter] = Field(default_factory=list)
    order_by: list[SortKey] = Field(default_factory=list)
    limit: int | None = None
    offset: int | None = None
    tenant_id: str | None = None
