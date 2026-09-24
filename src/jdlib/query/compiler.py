from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from jdlib.query.ast import QueryNode
from jdlib.query.dialect import PostgresDialect, QueryDialect
from jdlib.query.errors import CrossTenantQueryError
from jdlib.query.safety import IdentifierPolicy, parse_specification
from jdlib.query.specification import QuerySpecification
from jdlib.security.context import SecurityContext

TENANT_PARAMETER = "jdlib_scope_tenant"

_OPERATOR_SQL = {
    "eq": "=",
    "ne": "<>",
    "lt": "<",
    "lte": "<=",
    "gt": ">",
    "gte": ">=",
    "like": "LIKE",
    "not_like": "NOT LIKE",
}


@dataclass(frozen=True, slots=True)
class CompiledQuery:
    """Text and its bound parameters as one value.

    They are one value because they are useless apart: text without parameters cannot run, and
    parameters without text have no meaning. A caller therefore cannot accidentally execute the
    statement with the values interpolated, or reuse the parameters against different SQL.
    """

    text: str
    parameters: dict[str, object]
    names_in_order: tuple[str, ...] = ()
    dialect: str = "postgres"

    def __repr__(self) -> str:
        return (
            f"CompiledQuery(dialect={self.dialect!r}, names_in_order={self.names_in_order!r}, "
            "values=[REDACTED])"
        )


@dataclass
class QueryCompiler:
    """Renders a parsed specification to SQL for one dialect, binding every value."""

    policy: IdentifierPolicy
    dialect: QueryDialect = field(default_factory=PostgresDialect)

    def compile(
        self, spec: QuerySpecification, *, context: SecurityContext | None
    ) -> CompiledQuery:
        tenant_id = self._authorized_tenant(spec, context)
        node = parse_specification(spec, self.policy)
        return self.render(node, tenant_id=tenant_id)

    @staticmethod
    def _authorized_tenant(spec: QuerySpecification, context: SecurityContext | None) -> str:
        if context is None:
            raise CrossTenantQueryError(
                "a query cannot be compiled without a security context: the tenant it will run "
                "for would be unknown, and guessing it is not an option"
            )
        tenant = context.require_tenant()
        authorized = str(tenant.tenant_id)
        if spec.tenant_id is not None and spec.tenant_id != authorized:
            raise CrossTenantQueryError(
                "the specification names a different tenant than the security context "
                "authorizes; the context wins and the disagreement is refused"
            )
        return authorized

    def render(self, node: QueryNode, *, tenant_id: str) -> CompiledQuery:
        self._dialect_marker = self.dialect.name
        parameters: dict[str, object] = {}
        names: list[str] = []

        def bind(value: object, hint: str) -> str:
            name = f"jdlib_{hint}_{len(names)}"
            parameters[name] = value
            names.append(name)
            return self.dialect.placeholder(name)

        quote = self.dialect.quote
        columns = ", ".join(quote(column) for column in node.columns)
        text = f"SELECT {columns} FROM {quote(node.table)}"

        predicates: list[str] = []
        if node.tenant_scoped:
            predicates.append(f"{quote('tenant_id')} = {bind(tenant_id, 'scope')}")
        for predicate in node.predicates:
            column = quote(predicate.column)
            if predicate.operator in ("in", "not_in"):
                values = list(predicate.value) if isinstance(predicate.value, Iterable) else []
                placeholders = ", ".join(bind(value, "v") for value in values)
                keyword = "IN" if predicate.operator == "in" else "NOT IN"
                predicates.append(f"{column} {keyword} ({placeholders})")
                continue
            predicates.append(
                f"{column} {_OPERATOR_SQL[predicate.operator]} {bind(predicate.value, 'v')}"
            )
        if predicates:
            text += " WHERE " + " AND ".join(predicates)

        if node.order_by:
            ordering = ", ".join(
                f"{quote(key.column)} {key.direction.name}" for key in node.order_by
            )
            text += f" ORDER BY {ordering}"

        text += f" LIMIT {bind(node.limit, 'limit')}"
        if node.offset:
            text += f" OFFSET {bind(node.offset, 'offset')}"

        return CompiledQuery(
            text=text,
            parameters=parameters,
            names_in_order=tuple(names),
            dialect=self.dialect.name,
        )
