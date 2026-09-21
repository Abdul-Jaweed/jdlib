from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum

import sqlalchemy as sa
from pglast import parse_sql
from pglast.ast import (
    A_Expr,
    BoolExpr,
    ColumnRef,
    DeleteStmt,
    InsertStmt,
    JoinExpr,
    Node,
    ParamRef,
    RangeSubselect,
    RangeVar,
    SelectStmt,
    SubLink,
    UpdateStmt,
)
from pglast.enums import A_Expr_Kind, BoolExprType

from jdlib.errors import UnscopedRawSql
from jdlib.persistence.models import tenant_table_map


class RawSqlMode(StrEnum):
    TENANT_BOUND = "tenant_bound"
    PRIVILEGED = "privileged"


@dataclass(frozen=True, slots=True)
class CompiledRawSql:
    sql: str
    binds: tuple[object, ...]


def _operator_name(expr: A_Expr) -> str | None:
    parts = [getattr(node, "sval", None) for node in (expr.name or ())]
    return "".join(part for part in parts if part)


def _column_is_tenant_id(node: object, qualifiers: set[str]) -> bool:
    if not isinstance(node, ColumnRef):
        return False
    names = [getattr(field, "sval", None) for field in (node.fields or ())]
    if not names or names[-1] != "tenant_id":
        return False
    if len(names) == 1:
        return "" in qualifiers
    if len(names) == 2:
        return names[0] in qualifiers
    return False


def _param_index(node: object) -> int | None:
    return node.number if isinstance(node, ParamRef) else None


def _relation_qualifier(relation: RangeVar) -> str:
    alias = relation.alias
    aliasname = getattr(alias, "aliasname", None) if alias is not None else None
    return aliasname or relation.relname or ""


def _tenant_predicate(
    expr: object, tenant_id: uuid.UUID, binds: tuple[object, ...], qualifiers: set[str]
) -> bool:
    if (
        not isinstance(expr, A_Expr)
        or expr.kind != A_Expr_Kind.AEXPR_OP
        or _operator_name(expr) != "="
    ):
        return False
    for column, value in ((expr.lexpr, expr.rexpr), (expr.rexpr, expr.lexpr)):
        if _column_is_tenant_id(column, qualifiers):
            index = _param_index(value)
            if index is not None and 1 <= index <= len(binds) and binds[index - 1] == tenant_id:
                return True
    return False


def _conjuncts(where: object) -> list[object]:
    if isinstance(where, BoolExpr):
        if where.boolop == BoolExprType.OR_EXPR or where.boolop == BoolExprType.NOT_EXPR:
            raise UnscopedRawSql("OR/NOT predicates are not allowed in tenant-bound SQL")
        collected: list[object] = []
        for arg in where.args or ():
            collected.extend(_conjuncts(arg))
        return collected
    return [where]


def _descendants(node: object) -> Iterator[Node]:
    if isinstance(node, Node):
        yield node
        for field in node:
            yield from _descendants(getattr(node, field))
    elif isinstance(node, (tuple, list)):
        for item in node:
            yield from _descendants(item)


def _scan_expression_tree(stmt: Node, relations: list[RangeVar]) -> None:
    allowed = {id(relation) for relation in relations}
    for node in _descendants(stmt):
        if isinstance(node, SubLink):
            raise UnscopedRawSql("subqueries are not allowed in tenant-bound SQL")
        if isinstance(node, RangeVar) and id(node) not in allowed:
            raise UnscopedRawSql(f"relation outside FROM clause not allowed: {node.relname}")


def _relations(node: object) -> list[RangeVar]:
    if node is None:
        return []
    if isinstance(node, RangeVar):
        return [node]
    if isinstance(node, JoinExpr):
        return _relations(node.larg) + _relations(node.rarg)
    if isinstance(node, RangeSubselect):
        raise UnscopedRawSql("subqueries are not allowed in tenant-bound SQL")
    raise UnscopedRawSql(f"unsupported relation node {type(node).__name__}")


def _check_relation(relation: RangeVar, tables: dict[str, type]) -> str:
    if relation.schemaname is not None:
        raise UnscopedRawSql(f"schema-qualified relation not allowed: {relation.schemaname}")
    if relation.relname is None or relation.relname not in tables:
        raise UnscopedRawSql(f"unknown relation: {relation.relname}")
    return relation.relname


class RawSqlValidator:
    def __init__(self, tenant_tables: dict[str, type] | None = None) -> None:
        self._tables = tenant_tables if tenant_tables is not None else tenant_table_map()

    @staticmethod
    def compile(
        statement: sa.TextClause, dialect: sa.Dialect, params: dict[str, object]
    ) -> CompiledRawSql:
        try:
            compiled = statement.compile(dialect=dialect)
            ordered_names = list(getattr(compiled, "positiontup", None) or params)
            binds = tuple(params[name] for name in ordered_names)
        except Exception as exc:
            raise UnscopedRawSql("raw SQL could not be compiled") from exc
        return CompiledRawSql(sql=str(compiled), binds=binds)

    @staticmethod
    def _reject_cte(stmt: Node, message: str) -> None:
        if (
            isinstance(stmt, (SelectStmt, InsertStmt, UpdateStmt, DeleteStmt))
            and stmt.withClause is not None
        ):
            raise UnscopedRawSql(message)

    def _parse(self, compiled: CompiledRawSql) -> Node:
        try:
            statements = parse_sql(compiled.sql)
        except Exception as exc:
            raise UnscopedRawSql("raw SQL could not be parsed") from exc
        if len(statements) != 1:
            raise UnscopedRawSql("exactly one statement is allowed")
        return statements[0].stmt

    def validate_tenant_bound(self, compiled: CompiledRawSql, tenant_id: uuid.UUID) -> None:
        stmt = self._parse(compiled)
        self._reject_cte(stmt, "CTEs are not allowed in tenant-bound SQL")
        if isinstance(stmt, SelectStmt):
            relations = []
            for node in stmt.fromClause or ():
                relations.extend(_relations(node))
            where = stmt.whereClause
        elif isinstance(stmt, UpdateStmt):
            relations = _relations(stmt.relation)
            for node in stmt.fromClause or ():
                relations.extend(_relations(node))
            where = stmt.whereClause
        elif isinstance(stmt, DeleteStmt):
            relations = _relations(stmt.relation)
            for node in stmt.usingClause or ():
                relations.extend(_relations(node))
            where = stmt.whereClause
        elif isinstance(stmt, InsertStmt):
            self._validate_insert(stmt, compiled, tenant_id)
            return
        else:
            raise UnscopedRawSql(f"unsupported statement type {type(stmt).__name__}")
        if where is None:
            raise UnscopedRawSql("tenant-bound statement requires a WHERE clause")
        conjuncts = _conjuncts(where)
        names = [_check_relation(relation, self._tables) for relation in relations]
        _scan_expression_tree(stmt, relations)
        for relation, name in zip(relations, names, strict=True):
            qualifiers = {_relation_qualifier(relation)}
            if len(relations) == 1:
                qualifiers.add("")
            if not any(
                _tenant_predicate(conjunct, tenant_id, compiled.binds, qualifiers)
                for conjunct in conjuncts
            ):
                raise UnscopedRawSql(f"missing tenant predicate for relation {name}")

    def _validate_insert(
        self, stmt: InsertStmt, compiled: CompiledRawSql, tenant_id: uuid.UUID
    ) -> None:
        relation = stmt.relation
        if relation is None:
            raise UnscopedRawSql("INSERT without target relation")
        _check_relation(relation, self._tables)
        if stmt.selectStmt is None or not isinstance(stmt.selectStmt, SelectStmt):
            raise UnscopedRawSql("INSERT requires a VALUES list")
        if stmt.selectStmt.fromClause:
            raise UnscopedRawSql("INSERT ... SELECT is not allowed in tenant-bound SQL")
        _scan_expression_tree(stmt, [relation])
        columns = [getattr(target.name, "sval", target.name) for target in (stmt.cols or ())]
        if "tenant_id" not in columns:
            raise UnscopedRawSql("INSERT must supply tenant_id explicitly")
        index = columns.index("tenant_id")
        values_lists = stmt.selectStmt.valuesLists or ()
        if not values_lists:
            raise UnscopedRawSql("INSERT tenant_id value missing")
        for values in values_lists:
            if index >= len(values):
                raise UnscopedRawSql("INSERT tenant_id value missing")
            param = _param_index(values[index])
            if (
                param is None
                or not 1 <= param <= len(compiled.binds)
                or compiled.binds[param - 1] != tenant_id
            ):
                raise UnscopedRawSql("INSERT tenant_id value is not bound to the active tenant")

    def validate_privileged(self, compiled: CompiledRawSql) -> None:
        stmt = self._parse(compiled)
        self._reject_cte(stmt, "CTEs are not allowed")
        if not isinstance(stmt, (SelectStmt, InsertStmt, UpdateStmt, DeleteStmt)):
            raise UnscopedRawSql(f"unsupported statement type {type(stmt).__name__}")
