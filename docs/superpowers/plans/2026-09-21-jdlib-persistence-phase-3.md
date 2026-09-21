# jdlib Persistence Core (Phase 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the tenant-aware persistence layer: `TenantSession` with automatic scoping/stamping/validation, the fail-closed raw-SQL validator, `UnitOfWork`, `TenantRepository`, the `IsolationStrategy` protocol with the shared-schema adapter, and `SessionRouter` — proven by the isolation test suite on real PostgreSQL.

**Architecture:** SQLAlchemy events (`do_orm_execute` for reads/DML guard, `before_flush` for stamping/immutability) enforce tenant scoping inside `TenantSession`; application code never writes a tenant predicate. `rawsql.py` proves tenant boundedness structurally with `pglast` on dialect-compiled SQL. `UnitOfWork` is the transaction/admission boundary (write fence), `SessionRouter` selects the physical target via `IsolationStrategy`.

**Tech Stack:** SQLAlchemy 2.0 async (`asyncpg`), pglast, pytest + pytest-asyncio, testcontainers PostgreSQL 16. No new dependencies.

**Specs (frozen):** design rev 7 §6; `docs/jdlib/03-isolation-invariants.md` (I1–I4, I9, I11–I13, failure semantics); `docs/jdlib/06-strategy-matrix.md` §2–§4; `docs/jdlib/07-implementation-design.md` §6.3, §7.

## Global Constraints

- Python `>=3.12`; async-first; no new dependencies.
- Reads get automatic tenant predicates; writes are auto-stamped and validated; `tenant_id` is immutable; hard delete of `SoftDelete` models requires a privileged context.
- `TenantSession.raw_sql` has exactly two modes: `TENANT_BOUND` (structural proof required, `UnscopedRawSql` otherwise) and `PRIVILEGED` (capability-gated, audited). No boolean switch.
- Bulk DML through raw `session.execute(update()/delete())` against tenant tables raises `UnscopedBulkOperation`; scoped helpers set `jdlib_scoped=True`.
- No application writes may occur during relocation critical phases: `UnitOfWork` checks a `WriteFence` port at admission; privileged contexts bypass the fence.
- Commands: `.venv/Scripts/python -m pytest ...`, `ruff check .`, `mypy src/jdlib`; integration tests need `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` on this machine.
- No comments in source; docstrings only where the plan shows them; pristine test output.
- Commit after every task.

---

### Task 1: Tenant model discovery and `WriteFence`

**Files:**
- Create: `src/jdlib/persistence/__init__.py`
- Create: `src/jdlib/persistence/models.py`
- Create: `tests/unit/test_persistence_models.py`

**Interfaces:**
- Consumes: `TenantBase`, `TenantRouted` from `jdlib.models.base`; `TenantContext`, `PrivilegeKind` from `jdlib.context`; `TenantNotWritable` from `jdlib.errors`.
- Produces: `tenant_table_map() -> dict[str, type]` (table name → model, for every `TenantRouted` model mapped on `TenantBase`); `WriteFence` protocol (`async def assert_writable(tenant_id: uuid.UUID) -> None`); `NullWriteFence`; `privileged_bypass(context) -> bool`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_persistence_models.py`:

```python
import uuid
from datetime import datetime, timezone

import pytest

from jdlib.context import Principal, PrivilegeContext, PrivilegeKind, TenantContext
from jdlib.control.enums import PlacementStrategy, PrincipalKind
from jdlib.errors import TenantNotWritable
from jdlib.models.base import TenantRouted
from jdlib.persistence.models import (
    NullWriteFence,
    privileged_bypass,
    tenant_table_map,
)

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _context(privilege: PrivilegeContext | None = None) -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
        privilege=privilege,
    )


def test_tenant_table_map_covers_framework_tenant_plane():
    tables = tenant_table_map()
    assert {"organizations", "teams", "tenant_settings", "audit_events"} <= set(tables)
    assert all(issubclass(model, TenantRouted) for model in tables.values())


async def test_null_write_fence_always_allows():
    await NullWriteFence().assert_writable(TENANT_ID)


def test_privileged_bypass_requires_privilege_kind():
    assert privileged_bypass(_context()) is False
    operator = PrivilegeContext(
        kind=PrivilegeKind.OPERATOR,
        capability="platform.tenant.access.write",
        justification="ticket",
        actor=Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4()),
        issued_at=datetime.now(timezone.utc),
        expires_at=None,
    )
    assert privileged_bypass(_context(operator)) is True
    system = PrivilegeContext(
        kind=PrivilegeKind.SYSTEM,
        capability="relocation.manage",
        justification=None,
        actor=Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4()),
        issued_at=datetime.now(timezone.utc),
        expires_at=None,
    )
    assert privileged_bypass(_context(system)) is True


class _FencedFence:
    async def assert_writable(self, tenant_id: uuid.UUID) -> None:
        raise TenantNotWritable("relocation in progress")


async def test_fence_raises_for_non_privileged_context():
    with pytest.raises(TenantNotWritable):
        await _FencedFence().assert_writable(TENANT_ID)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_persistence_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.persistence'`

- [ ] **Step 3: Implement `src/jdlib/persistence/__init__.py` (empty) and `src/jdlib/persistence/models.py`**

```python
from __future__ import annotations

import uuid
from typing import Protocol

from jdlib.context import TenantContext
from jdlib.models.base import TenantBase, TenantRouted


def tenant_table_map() -> dict[str, type]:
    found: dict[str, type] = {}

    def walk(cls: type) -> None:
        for subclass in cls.__subclasses__():
            table = getattr(subclass, "__table__", None)
            if table is not None and table.metadata is TenantBase.metadata:
                if issubclass(subclass, TenantRouted):
                    found[table.name] = subclass
            walk(subclass)

    walk(TenantRouted)
    return found


class WriteFence(Protocol):
    async def assert_writable(self, tenant_id: uuid.UUID) -> None: ...


class NullWriteFence:
    async def assert_writable(self, tenant_id: uuid.UUID) -> None:
        return None


def privileged_bypass(context: TenantContext) -> bool:
    return context.privilege is not None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_persistence_models.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/persistence tests/unit/test_persistence_models.py
git commit -m "feat: tenant table discovery and write fence port"
```

---

### Task 2: Raw SQL validator

**Files:**
- Create: `src/jdlib/persistence/rawsql.py`
- Create: `tests/unit/test_rawsql.py`

**Interfaces:**
- Consumes: `jdlib.persistence.models.tenant_table_map`; `jdlib.errors.UnscopedRawSql`.
- Produces: `RawSqlMode` (`tenant_bound`, `privileged`); `CompiledRawSql(sql, binds)`; `RawSqlValidator(tenant_tables=None)` with `compile(statement, dialect) -> CompiledRawSql`, `validate_tenant_bound(compiled, tenant_id) -> None`, `validate_privileged(compiled) -> None`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_rawsql.py`:

```python
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from jdlib.errors import UnscopedRawSql
from jdlib.persistence.rawsql import RawSqlValidator

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
OTHER_ID = uuid.UUID("00000000-0000-0000-0000-0000000000bb")
DIALECT = postgresql.asyncpg.dialect()


@pytest.fixture()
def validator() -> RawSqlValidator:
    return RawSqlValidator(tenant_tables={"invoices": object, "projects": object})


def _compiled(sql: str, **params: object):
    statement = sa.text(sql).bindparams(**{k: sa.bindparam(k) for k in params})
    return RawSqlValidator.compile(statement, DIALECT, params)


def test_select_with_tenant_predicate_passes(validator):
    validator.validate_tenant_bound(
        _compiled(
            "SELECT * FROM invoices WHERE tenant_id = :tenant_id", tenant_id=TENANT_ID
        ),
        TENANT_ID,
    )


def test_select_without_predicate_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(_compiled("SELECT * FROM invoices"), TENANT_ID)


def test_or_true_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id = :tenant_id OR TRUE",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_wrong_tenant_value_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id = :tenant_id", tenant_id=OTHER_ID
            ),
            TENANT_ID,
        )


def test_is_distinct_from_predicate_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id IS DISTINCT FROM :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_is_not_distinct_from_predicate_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id IS NOT DISTINCT FROM :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_any_predicate_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id = ANY(:tenant_id)",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_join_requires_predicate_on_every_relation(validator):
    sql = (
        "SELECT * FROM invoices i JOIN projects p ON p.tenant_id = i.tenant_id "
        "WHERE i.tenant_id = :tenant_id"
    )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(_compiled(sql, tenant_id=TENANT_ID), TENANT_ID)
    sql_ok = (
        "SELECT * FROM invoices i JOIN projects p ON p.tenant_id = i.tenant_id "
        "WHERE i.tenant_id = :tenant_id AND p.tenant_id = :tenant_id"
    )
    validator.validate_tenant_bound(_compiled(sql_ok, tenant_id=TENANT_ID), TENANT_ID)


def test_update_and_delete_require_predicate(validator):
    validator.validate_tenant_bound(
        _compiled(
            "UPDATE invoices SET status = :status WHERE tenant_id = :tenant_id",
            status="paid",
            tenant_id=TENANT_ID,
        ),
        TENANT_ID,
    )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled("DELETE FROM invoices"), TENANT_ID
        )


def test_insert_requires_bound_tenant_value(validator):
    validator.validate_tenant_bound(
        _compiled(
            "INSERT INTO invoices (tenant_id, id) VALUES (:tenant_id, :id)",
            tenant_id=TENANT_ID,
            id=uuid.uuid4(),
        ),
        TENANT_ID,
    )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "INSERT INTO invoices (tenant_id, id) VALUES (:tenant_id, :id)",
                tenant_id=OTHER_ID,
                id=uuid.uuid4(),
            ),
            TENANT_ID,
        )


def test_unknown_relation_and_schema_escape_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled("SELECT * FROM mystery WHERE tenant_id = :tenant_id", tenant_id=TENANT_ID),
            TENANT_ID,
        )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM other_schema.invoices WHERE tenant_id = :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_cte_subquery_and_multi_statement_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "WITH x AS (SELECT * FROM invoices) SELECT * FROM x WHERE tenant_id = :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM (SELECT * FROM invoices) s WHERE tenant_id = :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id = :tenant_id; DROP TABLE invoices",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_privileged_mode_still_rejects_ddl(validator):
    validator.validate_privileged(_compiled("SELECT * FROM invoices"))
    with pytest.raises(UnscopedRawSql):
        validator.validate_privileged(_compiled("DROP TABLE invoices"))


def test_scalar_subquery_in_target_list_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT (SELECT count(*) FROM projects) FROM invoices "
                "WHERE tenant_id = :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_exists_subquery_in_where_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "SELECT * FROM invoices WHERE tenant_id = :tenant_id "
                "AND EXISTS (SELECT 1 FROM projects)",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_insert_checks_every_values_row(validator):
    validator.validate_tenant_bound(
        _compiled(
            "INSERT INTO invoices (tenant_id, id) VALUES (:tenant_id, :id1), (:tenant_id, :id2)",
            tenant_id=TENANT_ID,
            id1=uuid.uuid4(),
            id2=uuid.uuid4(),
        ),
        TENANT_ID,
    )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "INSERT INTO invoices (tenant_id, id) VALUES (:tenant_id, :id1), (:other, :id2)",
                tenant_id=TENANT_ID,
                other=OTHER_ID,
                id1=uuid.uuid4(),
                id2=uuid.uuid4(),
            ),
            TENANT_ID,
        )


def test_insert_literal_tenant_value_rejected(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "INSERT INTO invoices (tenant_id, id) VALUES (:tenant_id, :id1), "
                "('00000000-0000-0000-0000-0000000000bb', :id2)",
                tenant_id=TENANT_ID,
                id1=uuid.uuid4(),
                id2=uuid.uuid4(),
            ),
            TENANT_ID,
        )


def test_update_from_requires_predicate_on_every_relation(validator):
    sql = (
        "UPDATE invoices SET status = :status FROM projects p "
        "WHERE invoices.tenant_id = :tenant_id"
    )
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(sql, status="paid", tenant_id=TENANT_ID), TENANT_ID
        )
    sql_ok = (
        "UPDATE invoices SET status = :status FROM projects p "
        "WHERE invoices.tenant_id = :tenant_id AND p.tenant_id = :tenant_id"
    )
    validator.validate_tenant_bound(
        _compiled(sql_ok, status="paid", tenant_id=TENANT_ID), TENANT_ID
    )


def test_delete_using_requires_predicate_on_every_relation(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(
            _compiled(
                "DELETE FROM invoices USING projects WHERE invoices.tenant_id = :tenant_id",
                tenant_id=TENANT_ID,
            ),
            TENANT_ID,
        )


def test_malformed_sql_raises_unscoped(validator):
    with pytest.raises(UnscopedRawSql):
        validator.validate_tenant_bound(_compiled("SELECT FROM"), TENANT_ID)


def test_missing_bind_parameter_raises_unscoped():
    with pytest.raises(UnscopedRawSql):
        _compiled("SELECT * FROM invoices WHERE tenant_id = :tenant_id")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_rawsql.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.persistence.rawsql'`

- [ ] **Step 3: Implement `src/jdlib/persistence/rawsql.py`**

```python
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
```

Notes for the implementer (updated after review fixes, pglast v8.4 verified):
- `stmt.withClause` is accessed directly on `SelectStmt`/`InsertStmt`/`UpdateStmt`/`DeleteStmt` via
  `_reject_cte`; a rename or missing attribute now fails loudly (mypy/runtime) instead of silently
  disabling CTE rejection. Keep it that way.
- `UpdateStmt.fromClause` and `DeleteStmt.usingClause` are the v8.4 names for extra DML relations;
  both are fed through `_relations()` so every relation needs its own tenant predicate.
- `BoolExpr` has no `OR`/`NOT` class constants in v8.4; compare `where.boolop` against
  `pglast.enums.BoolExprType.OR_EXPR` / `NOT_EXPR`.
- `_scan_expression_tree` walks the parsed statement with `Node.__iter__` and fails closed on any
  `SubLink` (scalar/`EXISTS`/`IN`/`ANY`/`ALL` expression subqueries) and on any `RangeVar` outside
  the allowed FROM/relation paths (e.g. `SELECT INTO`).
- `compile` and `_parse` wrap SQLAlchemy/pglast exceptions and raise `UnscopedRawSql`, so malformed
  SQL or unresolved binds fail closed. `_validate_insert` checks every row in `valuesLists`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_rawsql.py -v`
Expected: PASS (21 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/persistence/rawsql.py tests/unit/test_rawsql.py
git commit -m "feat: structural raw SQL validator"
```

---

### Task 3: TenantSession — scoping, stamping, guards

**Files:**
- Create: `src/jdlib/persistence/session.py`
- Create: `tests/integration/test_session_isolation.py`
- Create: `tests/unit/test_session.py`
- Modify: `tests/integration/conftest.py` (add async engine + seeded tenants fixtures)

**Interfaces:**
- Consumes: Task 1–2; `TenantContext`; `TenantRouted`, `SoftDelete`; errors.
- Produces: `TenantSession` with `context`, `raw_sql(statement, params, *, mode)`, `execute(statement)`, `get(model, id)`, `add(obj)`, `flush()`, `update_where(model, values, *criteria)`, `delete_where(model, *criteria)`; `RawSqlAuditor` protocol.
- Invariants (fail closed): `delete_where` refuses `SoftDelete` models without a privileged context; `update_where` refuses `tenant_id` changes without a privileged context; `execute` refuses `TextClause`; unscoped Core INSERT/UPDATE/DELETE on tenant tables is refused unless `jdlib_scoped`/`jdlib_raw_sql` is set, including DML wrapped in `select(...).from_statement(...)` (table resolved from the statement's `element`); entity-less ORM selects (e.g. `select(func.count()).select_from(Model)`) are scoped via the statement's bind mapper only when its table is a direct FROM; SELECTs that reference a tenant table anywhere in the statement tree without such a scopable bind mapper (`select(Model.__table__)`, or a tenant table buried in a subquery) are refused as `UnscopedRawSql`; `raw_sql(PRIVILEGED)` reads `self.context.privilege` (not the ambient contextvar).

- [ ] **Step 1: Add async fixtures to `tests/integration/conftest.py`**

Append:

```python
@pytest.fixture()
async def async_engine(postgres_url: str):
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from jdlib.control.base import ControlBase
    from jdlib.control.models import Tenant  # noqa: F401
    from jdlib.models import audit, org, settings  # noqa: F401
    from jdlib.models.base import TenantBase
    from tests.support.invoice import Invoice  # noqa: F401

    engine = create_async_engine(
        postgres_url.replace("postgresql+psycopg", "postgresql+asyncpg")
    )
    async with engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{CONTROL_SCHEMA}"'))
        await connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{TENANT_SCHEMA}"'))
        await connection.execute(text(f'SET search_path TO "{TENANT_SCHEMA}"'))
        await connection.run_sync(TenantBase.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def session_factory(async_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    return async_sessionmaker(async_engine, expire_on_commit=False)
```

- [ ] **Step 2: Write the failing isolation tests**

`tests/integration/test_session_isolation.py`:

```python
import uuid

import pytest
import sqlalchemy as sa

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import (
    AuthorizationError,
    CrossTenantReferenceError,
    MissingTenantContext,
    UnscopedBulkOperation,
    UnscopedRawSql,
)
from jdlib.persistence.session import TenantSession
from tests.support.invoice import Invoice

TENANT_A = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
TENANT_B = uuid.UUID("00000000-0000-0000-0000-0000000000bb")


def _context(tenant_id: uuid.UUID) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme" if tenant_id == TENANT_A else "globex",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
    )


async def _session(session_factory, tenant_id: uuid.UUID) -> TenantSession:
    raw = session_factory()
    await raw.execute(sa.text('SET search_path TO "jt_test"'))
    return TenantSession(raw, _context(tenant_id))


async def test_reads_are_scoped_to_context_tenant(session_factory):
    async with await _session(session_factory, TENANT_B) as session:
        await session.add(Invoice(number=f"B-{uuid.uuid4().hex[:8]}"))
        await session.commit()
    async with await _session(session_factory, TENANT_A) as session:
        await session.add(Invoice(number=f"A-{uuid.uuid4().hex[:8]}"))
        await session.add(Invoice(number=f"A-{uuid.uuid4().hex[:8]}"))
        await session.commit()
    async with await _session(session_factory, TENANT_A) as session:
        rows = (await session.execute(sa.select(Invoice))).scalars().all()
        assert rows
        assert all(row.tenant_id == TENANT_A for row in rows)


async def test_entity_less_select_is_scoped(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        before = int(
            (
                await session.execute(sa.select(sa.func.count()).select_from(Invoice))
            ).scalar_one()
        )
    async with await _session(session_factory, TENANT_B) as session:
        await session.add(Invoice(number=f"B-{uuid.uuid4().hex[:8]}"))
        await session.commit()
    async with await _session(session_factory, TENANT_A) as session:
        scoped = int(
            (
                await session.execute(sa.select(sa.func.count()).select_from(Invoice))
            ).scalar_one()
        )
    raw = session_factory()
    await raw.execute(sa.text('SET search_path TO "jt_test"'))
    try:
        total = int(
            (await raw.execute(sa.text("SELECT count(*) FROM invoices"))).scalar_one()
        )
    finally:
        await raw.close()
    assert scoped == before
    assert total > scoped


async def test_table_level_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="table-level statements"):
            await session.execute(sa.select(Invoice.__table__))


async def test_subquery_table_level_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="table-level statements"):
            await session.execute(
                sa.select(sa.func.count()).select_from(sa.select(Invoice.id).subquery())
            )


async def test_cross_tenant_get_returns_none(session_factory):
    other_id = uuid.uuid4()
    async with await _session(session_factory, TENANT_B) as session:
        await session.add(Invoice(id=other_id, number=f"B-{uuid.uuid4().hex[:8]}"))
        await session.commit()
    async with await _session(session_factory, TENANT_B) as session:
        assert await session.get(Invoice, other_id) is not None
    async with await _session(session_factory, TENANT_A) as session:
        assert await session.get(Invoice, other_id) is None


async def test_writes_are_stamped(session_factory):
    invoice = Invoice(number=f"A-{uuid.uuid4().hex[:8]}")
    async with await _session(session_factory, TENANT_A) as session:
        await session.add(invoice)
        await session.flush()
        assert invoice.tenant_id == TENANT_A


async def test_explicit_foreign_tenant_id_rejected(session_factory):
    invoice = Invoice(number=f"X-{uuid.uuid4().hex[:8]}", tenant_id=TENANT_B)
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(CrossTenantReferenceError):
            await session.add(invoice)
            await session.flush()


async def test_tenant_id_is_immutable(session_factory):
    invoice = Invoice(number=f"A-{uuid.uuid4().hex[:8]}")
    async with await _session(session_factory, TENANT_A) as session:
        await session.add(invoice)
        await session.flush()
        invoice.tenant_id = TENANT_B
        with pytest.raises(CrossTenantReferenceError):
            await session.flush()


async def test_unscoped_bulk_dml_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedBulkOperation):
            await session.execute(sa.update(Invoice).values(status="paid"))


async def test_scoped_bulk_helpers_work(session_factory):
    number = f"A-{uuid.uuid4().hex[:8]}"
    async with await _session(session_factory, TENANT_A) as session:
        await session.add(Invoice(number=number))
        await session.flush()
        changed = await session.update_where(Invoice, {"status": "paid"}, Invoice.number == number)
        assert changed == 1


async def test_delete_where_rejects_soft_delete_without_privilege(session_factory):
    invoice = Invoice(number=f"A-{uuid.uuid4().hex[:8]}")
    async with await _session(session_factory, TENANT_A) as session:
        await session.add(invoice)
        await session.flush()
        with pytest.raises(AuthorizationError):
            await session.delete_where(Invoice, Invoice.id == invoice.id)


async def test_update_where_rejects_tenant_id_change(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(AuthorizationError):
            await session.update_where(
                Invoice, {"tenant_id": TENANT_B}, Invoice.number == "missing"
            )


async def test_execute_text_statement_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="use raw_sql for text statements"):
            await session.execute(sa.text("DELETE FROM invoices"))


async def test_execute_core_insert_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedBulkOperation):
            await session.execute(
                sa.insert(Invoice).values(
                    id=uuid.uuid4(),
                    tenant_id=TENANT_A,
                    number=f"A-{uuid.uuid4().hex[:8]}",
                    status="draft",
                )
            )


async def test_session_requires_context(session_factory):
    raw = session_factory()
    with pytest.raises(MissingTenantContext):
        TenantSession(raw, None)  # type: ignore[arg-type]
```

`tests/unit/test_session.py` (privileged raw SQL must read the session context's privilege, not
the ambient contextvar):

```python
import uuid
from datetime import UTC, datetime
from typing import Any, cast

import pytest
import sqlalchemy as sa

from jdlib.context import (
    Principal,
    PrincipalKind,
    PrivilegeContext,
    PrivilegeKind,
    TenantContext,
    context_scope,
)
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import AuthorizationError, UnscopedBulkOperation
from jdlib.persistence.rawsql import RawSqlMode
from jdlib.persistence.session import TenantSession
from tests.support.invoice import Invoice

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _context(privilege: PrivilegeContext | None = None) -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
        privilege=privilege,
    )


def _privilege() -> PrivilegeContext:
    return PrivilegeContext(
        kind=PrivilegeKind.OPERATOR,
        capability="tenant.raw_sql",
        justification="ticket",
        actor=Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4()),
        issued_at=datetime.now(UTC),
        expires_at=None,
    )


class _StubAsyncSession:
    def __init__(self) -> None:
        self.sync_session = sa.orm.Session()
        self.bind = sa.create_engine("postgresql+psycopg://")
        self.result: Any = object()
        self.executed: list[sa.Executable] = []

    async def execute(self, statement: sa.Executable, params: object = None) -> Any:
        self.executed.append(statement)
        return self.result


class _ExecutingStubAsyncSession(_StubAsyncSession):
    async def execute(self, statement: sa.Executable, params: object = None) -> Any:
        self.executed.append(statement)
        return self.sync_session.execute(statement, params)


def _tenant_session(context: TenantContext, stub: _StubAsyncSession) -> TenantSession:
    return TenantSession(cast(Any, stub), context)


async def test_from_statement_wrapped_insert_rejected() -> None:
    stub = _ExecutingStubAsyncSession()
    session = _tenant_session(_context(), stub)
    statement = sa.select(Invoice).from_statement(sa.insert(Invoice).returning(Invoice))
    with pytest.raises(UnscopedBulkOperation):
        await session.execute(statement)


async def test_privileged_raw_sql_rejects_without_session_privilege() -> None:
    stub = _StubAsyncSession()
    session = _tenant_session(_context(), stub)
    with context_scope(_context(_privilege())), pytest.raises(AuthorizationError):
        await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    assert stub.executed == []


async def test_privileged_raw_sql_accepts_session_privilege() -> None:
    stub = _StubAsyncSession()
    session = _tenant_session(_context(_privilege()), stub)
    with context_scope(_context()):
        result = await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    assert result is stub.result
    assert len(stub.executed) == 1
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_session_isolation.py tests/unit/test_session.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.persistence.session'`

- [ ] **Step 4: Implement `src/jdlib/persistence/session.py`**

```python
from __future__ import annotations

import uuid
from typing import Any, Protocol, cast

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlalchemy.sql import visitors

from jdlib.context import TenantContext
from jdlib.errors import (
    AuthorizationError,
    CrossTenantReferenceError,
    MissingTenantContext,
    UnscopedBulkOperation,
    UnscopedRawSql,
)
from jdlib.models.base import SoftDelete, TenantRouted
from jdlib.persistence.models import tenant_table_map
from jdlib.persistence.rawsql import CompiledRawSql, RawSqlMode, RawSqlValidator

_CTX_KEY = "jdlib_context"


class RawSqlAuditor(Protocol):
    async def record_raw_sql(
        self, *, mode: RawSqlMode, capability: str | None, tenant_id: uuid.UUID, sql: str
    ) -> None: ...


class _NoopRawSqlAuditor:
    async def record_raw_sql(
        self, *, mode: RawSqlMode, capability: str | None, tenant_id: uuid.UUID, sql: str
    ) -> None:
        return None


def _context_of(session: Session) -> TenantContext:
    context: TenantContext | None = session.info.get(_CTX_KEY)
    if context is None:
        raise MissingTenantContext("session has no tenant context")
    return context


def _register_events(session: Session) -> None:
    tables = tenant_table_map()

    @sa.event.listens_for(session, "do_orm_execute")
    def _scope(state: sa.orm.ORMExecuteState) -> None:
        context = state.session.info.get(_CTX_KEY)
        if context is None:
            if state.is_select or state.is_update or state.is_delete or state.is_insert:
                raise MissingTenantContext("session has no tenant context")
            return
        if state.is_select:
            tenant_id = context.tenant_id
            mappers = list(state.all_mappers)
            if not mappers:
                get_final_froms = getattr(state.statement, "get_final_froms", None)
                froms = (
                    get_final_froms()
                    if get_final_froms is not None
                    else getattr(state.statement, "froms", ())
                )
                direct = {from_.name for from_ in froms if isinstance(from_, sa.Table)}
                if (
                    state.bind_mapper is not None
                    and getattr(state.bind_mapper.local_table, "name", None) in direct
                ):
                    mappers = [state.bind_mapper]
            if not mappers:
                tenant_tables = {
                    element.name
                    for element in visitors.iterate(cast(Any, state.statement))
                    if isinstance(element, sa.Table)
                } & set(tables)
                if tenant_tables:
                    raise UnscopedRawSql(
                        "table-level statements on tenant tables must use raw_sql"
                    )
            options = [
                sa.orm.with_loader_criteria(
                    mapper.class_,
                    lambda cls: cls.tenant_id == tenant_id,
                    include_aliases=True,
                )
                for mapper in mappers
                if issubclass(mapper.class_, TenantRouted)
            ]
            if options:
                state.statement = state.statement.options(*options)
        elif state.is_insert or state.is_update or state.is_delete:
            if state.execution_options.get("jdlib_scoped") or state.execution_options.get(
                "jdlib_raw_sql"
            ):
                return
            table = getattr(state.statement, "table", None)
            if table is None:
                table = getattr(getattr(state.statement, "element", None), "table", None)
            if table is not None and table.name in tables:
                raise UnscopedBulkOperation(
                    f"unscoped bulk DML on {table.name}; use update_where/delete_where/raw_sql"
                )

    @sa.event.listens_for(session, "before_flush")
    def _validate(flush_session: Session, flush_context: object, instances: object) -> None:
        context = _context_of(flush_session)
        for obj in flush_session.new:
            if isinstance(obj, TenantRouted):
                current = obj.tenant_id
                if current is None:
                    obj.tenant_id = context.tenant_id
                elif current != context.tenant_id:
                    raise CrossTenantReferenceError(
                        f"{type(obj).__name__}.tenant_id", str(context.tenant_id), str(current)
                    )
        for obj in flush_session.dirty:
            if not isinstance(obj, TenantRouted):
                continue
            state = sa.inspect(obj)
            if state is None:
                continue
            history = state.attrs.tenant_id.history
            if history.has_changes():
                raise CrossTenantReferenceError(
                    f"{type(obj).__name__}.tenant_id",
                    str(context.tenant_id),
                    str(history.added[0] if history.added else history.deleted[0]),
                )
        for obj in flush_session.deleted:
            if isinstance(obj, SoftDelete) and context.privilege is None:
                raise AuthorizationError("hard delete requires a privileged context")


class TenantSession:
    def __init__(
        self,
        session: AsyncSession,
        context: TenantContext | None,
        *,
        auditor: RawSqlAuditor | None = None,
        validator: RawSqlValidator | None = None,
    ) -> None:
        if context is None:
            raise MissingTenantContext("TenantSession requires a TenantContext")
        self._session = session
        self.context = context
        self._auditor = auditor or _NoopRawSqlAuditor()
        self._validator = validator or RawSqlValidator()
        session.sync_session.info[_CTX_KEY] = context
        _register_events(session.sync_session)

    async def __aenter__(self) -> TenantSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._session.close()

    async def flush(self) -> None:
        await self._session.flush()

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()

    async def execute(self, statement: sa.Executable) -> sa.Result[Any]:
        if isinstance(statement, sa.TextClause):
            raise UnscopedRawSql("use raw_sql for text statements")
        return await self._session.execute(statement)

    async def get(self, model: type[Any], entity_id: uuid.UUID) -> Any | None:
        if issubclass(model, TenantRouted):
            return await self._session.get(model, (self.context.tenant_id, entity_id))
        return await self._session.get(model, entity_id)

    async def add(self, obj: Any) -> None:
        self._session.add(obj)

    async def delete(self, obj: Any) -> None:
        await self._session.delete(obj)

    async def update_where(
        self, model: type[Any], values: dict[str, Any], *criteria: sa.ColumnElement[bool]
    ) -> int:
        if "tenant_id" in values and self.context.privilege is None:
            raise AuthorizationError("tenant_id update requires a privileged context")
        statement = (
            sa.update(model)
            .where(model.tenant_id == self.context.tenant_id, *criteria)
            .values(**values)
            .execution_options(jdlib_scoped=True)
        )
        result = cast(sa.CursorResult[Any], await self._session.execute(statement))
        return int(result.rowcount or 0)

    async def delete_where(
        self, model: type[Any], *criteria: sa.ColumnElement[bool]
    ) -> int:
        if issubclass(model, SoftDelete) and self.context.privilege is None:
            raise AuthorizationError("hard delete requires a privileged context")
        statement = (
            sa.delete(model)
            .where(model.tenant_id == self.context.tenant_id, *criteria)
            .execution_options(jdlib_scoped=True)
        )
        result = cast(sa.CursorResult[Any], await self._session.execute(statement))
        return int(result.rowcount or 0)

    async def raw_sql(
        self,
        statement: sa.TextClause,
        params: dict[str, object] | None = None,
        *,
        mode: RawSqlMode = RawSqlMode.TENANT_BOUND,
    ) -> sa.Result[Any]:
        params = params or {}
        dialect = self._session.bind.dialect
        compiled: CompiledRawSql = self._validator.compile(statement, dialect, params)
        if mode == RawSqlMode.PRIVILEGED:
            privilege = self.context.privilege
            if privilege is None:
                raise AuthorizationError("privileged raw SQL requires a privileged context")
            capability = privilege.capability or ""
            if capability not in {"tenant.raw_sql", "platform.raw_sql"}:
                raise AuthorizationError("missing raw SQL capability")
            self._validator.validate_privileged(compiled)
            await self._auditor.record_raw_sql(
                mode=mode, capability=capability, tenant_id=self.context.tenant_id, sql=compiled.sql
            )
        else:
            self._validator.validate_tenant_bound(compiled, self.context.tenant_id)
        return await self._session.execute(
            statement.execution_options(jdlib_raw_sql=True), params
        )
```

Note for the implementer: `ORMExecuteState.is_insert` exists in SQLAlchemy 2.0.54 and is
required for the bulk-DML guard. If `pglast.ast.BoolExpr` uses different constant names in a
future version, adapt minimally.

- [ ] **Step 5: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_session_isolation.py tests/unit/test_session.py -v`
Expected: PASS (18 passed: 15 integration + 3 unit)

- [ ] **Step 6: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

Expected: `156 passed`; `All checks passed!`; `Success: no issues found in 27 source files`.
Note: the pre-existing unraisable `ResourceWarning` under `-W error` (undisposed engines in
`tests/integration/test_migrations.py` / `test_tenant_models.py`) has been fixed by disposing
those engines; the full suite is green under `-W error`.

```bash
git add src/jdlib/persistence/session.py tests/integration/test_session_isolation.py tests/unit/test_session.py tests/integration/conftest.py
git commit -m "feat: tenant session with scoping, stamping, and bulk guards"
```

---

### Task 4: UnitOfWork

**Files:**
- Create: `src/jdlib/persistence/uow.py`
- Create: `tests/unit/test_uow.py`

**Interfaces:**
- Consumes: `TenantSession`, `WriteFence`, `privileged_bypass`, `TenantContext`.
- Produces: `UnitOfWork(session_factory, context, *, fence, auditor=None)` async context manager yielding a `TenantSession`; commits on clean exit, rolls back on exception; checks the fence unless `privileged_bypass(context)`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_uow.py`:

```python
import uuid

import pytest

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import TenantNotWritable
from jdlib.persistence.uow import UnitOfWork

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
    )


class _FakeSession:
    def __init__(self) -> None:
        self.committed = False
        self.rolled_back = False
        self.closed = False
        self.info: dict[str, object] = {}

        class _Sync:
            pass

        self.sync_session = _Sync()
        self.bind = type("Bind", (), {"dialect": None})()

    async def close(self) -> None:
        self.closed = True

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True


class _Factory:
    def __init__(self) -> None:
        self.sessions: list[_FakeSession] = []

    def __call__(self) -> _FakeSession:
        session = _FakeSession()
        self.sessions.append(session)
        return session


class _Fence:
    def __init__(self, blocked: bool = False) -> None:
        self.blocked = blocked
        self.calls = 0

    async def assert_writable(self, tenant_id: uuid.UUID) -> None:
        self.calls += 1
        if self.blocked:
            raise TenantNotWritable("relocation in progress")


async def test_commit_on_clean_exit(monkeypatch):
    factory = _Factory()
    monkeypatch.setattr(
        "jdlib.persistence.uow.TenantSession", lambda session, context, **kw: session
    )
    fence = _Fence()
    async with UnitOfWork(factory, _context(), fence=fence) as session:
        assert session is factory.sessions[0]
    assert factory.sessions[0].committed is True
    assert factory.sessions[0].closed is True
    assert fence.calls == 1


async def test_rollback_on_exception(monkeypatch):
    factory = _Factory()
    monkeypatch.setattr(
        "jdlib.persistence.uow.TenantSession", lambda session, context, **kw: session
    )
    with pytest.raises(RuntimeError):
        async with UnitOfWork(factory, _context(), fence=_Fence()) as _session:
            raise RuntimeError("boom")
    assert factory.sessions[0].rolled_back is True
    assert factory.sessions[0].committed is False
    assert factory.sessions[0].closed is True


async def test_fence_blocks_admission(monkeypatch):
    factory = _Factory()
    monkeypatch.setattr(
        "jdlib.persistence.uow.TenantSession", lambda session, context, **kw: session
    )
    with pytest.raises(TenantNotWritable):
        async with UnitOfWork(factory, _context(), fence=_Fence(blocked=True)):
            pass
    assert factory.sessions == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_uow.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.persistence.uow'`

- [ ] **Step 3: Implement `src/jdlib/persistence/uow.py`**

```python
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from jdlib.context import TenantContext
from jdlib.persistence.models import WriteFence, privileged_bypass
from jdlib.persistence.session import RawSqlAuditor, TenantSession


class UnitOfWork:
    def __init__(
        self,
        session_factory: Callable[[], Any],
        context: TenantContext,
        *,
        fence: WriteFence,
        auditor: RawSqlAuditor | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._context = context
        self._fence = fence
        self._auditor = auditor
        self._session: TenantSession | None = None

    async def __aenter__(self) -> TenantSession:
        if not privileged_bypass(self._context):
            await self._fence.assert_writable(self._context.tenant_id)
        raw = self._session_factory()
        self._session = TenantSession(raw, self._context, auditor=self._auditor)
        return self._session

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        assert self._session is not None
        try:
            if exc_type is None:
                await self._session.commit()
            else:
                await self._session.rollback()
        finally:
            await self._session.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_uow.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/persistence/uow.py tests/unit/test_uow.py
git commit -m "feat: unit of work with write fence admission"
```

---

### Task 5: TenantRepository

**Files:**
- Create: `src/jdlib/persistence/repository.py`
- Create: `tests/integration/test_repository.py`

**Interfaces:**
- Consumes: `TenantSession`, `SoftDelete`, `Timestamped`.
- Produces: `TenantRepository[ModelT]` with `get`, `list`, `add`, `update`, `soft_delete`, `count`.

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_repository.py`:

```python
import uuid

from jdlib.persistence.repository import TenantRepository
from tests.support.invoice import Invoice

TENANT_A = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


async def test_repository_crud_is_tenant_scoped(session_factory):
    from tests.integration.test_session_isolation import TENANT_B, _session

    number = f"A-{uuid.uuid4().hex[:8]}"
    async with await _session(session_factory, TENANT_A) as session:
        repository: TenantRepository[Invoice] = TenantRepository(session, Invoice)
        invoice = await repository.add(Invoice(number=number))
        assert invoice.tenant_id == TENANT_A

        fetched = await repository.get(invoice.id)
        assert fetched is not None and fetched.number == number

        await repository.update(invoice, status="paid")
        await session.commit()
        invoice_id = invoice.id

    # Fresh session re-read proves the update reached the database.
    async with await _session(session_factory, TENANT_A) as session:
        repository = TenantRepository(session, Invoice)
        persisted = await repository.get(invoice_id)
        assert persisted is not None and persisted.status == "paid"

        baseline = await repository.count()
        assert baseline >= 1
        rows = await repository.list(Invoice.number == number)
        assert [row.number for row in rows] == [number]

    # Commit a second tenant's row; tenant A's count must not move.
    b_number = f"B-{uuid.uuid4().hex[:8]}"
    async with await _session(session_factory, TENANT_B) as b_session:
        await b_session.add(Invoice(number=b_number))
        await b_session.commit()

    async with await _session(session_factory, TENANT_A) as session:
        repository = TenantRepository(session, Invoice)
        assert await repository.count() == baseline
        assert b_number not in [row.number for row in await repository.list()]

        target = await repository.get(invoice_id)
        assert target is not None
        await repository.soft_delete(target)
        assert await repository.get(invoice_id) is None
        assert number not in [row.number for row in await repository.list()]
        assert await repository.count() == baseline - 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_repository.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.persistence.repository'`

- [ ] **Step 3: Implement `src/jdlib/persistence/repository.py`**

```python
from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any, Generic, TypeVar

import sqlalchemy as sa

from jdlib.persistence.session import TenantSession

ModelT = TypeVar("ModelT")


class TenantRepository(Generic[ModelT]):
    def __init__(self, session: TenantSession, model: type[ModelT]) -> None:
        self._session = session
        self._model = model

    def _live_criteria(self) -> list[sa.ColumnElement[bool]]:
        if hasattr(self._model, "deleted_at"):
            return [self._model.deleted_at.is_(None)]
        return []

    async def get(self, entity_id: uuid.UUID) -> ModelT | None:
        if not hasattr(self._model, "deleted_at"):
            return await self._session.get(self._model, entity_id)
        statement = sa.select(self._model).where(
            self._model.id == entity_id, *self._live_criteria()
        )
        result = await self._session.execute(statement)
        return result.scalars().first()

    async def list(
        self,
        *criteria: sa.ColumnElement[bool],
        order_by: sa.ColumnElement[Any] | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Sequence[ModelT]:
        statement = sa.select(self._model).where(*self._live_criteria())
        if criteria:
            statement = statement.where(*criteria)
        if order_by is not None:
            statement = statement.order_by(order_by)
        if limit is not None:
            statement = statement.limit(limit)
        if offset is not None:
            statement = statement.offset(offset)
        result = await self._session.execute(statement)
        return result.scalars().all()

    async def add(self, obj: ModelT) -> ModelT:
        self._session.add(obj)
        await self._session.flush()
        return obj

    async def update(self, obj: ModelT, **changes: Any) -> ModelT:
        for field, value in changes.items():
            setattr(obj, field, value)
        await self._session.flush()
        return obj

    async def soft_delete(self, obj: ModelT) -> None:
        if not hasattr(obj, "deleted_at"):
            raise TypeError(f"{type(obj).__name__} is not soft-deletable")
        setattr(obj, "deleted_at", datetime.now(timezone.utc))
        await self._session.flush()

    async def count(self, *criteria: sa.ColumnElement[bool]) -> int:
        statement = sa.select(sa.func.count()).select_from(self._model).where(
            *self._live_criteria()
        )
        if criteria:
            statement = statement.where(*criteria)
        result = await self._session.execute(statement)
        return int(result.scalar_one())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_repository.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/persistence/repository.py tests/integration/test_repository.py
git commit -m "feat: tenant repository with soft-delete-aware queries"
```

---

### Task 6: IsolationStrategy and SessionRouter

**Files:**
- Create: `src/jdlib/persistence/strategies/__init__.py`
- Create: `src/jdlib/persistence/strategies/base.py`
- Create: `src/jdlib/persistence/strategies/shared.py`
- Create: `src/jdlib/persistence/router.py`
- Create: `tests/unit/test_router.py`

**Interfaces:**
- Consumes: `TenantRecord`; `StrategyCapabilityError`; `AsyncEngine`.
- Produces: `StrategyCapabilities`; `IsolationStrategy` protocol (`name`, `capabilities`, `async session(tenant) -> AsyncSession`); `SharedSchemaStrategy(engine)`; `SessionRouter(strategies)` with `async session(tenant) -> AsyncSession` validating `tenant.strategy`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_router.py`:

```python
import uuid

import pytest

from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.context import TenantRecord
from jdlib.errors import StrategyCapabilityError
from jdlib.persistence.router import SessionRouter
from jdlib.persistence.strategies.base import StrategyCapabilities
from jdlib.persistence.strategies.shared import SharedSchemaStrategy


class _FakeEngine:
    pass


def _record(strategy: PlacementStrategy) -> TenantRecord:
    return TenantRecord(
        id=uuid.uuid4(), slug="acme", status=TenantStatus.ACTIVE, strategy=strategy
    )


def test_shared_strategy_capabilities():
    strategy = SharedSchemaStrategy(_FakeEngine())  # type: ignore[arg-type]
    assert strategy.name == "shared"
    assert strategy.capabilities == StrategyCapabilities(
        supports_rls=True, supports_ddl=False
    )


async def test_router_requires_known_strategy():
    router = SessionRouter({PlacementStrategy.SHARED: SharedSchemaStrategy(_FakeEngine())})  # type: ignore[arg-type]
    with pytest.raises(StrategyCapabilityError):
        await router.session(_record(PlacementStrategy.DATABASE))


async def test_router_routes_shared_tenant():
    router = SessionRouter({PlacementStrategy.SHARED: SharedSchemaStrategy(_FakeEngine())})  # type: ignore[arg-type]
    session = await router.session(_record(PlacementStrategy.SHARED))
    assert session is not None
    await session.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_router.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.persistence.strategies'`

- [ ] **Step 3: Implement the strategy package and router**

`src/jdlib/persistence/strategies/base.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import TenantRecord


@dataclass(frozen=True, slots=True)
class StrategyCapabilities:
    supports_rls: bool
    supports_ddl: bool


class IsolationStrategy(Protocol):
    name: str
    capabilities: StrategyCapabilities

    async def session(self, tenant: TenantRecord) -> AsyncSession: ...
```

`src/jdlib/persistence/strategies/shared.py`:

```python
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from jdlib.context import TenantRecord
from jdlib.persistence.strategies.base import StrategyCapabilities


class SharedSchemaStrategy:
    name = "shared"
    capabilities = StrategyCapabilities(supports_rls=True, supports_ddl=False)

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def session(self, tenant: TenantRecord) -> AsyncSession:
        return AsyncSession(self._engine, expire_on_commit=False)
```

`src/jdlib/persistence/strategies/__init__.py`: empty.

`src/jdlib/persistence/router.py`:

```python
from __future__ import annotations

from collections.abc import Mapping

from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import TenantRecord
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import StrategyCapabilityError
from jdlib.persistence.strategies.base import IsolationStrategy


class SessionRouter:
    def __init__(self, strategies: Mapping[PlacementStrategy, IsolationStrategy]) -> None:
        self._strategies = dict(strategies)

    async def session(self, tenant: TenantRecord) -> AsyncSession:
        strategy = self._strategies.get(tenant.strategy)
        if strategy is None:
            raise StrategyCapabilityError(
                f"no isolation strategy registered for {tenant.strategy}"
            )
        return await strategy.session(tenant)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_router.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/persistence/strategies src/jdlib/persistence/router.py tests/unit/test_router.py
git commit -m "feat: isolation strategy protocol and session router"
```

---

## Phase 3 Exit Criteria

- [ ] Full suite green: Phase 1–2 tests plus the new isolation suite on real PostgreSQL 16.
- [ ] I1/I2/I3/I4/I9 behaviors proven: fail-closed sessions, scoped reads, stamped writes, immutable `tenant_id`, rejected cross-tenant references, rejected unscoped bulk DML.
- [ ] Raw SQL: SELECT/UPDATE/DELETE require proven tenant predicates; INSERT requires a bound tenant value; CTE/subquery/schema-escape/multi-statement rejected; privileged mode capability-gated and audited.
- [ ] `UnitOfWork` commits clean and rolls back dirty; write fence blocks admission unless the context is privileged.
- [ ] `SessionRouter` routes by placement and fails closed on unregistered strategies.
- [ ] `ruff` and strict `mypy` clean.

## Plan Series (remaining)

- Plan 4 — Phases 4–6: `TenantRegistry` lifecycle/provisioning, authorization (catalog, registry, PDP, guards, `AccessControl`), authentication adapters.
- Plan 5 — Phases 7–9: schema and database strategies, RLS emission and tests.
- Plan 6 — Phase 10: audit sinks, `jdlib.testing`, FastAPI/CLI integrations, docs.
