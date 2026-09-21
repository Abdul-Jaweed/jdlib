from __future__ import annotations

import uuid
from typing import Any, Protocol, cast

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import FromStatement, Session
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


def _direct_froms(statement: Any) -> tuple[Any, ...]:
    get_final_froms = getattr(statement, "get_final_froms", None)
    if get_final_froms is not None:
        return tuple(get_final_froms())
    return tuple(getattr(statement, "froms", ()))


def _direct_table_names(statement: Any) -> set[str]:
    names: set[str] = set()

    def collect(element: object) -> None:
        if isinstance(element, sa.TableClause):
            names.add(element.name)
        elif isinstance(element, sa.Join):
            collect(element.left)
            collect(element.right)
        elif isinstance(element, sa.Alias) and not isinstance(element, sa.Subquery):
            collect(element.element)

    for from_ in _direct_froms(statement):
        collect(from_)
    return names


def _register_events(session: Session) -> None:
    tables = tenant_table_map()

    @sa.event.listens_for(session, "do_orm_execute")
    def _scope(state: sa.orm.ORMExecuteState) -> None:
        context = state.session.info.get(_CTX_KEY)
        if context is None:
            if state.is_select or state.is_update or state.is_delete or state.is_insert:
                raise MissingTenantContext("session has no tenant context")
            return
        if isinstance(state.statement, FromStatement) and not (
            state.is_insert or state.is_update or state.is_delete
        ):
            raise UnscopedRawSql(
                "from_statement is not supported; use ORM selects or raw_sql"
            )
        if state.is_select:
            tenant_id = context.tenant_id
            all_mappers = state.all_mappers
            if not all_mappers and any(
                isinstance(from_, sa.TextClause) for from_ in _direct_froms(state.statement)
            ):
                raise UnscopedRawSql(
                    "table-level statements on tenant tables must use raw_sql"
                )
            direct = _direct_table_names(state.statement)

            def _trusted(mapper: sa.orm.Mapper[Any]) -> bool:
                local_table = getattr(mapper, "local_table", None)
                return (
                    issubclass(mapper.class_, TenantRouted)
                    and local_table is not None
                    and local_table.name in direct
                )

            mappers = list(all_mappers)
            bind_mapper = state.bind_mapper
            if (
                bind_mapper is not None
                and bind_mapper not in mappers
                and _trusted(bind_mapper)
            ):
                mappers.append(bind_mapper)
            allowed: set[str] = set()
            for mapper in mappers:
                if not _trusted(mapper):
                    continue
                local_name = getattr(mapper.local_table, "name", None)
                if local_name is not None:
                    allowed.add(local_name)
            tenant_tables = {
                element
                for element in visitors.iterate(cast(Any, state.statement))
                if isinstance(element, sa.TableClause) and element.name in tables
            }
            if any(table.name not in allowed for table in tenant_tables):
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
