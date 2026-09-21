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
from tests.support.invoice import Invoice, LineItem

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


async def test_entity_with_bare_table_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="table-level statements"):
            await session.execute(sa.select(Invoice, LineItem.__table__))


async def test_entity_join_bare_table_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="table-level statements"):
            await session.execute(
                sa.select(Invoice).join(
                    LineItem.__table__, LineItem.__table__.c.invoice_id == Invoice.id
                )
            )


async def test_entity_select_from_bare_table_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="table-level statements"):
            await session.execute(sa.select(Invoice).select_from(LineItem.__table__))


async def test_subquery_table_level_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="table-level statements"):
            await session.execute(
                sa.select(sa.func.count()).select_from(sa.select(Invoice.id).subquery())
            )


async def test_multi_table_entity_less_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="table-level statements"):
            await session.execute(sa.select(sa.func.count()).select_from(Invoice, LineItem))


async def test_subquery_tenant_table_without_mapper_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="table-level statements"):
            await session.execute(
                sa.select(sa.func.count())
                .select_from(Invoice)
                .where(Invoice.id.in_(sa.select(LineItem.id)))
            )


async def test_table_clause_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="table-level statements"):
            await session.execute(sa.select(sa.func.count()).select_from(sa.table("invoices")))


async def test_text_clause_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="text fragments"):
            await session.execute(sa.select(sa.func.count()).select_from(sa.text("invoices")))


async def test_text_fragment_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="text fragments"):
            await session.execute(sa.select(sa.text("* FROM invoices")))


async def test_text_fragment_in_criteria_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="text fragments"):
            await session.execute(sa.select(Invoice).where(sa.text("1 = 1")))


async def test_aliased_entity_select_is_scoped(session_factory):
    a_id = uuid.uuid4()
    async with await _session(session_factory, TENANT_A) as session:
        await session.add(Invoice(id=a_id, number=f"A-{uuid.uuid4().hex[:8]}"))
        await session.commit()
    b_id = uuid.uuid4()
    async with await _session(session_factory, TENANT_B) as session:
        await session.add(Invoice(id=b_id, number=f"B-{uuid.uuid4().hex[:8]}"))
        await session.commit()
    aliased = sa.orm.aliased(Invoice)
    async with await _session(session_factory, TENANT_A) as session:
        rows = (await session.execute(sa.select(aliased))).scalars().all()
        ids = {row.id for row in rows}
        assert a_id in ids
        assert b_id not in ids
        assert all(row.tenant_id == TENANT_A for row in rows)


async def test_literal_column_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="literal SQL fragments"):
            await session.execute(
                sa.select(sa.literal_column("tenant_id")).select_from(Invoice)
            )


async def test_table_clause_alias_from_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="table-level statements"):
            await session.execute(
                sa.select(sa.func.count()).select_from(
                    Invoice, sa.table("invoices").alias("raw")
                )
            )


async def test_bare_table_alias_with_entity_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="aliases of tenant tables"):
            await session.execute(sa.select(Invoice, Invoice.__table__.alias("raw")))


async def test_bare_table_alias_join_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="aliases of tenant tables"):
            await session.execute(
                sa.select(Invoice).join(Invoice.__table__.alias("raw"), sa.true())
            )


async def test_bare_table_alias_select_from_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="aliases of tenant tables"):
            await session.execute(
                sa.select(Invoice).select_from(Invoice.__table__.alias("raw"))
            )


async def test_implicit_from_unselected_tenant_entity_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="table-level statements"):
            await session.execute(
                sa.select(LineItem).where(LineItem.invoice_id == Invoice.id)
            )


async def test_join_between_tenant_models_is_scoped(session_factory):
    invoice_id = uuid.uuid4()
    async with await _session(session_factory, TENANT_B) as session:
        await session.add(Invoice(id=invoice_id, number=f"B-{uuid.uuid4().hex[:8]}"))
        await session.flush()
        await session.add(LineItem(invoice_id=invoice_id, amount_cents=500))
        await session.commit()
    async with await _session(session_factory, TENANT_A) as session:
        rows = (
            await session.execute(
                sa.select(Invoice).join(LineItem, LineItem.invoice_id == Invoice.id)
            )
        ).scalars().all()
        assert all(row.tenant_id == TENANT_A for row in rows)
    async with await _session(session_factory, TENANT_B) as session:
        rows = (
            await session.execute(
                sa.select(Invoice)
                .join(LineItem, LineItem.invoice_id == Invoice.id)
                .where(Invoice.id == invoice_id)
            )
        ).scalars().all()
        assert [row.id for row in rows] == [invoice_id]


async def test_multi_entity_select_is_scoped(session_factory):
    async with await _session(session_factory, TENANT_B) as session:
        invoice_b = Invoice(number=f"B-{uuid.uuid4().hex[:8]}")
        await session.add(invoice_b)
        await session.flush()
        await session.add(LineItem(invoice_id=invoice_b.id, amount_cents=700))
        await session.commit()
    async with await _session(session_factory, TENANT_A) as session:
        invoice_a = Invoice(number=f"A-{uuid.uuid4().hex[:8]}")
        await session.add(invoice_a)
        await session.flush()
        await session.add(LineItem(invoice_id=invoice_a.id, amount_cents=300))
        await session.commit()
    async with await _session(session_factory, TENANT_A) as session:
        rows = (
            await session.execute(
                sa.select(Invoice, LineItem).where(LineItem.invoice_id == Invoice.id)
            )
        ).all()
        assert rows
        for invoice_row, line_item_row in rows:
            assert invoice_row.tenant_id == TENANT_A
            assert line_item_row.tenant_id == TENANT_A


async def test_from_statement_orm_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="from_statement is not supported"):
            await session.execute(sa.select(Invoice).from_statement(sa.select(Invoice)))


async def test_from_statement_table_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="from_statement is not supported"):
            await session.execute(
                sa.select(Invoice).from_statement(sa.select(Invoice.__table__))
            )


async def test_from_statement_text_select_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="from_statement is not supported"):
            await session.execute(
                sa.select(Invoice).from_statement(sa.text("SELECT * FROM invoices"))
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


async def test_raw_sql_update_tenant_id_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="tenant_id may not be assigned"):
            await session.raw_sql(
                sa.text("UPDATE invoices SET tenant_id = :other WHERE tenant_id = :tenant_id"),
                {"other": TENANT_B, "tenant_id": TENANT_A},
            )


async def test_raw_sql_on_conflict_tenant_id_rejected(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        with pytest.raises(UnscopedRawSql, match="tenant_id may not be assigned"):
            await session.raw_sql(
                sa.text(
                    "INSERT INTO invoices (tenant_id, id, number) "
                    "VALUES (:tenant_id, :id, :number) "
                    "ON CONFLICT (tenant_id, id) DO UPDATE SET tenant_id = :other"
                ),
                {
                    "tenant_id": TENANT_A,
                    "id": uuid.uuid4(),
                    "number": f"A-{uuid.uuid4().hex[:8]}",
                    "other": TENANT_B,
                },
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
