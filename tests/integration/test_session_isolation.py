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
