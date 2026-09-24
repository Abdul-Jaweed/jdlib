"""Phase 8 (tenant isolation): attacks that need a real database to be believed.

The claims under attack:

* the scoped bulk helpers cannot reach another tenant's rows, even when the
  predicate names them — "the tenant is a parameter, not a filter",
* a cross-tenant foreign-key reference is impossible, and not merely because the
  library's session guard notices: the constraint itself carries the tenant,
* switching tenants on one engine/pool leaves nothing behind.

The first two are the interesting ones because their failure mode is silent: an
`UPDATE` that touches another tenant's row returns a rowcount, and a foreign key
that ignores the tenant is only visible when someone traverses it.

Assertions here are supersets filtered by this test's own seed (the schema is
shared with the rest of the integration suite), never exact global counts.
"""

from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.persistence.session import TenantSession
from tests.support.invoice import Invoice, LineItem

pytestmark = pytest.mark.integration

TENANT_A = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
TENANT_B = uuid.UUID("00000000-0000-0000-0000-0000000000bb")


def _context(tenant_id: uuid.UUID) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme" if tenant_id == TENANT_A else "globex",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req-adv-iso",
        correlation_id="corr-adv-iso",
    )


async def _session(session_factory, tenant_id: uuid.UUID) -> TenantSession:
    raw = session_factory()
    await raw.execute(sa.text('SET search_path TO "jt_test"'))
    return TenantSession(raw, _context(tenant_id))


async def _seed_invoice(session: TenantSession, prefix: str) -> Invoice:
    invoice = Invoice(number=f"{prefix}-{uuid.uuid4().hex[:8]}")
    await session.add(invoice)
    await session.flush()
    return invoice


# --- bulk helpers cannot be aimed at another tenant ---------------------------


async def test_a_bulk_update_naming_another_tenants_row_changes_nothing(session_factory):
    async with await _session(session_factory, TENANT_B) as session:
        victim = await _seed_invoice(session, "B")
        victim_id, before_status = victim.id, victim.status
        await session.commit()

    async with await _session(session_factory, TENANT_A) as session:
        changed = await session.update_where(
            Invoice, {"status": "pwned"}, Invoice.id == victim_id
        )
        await session.commit()

    assert changed == 0, "another tenant's row must not be reachable by a bulk update"

    async with await _session(session_factory, TENANT_B) as session:
        row = await session.get(Invoice, victim_id)
        assert row is not None
        assert row.status == before_status


async def test_a_bulk_delete_naming_another_tenants_row_deletes_nothing(session_factory):
    async with await _session(session_factory, TENANT_B) as session:
        invoice = await _seed_invoice(session, "B")
        line = LineItem(invoice_id=invoice.id, amount_cents=4321)
        await session.add(line)
        await session.flush()
        line_id = line.id
        await session.commit()

    async with await _session(session_factory, TENANT_A) as session:
        deleted = await session.delete_where(LineItem, LineItem.id == line_id)
        await session.commit()

    assert deleted == 0

    async with await _session(session_factory, TENANT_B) as session:
        still_there = (
            await session.execute(
                sa.select(sa.func.count()).select_from(LineItem).where(LineItem.id == line_id)
            )
        ).scalar_one()
        assert still_there == 1


async def test_a_bulk_update_without_criteria_cannot_leave_its_own_tenant(session_factory):
    """The strongest form: no WHERE beyond the tenant, and the tenant still holds."""
    async with await _session(session_factory, TENANT_B) as session:
        victim = await _seed_invoice(session, "B")
        victim_id = victim.id
        await session.commit()

    async with await _session(session_factory, TENANT_A) as session:
        own = await _seed_invoice(session, "A")
        own_id = own.id
        await session.commit()

    async with await _session(session_factory, TENANT_A) as session:
        changed = await session.update_where(Invoice, {"status": "touched"})
        await session.commit()

    assert changed >= 1
    async with await _session(session_factory, TENANT_A) as session:
        assert (await session.get(Invoice, own_id)).status == "touched"
    async with await _session(session_factory, TENANT_B) as session:
        assert (await session.get(Invoice, victim_id)).status != "touched"


# --- the constraint itself carries the tenant ---------------------------------


async def test_the_database_refuses_a_cross_tenant_foreign_key_reference(session_factory):
    """Prove it with a raw connection, with no library guard in the way.

    The reference `line_items(tenant_id, invoice_id) -> invoices(tenant_id, id)`
    is composite on purpose: a row cannot point at another tenant's invoice even
    if every application-level check were bypassed.
    """
    async with await _session(session_factory, TENANT_B) as session:
        invoice = await _seed_invoice(session, "B")
        invoice_id = invoice.id
        await session.commit()

    raw = session_factory()
    await raw.execute(sa.text('SET search_path TO "jt_test"'))
    try:
        with pytest.raises(IntegrityError):
            await raw.execute(
                sa.text(
                    "INSERT INTO line_items (id, tenant_id, invoice_id, amount_cents) "
                    "VALUES (:id, :tenant_id, :invoice_id, 1)"
                ),
                {"id": uuid.uuid4(), "tenant_id": TENANT_A, "invoice_id": invoice_id},
            )
        await raw.rollback()
        # Control: the same insert with the invoice's own tenant is accepted, so
        # the refusal above is about the tenant boundary and not a broken fixture.
        await raw.execute(
            sa.text(
                "INSERT INTO line_items (id, tenant_id, invoice_id, amount_cents) "
                "VALUES (:id, :tenant_id, :invoice_id, 1)"
            ),
            {"id": uuid.uuid4(), "tenant_id": TENANT_B, "invoice_id": invoice_id},
        )
        await raw.rollback()
    finally:
        await raw.close()


# --- switching tenants leaves nothing behind -----------------------------------


async def test_switching_tenants_on_one_pool_leaks_nothing(session_factory):
    async with await _session(session_factory, TENANT_A) as session:
        invoice_a = await _seed_invoice(session, "A")
        id_a = invoice_a.id
        await session.commit()

    async with await _session(session_factory, TENANT_B) as session:
        invoice_b = await _seed_invoice(session, "B")
        id_b = invoice_b.id
        await session.commit()

    # Same engine, same pool, opposite order: each context sees exactly one.
    for tenant, visible, hidden in (
        (TENANT_B, id_b, id_a),
        (TENANT_A, id_a, id_b),
        (TENANT_B, id_b, id_a),
    ):
        async with await _session(session_factory, tenant) as session:
            assert await session.get(Invoice, visible) is not None
            assert await session.get(Invoice, hidden) is None
            rows = (await session.execute(sa.select(Invoice))).scalars().all()
            assert all(row.tenant_id == tenant for row in rows)
