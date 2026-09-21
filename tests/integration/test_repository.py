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

    async with await _session(session_factory, TENANT_A) as session:
        repository = TenantRepository(session, Invoice)
        persisted = await repository.get(invoice_id)
        assert persisted is not None and persisted.status == "paid"

        baseline = await repository.count()
        assert baseline >= 1
        rows = await repository.list(Invoice.number == number)
        assert [row.number for row in rows] == [number]

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
