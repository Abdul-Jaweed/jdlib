import uuid

from jdlib.persistence.repository import TenantRepository
from tests.support.invoice import Invoice

TENANT_A = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


async def test_repository_crud_is_tenant_scoped(session_factory):
    from tests.integration.test_session_isolation import _session

    async with await _session(session_factory, TENANT_A) as session:
        repository: TenantRepository[Invoice] = TenantRepository(session, Invoice)
        number = f"A-{uuid.uuid4().hex[:8]}"
        invoice = await repository.add(Invoice(number=number))
        assert invoice.tenant_id == TENANT_A

        fetched = await repository.get(invoice.id)
        assert fetched is not None and fetched.number == number

        await repository.update(invoice, status="paid")
        assert (await repository.get(invoice.id)).status == "paid"

        assert await repository.count() >= 1
        rows = await repository.list(Invoice.number == number)
        assert [row.number for row in rows] == [number]

        await repository.soft_delete(invoice)
        assert await repository.get(invoice.id) is None
