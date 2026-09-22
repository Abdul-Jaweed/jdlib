import uuid

from jdlib.authz.resource_types import ResourceTypeDefinition, ResourceTypeRegistry
from jdlib.authz.scopes import ResourceRef, ScopeRef, ScopeResolver
from jdlib.control.enums import ScopeType
from jdlib.models.org import Organization, Team
from tests.support.invoice import Invoice

TENANT_A = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _registry() -> ResourceTypeRegistry:
    registry = ResourceTypeRegistry()
    registry.register(
        ResourceTypeDefinition("invoice", Invoice, tenant_owned=True, tenant_routed=True,
                               permission_namespace="invoice")
    )
    return registry


async def _seed_org_tree(session):
    root, child, sibling = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    await session.add(Organization(id=root, name="Root", slug=f"root-{root.hex[:6]}"))
    await session.add(
        Organization(id=child, name="Child", slug=f"child-{child.hex[:6]}",
                     parent_organization_id=root)
    )
    await session.add(
        Organization(id=sibling, name="Sibling", slug=f"sib-{sibling.hex[:6]}")
    )
    team = uuid.uuid4()
    await session.add(Team(id=team, organization_id=child, name="Team", slug=f"t-{team.hex[:6]}"))
    await session.flush()
    return root, child, sibling, team


async def test_tenant_scope_chain_is_just_tenant(session_factory):
    from tests.integration.test_session_isolation import _session

    resolver = ScopeResolver(_registry())
    async with await _session(session_factory, TENANT_A) as session:
        chain = await resolver.chain(session, ScopeRef(ScopeType.TENANT, None))
        assert chain == (ScopeRef(ScopeType.TENANT, None),)


async def test_org_chain_includes_ancestors(session_factory):
    from tests.integration.test_session_isolation import _session

    resolver = ScopeResolver(_registry())
    async with await _session(session_factory, TENANT_A) as session:
        root, child, sibling, _ = await _seed_org_tree(session)
        chain = await resolver.chain(session, ScopeRef(ScopeType.ORG, child))
        assert chain == (
            ScopeRef(ScopeType.TENANT, None),
            ScopeRef(ScopeType.ORG, child),
            ScopeRef(ScopeType.ORG, root),
        )
        sibling_chain = await resolver.chain(session, ScopeRef(ScopeType.ORG, sibling))
        assert ScopeRef(ScopeType.ORG, root) not in sibling_chain


async def test_team_chain_includes_its_org_and_ancestors(session_factory):
    from tests.integration.test_session_isolation import _session

    resolver = ScopeResolver(_registry())
    async with await _session(session_factory, TENANT_A) as session:
        root, child, _, team = await _seed_org_tree(session)
        chain = await resolver.chain(session, ScopeRef(ScopeType.TEAM, team))
        assert chain == (
            ScopeRef(ScopeType.TENANT, None),
            ScopeRef(ScopeType.ORG, child),
            ScopeRef(ScopeType.ORG, root),
            ScopeRef(ScopeType.TEAM, team),
        )


async def test_resource_chain_uses_ownership(session_factory):
    from tests.integration.test_session_isolation import _session

    resolver = ScopeResolver(_registry())
    async with await _session(session_factory, TENANT_A) as session:
        root, child, _, team = await _seed_org_tree(session)
        invoice_id = uuid.uuid4()
        await session.add(
            Invoice(id=invoice_id, number=f"INV-{invoice_id.hex[:6]}",
                    organization_id=child, team_id=team)
        )
        await session.flush()
        chain = await resolver.chain(session, ResourceRef("invoice", invoice_id))
        assert chain == (
            ScopeRef(ScopeType.TENANT, None),
            ScopeRef(ScopeType.ORG, child),
            ScopeRef(ScopeType.ORG, root),
            ScopeRef(ScopeType.TEAM, team),
        )
