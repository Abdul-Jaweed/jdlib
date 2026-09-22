import uuid

import pytest

from jdlib.authz.guards import Enforcer, requires
from jdlib.authz.pdp import Decision
from jdlib.authz.scopes import ScopeRef
from jdlib.context import Principal, PrincipalKind, TenantContext, context_scope
from jdlib.control.enums import PlacementStrategy, ScopeType
from jdlib.errors import PermissionDenied


class _PDP:
    def __init__(self, allowed: bool) -> None:
        self.allowed = allowed
        self.calls: list[tuple[str, ScopeRef]] = []

    async def evaluate(self, principal, permission, target, context, *, session):
        self.calls.append((permission, target))
        return Decision(self.allowed, "allowed" if self.allowed else "no_allow", ())


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=uuid.UUID(int=1),
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.UUID(int=2)),
        request_id="req",
        correlation_id="corr",
    )


@pytest.fixture(autouse=True)
def _tenant_context():
    with context_scope(_context()):
        yield


async def test_require_raises_when_denied():
    enforcer = Enforcer(_PDP(False))
    with pytest.raises(PermissionDenied):
        await enforcer.require("resource:read", ScopeRef(ScopeType.TENANT, None), session=None)


async def test_require_returns_decision_when_allowed():
    enforcer = Enforcer(_PDP(True))
    decision = await enforcer.require(
        "resource:read", ScopeRef(ScopeType.TENANT, None), session=None
    )
    assert decision.allowed is True


async def test_requires_decorator_checks_before_calling():
    pdp = _PDP(True)
    enforcer = Enforcer(pdp)

    @requires("resource:read", enforcer=enforcer)
    async def handler(*, session=None) -> str:
        return "ok"

    assert await handler(session=None) == "ok"
    assert pdp.calls[0][0] == "resource:read"


async def test_requires_decorator_raises_when_denied():
    enforcer = Enforcer(_PDP(False))

    @requires("resource:read", enforcer=enforcer)
    async def handler(*, session=None) -> str:
        raise AssertionError("must not run")

    with pytest.raises(PermissionDenied):
        await handler(session=None)


async def test_target_factory_receives_kwargs():
    pdp = _PDP(True)
    enforcer = Enforcer(pdp)

    @requires(
        "resource:read",
        enforcer=enforcer,
        target_factory=lambda resource_id, **_: ScopeRef(ScopeType.TEAM, resource_id),
    )
    async def handler(*, resource_id: uuid.UUID, session=None) -> str:
        return "ok"

    await handler(resource_id=uuid.UUID(int=7), session=None)
    assert pdp.calls[0][1] == ScopeRef(ScopeType.TEAM, uuid.UUID(int=7))
